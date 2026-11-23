use anyhow::{anyhow, Result};
use async_trait::async_trait;
use orbien_core::config::ClientConfig;
use orbien_core::transport::{
    boxed_stream, client_enable_tls, dial_kcp, dial_websocket, new_client_tls_config_tofu,
    DynStream, Protocol, QuicSession, YamuxClient, MAX_NUM_STREAMS,
};
use rustls::ClientConfig as RustlsClientConfig;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

pub(crate) fn check_tls_config(cfg: &ClientConfig) -> Result<()> {
    let tls = TlsDialOpts::from_config(cfg)?;
    if tls.enable {
        rustls::pki_types::ServerName::try_from(tls.server_name.clone())
            .map_err(|e| anyhow!("invalid transport.tls.serverName: {e}"))?;
    }
    if matches!(cfg.protocol()?, Protocol::Quic) {
        let mut crypto = (*tls.cfg).clone();
        crypto.alpn_protocols = vec![orbien_core::transport::ALPN_ORBIEN.to_vec()];
        orbien_core::transport::check_quic_client_crypto(crypto)?;
    }
    Ok(())
}

#[async_trait]
pub trait Connector: Send + Sync {
    async fn open(&self) -> Result<DynStream>;
}

struct TlsDialOpts {
    enable: bool,
    cfg: Arc<RustlsClientConfig>,
    server_name: String,
}

impl TlsDialOpts {
    fn from_config(cfg: &ClientConfig) -> Result<Self> {
        let tls = &cfg.transport.tls;
        // H1 (TOFU): opt-in pinning store wins over legacy skip-verify; an
        // explicit trustedCaFile still takes precedence inside the builder.
        let tofu = if tls.trusted_ca_file.trim().is_empty()
            && !tls.tofu_store_file.trim().is_empty()
        {
            Some(std::path::PathBuf::from(&tls.tofu_store_file))
        } else {
            None
        };
        let rustls_cfg = new_client_tls_config_tofu(
            &tls.cert_file,
            &tls.key_file,
            &tls.trusted_ca_file,
            tofu.as_deref(),
        )?;
        Ok(Self {
            enable: tls.enable,
            cfg: rustls_cfg,
            server_name: cfg.tls_server_name().to_string(),
        })
    }

    async fn maybe_wrap(&self, stream: DynStream) -> Result<DynStream> {
        if !self.enable {
            return Ok(stream);
        }
        client_enable_tls(stream, Arc::clone(&self.cfg), &self.server_name).await
    }
}

/// #12: verify-by-default. With TLS on, the client must either verify
/// the server (trusted CA or TOFU pin) or explicitly opt into
/// skip-verify with `transport.tls.insecureSkipVerify`. Deliberately
/// NOT in `TlsDialOpts::from_config` or `check_tls_config`:
/// `--check-config` stays warn-only (scripts/check-configs.py requires
/// a minimal client config to pass with reason `no-server-trust`).
pub(crate) fn require_server_trust(cfg: &ClientConfig) -> Result<()> {
    let tls = &cfg.transport.tls;
    if !tls.enable || tls.insecure_skip_verify {
        return Ok(());
    }
    if !tls.trusted_ca_file.trim().is_empty() || !tls.tofu_store_file.trim().is_empty() {
        return Ok(());
    }
    Err(anyhow!(
        "refusing to connect without server verification: no transport.tls.trustedCaFile or \
         transport.tls.tofuStoreFile is configured; set transport.tls.insecureSkipVerify = true \
         to connect anyway (insecure — MITM possible), or configure a CA / TOFU store"
    ))
}

pub async fn build_connector(cfg: &ClientConfig) -> Result<Arc<dyn Connector>> {
    // #12: verify-by-default — refuse before any dial. Covers TCP/WS/
    // KCP and QUIC alike, since every protocol goes through here.
    require_server_trust(cfg)?;
    let tls = TlsDialOpts::from_config(cfg)?;
    let max_streams = cfg.transport.max_yamux_streams.unwrap_or(MAX_NUM_STREAMS);
    match cfg.protocol()? {
        Protocol::Tcp => {
            if cfg.transport.tcp_mux {
                let stream = dial_tcp_tls(cfg, &tls).await?;
                tracing::info!(
                    endpoint = %cfg.server_endpoint(),
                    tls = tls.enable,
                    "tcpMux: physical TCP opened, yamux client started"
                );
                Ok(Arc::new(YamuxConnector::new(
                    YamuxClient::start(stream, max_streams),
                    cfg.clone(),
                    tls,
                    Protocol::Tcp,
                    max_streams,
                )))
            } else {
                Ok(Arc::new(TcpConnector {
                    endpoint: cfg.server_endpoint(),
                    tls,
                }))
            }
        }
        Protocol::Websocket => {
            if cfg.transport.tcp_mux {
                let stream = dial_ws_tls(cfg, &tls).await?;
                tracing::info!(
                    endpoint = %cfg.server_endpoint(),
                    tls = tls.enable,
                    "tcpMux: physical WebSocket opened, yamux client started"
                );
                Ok(Arc::new(YamuxConnector::new(
                    YamuxClient::start(stream, max_streams),
                    cfg.clone(),
                    tls,
                    Protocol::Websocket,
                    max_streams,
                )))
            } else {
                Ok(Arc::new(WebsocketConnector {
                    endpoint: cfg.server_endpoint(),
                    tls,
                }))
            }
        }
        Protocol::Kcp => {
            let addr = resolve_addr(cfg)?;
            if cfg.transport.tcp_mux {
                let stream = dial_kcp_tls(addr, &tls).await?;
                tracing::info!(
                    %addr,
                    tls = tls.enable,
                    "tcpMux: physical KCP opened, yamux client started"
                );
                Ok(Arc::new(YamuxConnector::new(
                    YamuxClient::start(stream, max_streams),
                    cfg.clone(),
                    tls,
                    Protocol::Kcp,
                    max_streams,
                )))
            } else {
                Ok(Arc::new(KcpConnector { addr, tls }))
            }
        }
        Protocol::Quic => {
            let addr = resolve_addr(cfg)?;
            let t = &cfg.transport.tls;
            // H1 (TOFU): QUIC dials participate in pinning — pass the store
            // when configured and no explicit CA overrides it.
            let tofu = if t.trusted_ca_file.trim().is_empty()
                && !t.tofu_store_file.trim().is_empty()
            {
                Some(std::path::PathBuf::from(&t.tofu_store_file))
            } else {
                None
            };
            let session = QuicSession::dial(
                addr,
                &cfg.tls_server_name(),
                &cfg.transport.quic,
                &t.cert_file,
                &t.key_file,
                &t.trusted_ca_file,
                tofu.as_deref(),
            )
            .await?;
            tracing::info!(%addr, "quic session opened");
            Ok(Arc::new(QuicConnector {
                session: Arc::new(session),
            }))
        }
    }
}

async fn dial_tcp_tls(cfg: &ClientConfig, tls: &TlsDialOpts) -> Result<DynStream> {
    let stream = TcpStream::connect(cfg.server_endpoint()).await?;
    orbien_core::net::enable_nodelay(&stream);
    tls.maybe_wrap(boxed_stream(stream)).await
}

async fn dial_ws_tls(cfg: &ClientConfig, tls: &TlsDialOpts) -> Result<DynStream> {
    let stream = dial_websocket(&cfg.server_endpoint()).await?;
    tls.maybe_wrap(stream).await
}

async fn dial_kcp_tls(addr: SocketAddr, tls: &TlsDialOpts) -> Result<DynStream> {
    let stream = dial_kcp(addr).await?;
    tls.maybe_wrap(stream).await
}

fn resolve_addr(cfg: &ClientConfig) -> Result<SocketAddr> {
    cfg.server_endpoint()
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("cannot resolve {}", cfg.server_endpoint()))
}

/// yamux connector that automatically re-dials the physical connection when
/// the yamux session closes, instead of failing permanently.
struct YamuxConnector {
    /// Current active yamux client — replaced on reconnect.
    inner: Mutex<YamuxClient>,
    cfg: ClientConfig,
    tls: TlsDialOpts,
    protocol: Protocol,
    max_streams: usize,
    /// Prevents concurrent dial storms: only one goroutine rebuilds at a time.
    rebuild_lock: Mutex<()>,
}

impl YamuxConnector {
    fn new(
        initial: YamuxClient,
        cfg: ClientConfig,
        tls: TlsDialOpts,
        protocol: Protocol,
        max_streams: usize,
    ) -> Self {
        Self {
            inner: Mutex::new(initial),
            cfg,
            tls,
            protocol,
            max_streams,
            rebuild_lock: Mutex::new(()),
        }
    }

    async fn rebuild(&self) -> Result<()> {
        let _guard = self.rebuild_lock.lock().await;
        // Re-check: another task may have already rebuilt while we waited.
        // We can't easily detect "still broken" without trying open_stream,
        // so just always rebuild — the cost is one extra physical dial.
        let stream = match self.protocol {
            Protocol::Tcp => dial_tcp_tls(&self.cfg, &self.tls).await?,
            Protocol::Websocket => dial_ws_tls(&self.cfg, &self.tls).await?,
            Protocol::Kcp => {
                let addr = resolve_addr(&self.cfg)?;
                dial_kcp_tls(addr, &self.tls).await?
            }
            Protocol::Quic => return Err(anyhow!("yamux over quic is not supported")),
        };
        tracing::info!(
            protocol = ?self.protocol,
            "yamux session re-established after physical reconnect"
        );
        let new_client = YamuxClient::start(stream, self.max_streams);
        *self.inner.lock().await = new_client;
        Ok(())
    }
}

#[async_trait]
impl Connector for YamuxConnector {
    async fn open(&self) -> Result<DynStream> {
        // First attempt.
        let result = self.inner.lock().await.open_stream().await;
        match result {
            Ok(s) => return Ok(s),
            Err(ref e) if e.to_string().contains("yamux client session closed") => {
                tracing::warn!("yamux session closed, rebuilding physical connection");
            }
            Err(e) => return Err(e),
        }
        // Rebuild then retry once.
        self.rebuild().await?;
        self.inner.lock().await.open_stream().await
    }
}

struct TcpConnector {
    endpoint: String,
    tls: TlsDialOpts,
}

#[async_trait]
impl Connector for TcpConnector {
    async fn open(&self) -> Result<DynStream> {
        let stream = TcpStream::connect(&self.endpoint).await?;
        orbien_core::net::enable_nodelay(&stream);
        self.tls.maybe_wrap(boxed_stream(stream)).await
    }
}

struct WebsocketConnector {
    endpoint: String,
    tls: TlsDialOpts,
}

#[async_trait]
impl Connector for WebsocketConnector {
    async fn open(&self) -> Result<DynStream> {
        let stream = dial_websocket(&self.endpoint).await?;
        self.tls.maybe_wrap(stream).await
    }
}

struct KcpConnector {
    addr: SocketAddr,
    tls: TlsDialOpts,
}

#[async_trait]
impl Connector for KcpConnector {
    async fn open(&self) -> Result<DynStream> {
        let stream = dial_kcp(self.addr).await?;
        self.tls.maybe_wrap(stream).await
    }
}

struct QuicConnector {
    session: Arc<QuicSession>,
}

#[async_trait]
impl Connector for QuicConnector {
    async fn open(&self) -> Result<DynStream> {
        self.session.open_stream().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg(tls: serde_json::Value) -> ClientConfig {
        serde_json::from_value(json!({
            "server": "127.0.0.1:9527",
            "transport": { "tls": tls },
        }))
        .expect("test config parses")
    }

    #[test]
    fn refuses_unverified_tls_by_default() {
        // No CA, no TOFU, no opt-in: refuse, and name the option.
        let err = require_server_trust(&cfg(json!({}))).unwrap_err();
        assert!(
            err.to_string().contains("insecureSkipVerify"),
            "error names the opt-in: {err}"
        );
        // Explicit opt-in, CA, TOFU, or TLS off: allowed.
        assert!(require_server_trust(&cfg(json!({ "insecureSkipVerify": true }))).is_ok());
        assert!(require_server_trust(&cfg(json!({ "trustedCaFile": "./ca.crt" }))).is_ok());
        assert!(require_server_trust(&cfg(json!({ "tofuStoreFile": "./pin.json" }))).is_ok());
        assert!(require_server_trust(&cfg(json!({ "enable": false }))).is_ok());
    }
}
