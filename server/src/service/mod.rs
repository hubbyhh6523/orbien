mod dashboard_view;
mod ingress;
mod p2p_broker;
mod pre_login;
mod session_registry;

use crate::access::AccessPolicy;
use crate::control::Control;
use crate::metrics::MemMetrics;
use crate::tunnel::{run_http_gw_listener, run_https_gw_listener, HttpGw, HttpsGw};
use anyhow::{anyhow, Result};
use orbien_core::config::ServerConfig;
use orbien_core::transport;
use p2p_broker::P2pBroker;
use pre_login::PreLoginGate;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::task::JoinSet;

#[allow(unused_imports)]
pub use dashboard_view::DashboardSnapshot;

pub(crate) struct OfflineClientRecord {
    session_id: String,
    user: String,
    hostname: String,
    os: String,
    arch: String,
    client_ip: String,
    version: String,
    tunnel_count: usize,
    /// Wall-clock time, not `Instant`: a 24h TTL needs a timestamp that can
    /// be 25h old, and `Instant::now() - 25h` panics on a monotonic clock
    /// that started less than 25h ago (Windows CI).
    disconnected_at: SystemTime,
}

/// Offline client records: at most this many, each kept for `OFFLINE_TTL`
/// (#11). Cleanup happens on insert; there is no background task.
const MAX_OFFLINE_CLIENTS: usize = 1000;
const OFFLINE_TTL: Duration = Duration::from_secs(24 * 3600);

pub struct Service {
    cfg: ServerConfig,
    access: Arc<RwLock<Arc<AccessPolicy>>>,
    controls: Arc<Mutex<HashMap<String, Arc<Control>>>>,
    offline_clients: Arc<Mutex<HashMap<String, OfflineClientRecord>>>,
    http_gw: Option<Arc<HttpGw>>,
    https_gw: Option<Arc<HttpsGw>>,
    tls_config: Arc<rustls::ServerConfig>,
    metrics: Arc<MemMetrics>,
    /// Broker for P2P direct-tunnel handshakes.
    p2p: Arc<P2pBroker>,
    /// Pre-login connection gate (#13): caps unauthenticated connections.
    pre_login: Arc<PreLoginGate>,
}

impl Service {
    pub fn new(cfg: ServerConfig) -> Result<Self> {
        let (policy, tls_config) = Self::prepare_config(&cfg)?;
        let access = Arc::new(RwLock::new(Arc::new(policy)));
        let http_gw = if cfg.http_gw_enabled() {
            Some(Arc::new(HttpGw::new(cfg.http_gw_port)))
        } else {
            None
        };
        let https_gw = if cfg.https_gw_enabled() {
            Some(Arc::new(HttpsGw::new(cfg.https_gw_port)))
        } else {
            None
        };
        let tls = &cfg.transport.tls;
        if tls.force {
            tracing::info!("transport.tls.force=true — non-TLS control connections rejected");
        }
        let limits = cfg.limits.clone();
        tracing::info!(
            pre_login_timeout_secs = limits.pre_login_timeout_secs,
            first_message_max_bytes = limits.first_message_max_bytes,
            pre_login_max_conns = limits.pre_login_max_conns,
            pre_login_max_conns_per_ip = limits.pre_login_max_conns_per_ip,
            idle_timeout_secs = limits.idle_timeout_secs,
            "pre-login limits"
        );
        Ok(Self {
            cfg,
            access,
            controls: Arc::new(Mutex::new(HashMap::new())),
            offline_clients: Arc::new(Mutex::new(HashMap::new())),
            http_gw,
            https_gw,
            tls_config,
            metrics: MemMetrics::new(),
            p2p: P2pBroker::new(),
            pre_login: PreLoginGate::new(
                limits.pre_login_max_conns,
                limits.pre_login_max_conns_per_ip,
            ),
        })
    }

    pub async fn run(self) -> Result<()> {
        let this = Arc::new(self);

        let tcp_addr = this.cfg.listen.clone();
        let tcp_listener = TcpListener::bind(&tcp_addr).await?;
        tracing::info!(
            %tcp_addr,
            ws_path = transport::ORBIEN_WEBSOCKET_PATH,
            tcp_mux = this.cfg.transport.tcp_mux,
            "tcp/websocket control/data listener ready"
        );

        let gw_shutdown = Arc::new(Notify::new());
        let mut set = JoinSet::new();

        if let Some(ref gw) = this.http_gw {
            let bind = this.cfg.proxy_addr.clone();
            let port = this.cfg.http_gw_port;
            let gw = Arc::clone(gw);
            let access = Arc::clone(&this.access);
            let shutdown = Arc::clone(&gw_shutdown);
            set.spawn(async move { run_http_gw_listener(bind, port, gw, access, shutdown).await });
        }

        if let Some(ref gw) = this.https_gw {
            let bind = this.cfg.proxy_addr.clone();
            let port = this.cfg.https_gw_port;
            let gw = Arc::clone(gw);
            let access = Arc::clone(&this.access);
            let shutdown = Arc::clone(&gw_shutdown);
            set.spawn(async move { run_https_gw_listener(bind, port, gw, access, shutdown).await });
        }

        if this.cfg.quic_enabled() {
            let quic_addr = Self::transport_bind_addr(&this.cfg, this.cfg.quic_port)?;
            let endpoint = transport::build_server_endpoint(
                quic_addr,
                &this.cfg.transport.quic,
                &this.cfg.transport.tls.cert_file,
                &this.cfg.transport.tls.key_file,
                &this.cfg.transport.tls.trusted_ca_file,
            )?;
            tracing::info!(%quic_addr, "quic control/data listener ready");
            let svc = Arc::clone(&this);
            set.spawn(async move { svc.run_quic(endpoint).await });
        }

        if this.cfg.kcp_enabled() {
            let kcp_addr = Self::transport_bind_addr(&this.cfg, this.cfg.kcp_port)?;
            let listener = transport::bind_kcp_listener(kcp_addr).await?;
            tracing::info!(
                %kcp_addr,
                tcp_mux = this.cfg.transport.tcp_mux,
                "kcp control/data listener ready"
            );
            let svc = Arc::clone(&this);
            set.spawn(async move { svc.run_kcp(listener).await });
        }

        if this.cfg.dashboard.enabled() {
            let web_cfg = this.cfg.dashboard.clone();
            let svc = Arc::clone(&this);
            set.spawn(async move { crate::dashboard::run(svc, web_cfg).await });
        }

        let svc = Arc::clone(&this);
        set.spawn(async move { svc.run_tcp(tcp_listener).await });

        let first = set
            .join_next()
            .await
            .ok_or_else(|| anyhow!("no listener tasks"))?;
        gw_shutdown.notify_waiters();
        set.abort_all();
        while set.join_next().await.is_some() {}

        match first {
            // #13: a listener that ends on its own is abnormal — the
            // server used to exit 0 when one gateway's accept loop broke,
            // silently killing every tunnel. Now the process fails loudly
            // so the supervisor restarts it.
            Ok(Ok(())) => {
                tracing::error!("listener exited unexpectedly; shutting down");
                Err(anyhow!("listener exited unexpectedly"))
            }
            Ok(Err(e)) => Err(e),
            Err(e) if e.is_cancelled() => Ok(()),
            Err(e) => Err(anyhow!("listener task join: {e}")),
        }
    }

    pub fn cfg(&self) -> &ServerConfig {
        &self.cfg
    }

    pub fn metrics(&self) -> &Arc<MemMetrics> {
        &self.metrics
    }

    #[allow(dead_code)]
    pub async fn access_policy(&self) -> Arc<AccessPolicy> {
        Arc::clone(&*self.access.read().await)
    }

    fn transport_bind_addr(cfg: &ServerConfig, port: u16) -> Result<SocketAddr> {
        // Parsing only: do not resolve DNS or create an endpoint here.
        format!("{}:{port}", cfg.listen_host()?)
            .parse()
            .map_err(|e| anyhow!("invalid transport bind address: {e}"))
    }

    fn prepare_config(cfg: &ServerConfig) -> Result<(AccessPolicy, Arc<rustls::ServerConfig>)> {
        cfg.validate()?;
        let policy = AccessPolicy::from_server_config(cfg)
            .map_err(|e| e.context("access policy preflight"))?;
        let tls = &cfg.transport.tls;
        let tls_config = transport::new_server_tls_config(
            &tls.cert_file, &tls.key_file, &tls.trusted_ca_file,
        ).map_err(|e| e.context("transport.tls preflight"))?;
        if cfg.quic_enabled() {
            Self::transport_bind_addr(cfg, cfg.quic_port)?;
            let mut crypto = (*tls_config).clone();
            crypto.alpn_protocols = vec![transport::ALPN_ORBIEN.to_vec()];
            let _ = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
                .map_err(|e| anyhow!("QuicServerConfig: {e}"))?;
        }
        if cfg.kcp_enabled() {
            Self::transport_bind_addr(cfg, cfg.kcp_port)?;
        }
        Ok((policy, tls_config))
    }

    pub fn check_config(cfg: &ServerConfig) -> Result<()> {
        Self::prepare_config(cfg).map(|_| ())
    }

    pub async fn reload_config_file(&self, path: impl AsRef<std::path::Path>) -> Result<Vec<String>> {
        // Load/expand/resolve/complete/validate the entire candidate first.
        let cfg = ServerConfig::load(path)?;
        self.reload_access_policy(&cfg).await
    }

    pub async fn reload_access_policy(
        &self,
        new_cfg: &ServerConfig,
    ) -> Result<Vec<String>> {
        let (new_policy, _) = Self::prepare_config(new_cfg)?;
        orbien_core::config::print_config_warnings(&new_cfg.risk_warnings());

        let mut changed: Vec<String> = Vec::new();
        let old = &self.cfg;

        if old.listen != new_cfg.listen {
            changed.push("listen".into());
        }
        if old.auth.auth_type != new_cfg.auth.auth_type
            || old.auth.token != new_cfg.auth.token
            || old.auth.token_policies != new_cfg.auth.token_policies
        {
            changed.push("auth".into());
        }
        if old.http_gw_port != new_cfg.http_gw_port
            || old.https_gw_port != new_cfg.https_gw_port
            || old.http_gw_enabled() != new_cfg.http_gw_enabled()
        {
            changed.push("gateway".into());
        }
        if old.root_domain != new_cfg.root_domain {
            changed.push("root_domain".into());
        }
        if old.quic_port != new_cfg.quic_port || old.kcp_port != new_cfg.kcp_port {
            changed.push("transport_ports".into());
        }

        *self.access.write().await = Arc::new(new_policy);
        tracing::info!(changed = ?changed, "access policy reloaded");
        Ok(changed)
    }

    /// Offline client records are capped and expire (#11): at most
    /// `MAX_OFFLINE_CLIENTS` records, each kept for `OFFLINE_TTL`. Expired
    /// and oldest records are dropped on insert; there is no background
    /// cleanup task.
    pub(crate) async fn record_offline(&self, record: OfflineClientRecord) {
        let mut offline = self.offline_clients.lock().await;
        let now = SystemTime::now();
        offline.retain(|_, r| {
            now.duration_since(r.disconnected_at).unwrap_or(Duration::ZERO) < OFFLINE_TTL
        });
        if offline.len() >= MAX_OFFLINE_CLIENTS {
            if let Some(oldest) = offline
                .iter()
                .min_by_key(|(_, r)| r.disconnected_at)
                .map(|(k, _)| k.clone())
            {
                offline.remove(&oldest);
            }
        }
        offline.insert(record.session_id.clone(), record);
    }

    pub async fn kick_client(&self, session_id: &str) -> Result<()> {
        let control = {
            let mut map = self.controls.lock().await;
            map.remove(session_id)
        };
        match control {
            Some(c) => {
                let tunnel_count = c.tunnel_count().await;
                self.record_offline(OfflineClientRecord {
                    session_id: session_id.to_string(),
                    user: c.user.clone(),
                    hostname: c.hostname.clone(),
                    os: c.os.clone(),
                    arch: c.arch.clone(),
                    client_ip: c.client_ip.clone(),
                    version: c.version.clone(),
                    tunnel_count,
                    disconnected_at: SystemTime::now(),
                })
                .await;
                c.kick("kicked from dashboard").await;
                Ok(())
            }
            None => Err(anyhow!("client not online: {session_id}")),
        }
    }

    pub async fn kick_proxy(&self, proxy_name: &str) -> Result<()> {
        let controls: Vec<Arc<Control>> = {
            let map = self.controls.lock().await;
            map.values().cloned().collect()
        };
        for ctrl in controls {
            if ctrl.kick_tunnel(proxy_name).await {
                return Ok(());
            }
        }
        Err(anyhow!("proxy not found: {proxy_name}"))
    }

    // ── P2P helpers ───────────────────────────────────────────────────────────

    /// Look up a live `Control` by session ID.  Returns `None` if the session
    /// is not currently connected.
    pub(crate) async fn control_by_session(
        &self,
        session_id: &str,
    ) -> Option<Arc<Control>> {
        self.controls.lock().await.get(session_id).cloned()
    }

    /// Handle an incoming `P2pReq` from `initiator_ctrl`.
    pub(crate) async fn handle_p2p_req(
        self: &Arc<Self>,
        req: orbien_core::msg::P2pReq,
        initiator_ctrl: Arc<Control>,
        initiator_peer: std::net::SocketAddr,
    ) -> anyhow::Result<()> {
        let responder = self
            .control_by_session(&req.peer_session_id)
            .await
            .ok_or_else(|| anyhow!("P2pReq: peer session not found: {}", req.peer_session_id))?;
        self.p2p
            .handle_req(req, initiator_ctrl, initiator_peer, responder)
            .await
    }

    /// Handle an incoming `P2pAddr` from the client identified by `session_id`.
    pub(crate) async fn handle_p2p_addr(
        &self,
        addr_msg: orbien_core::msg::P2pAddr,
        session_id: &str,
    ) -> anyhow::Result<()> {
        self.p2p.handle_addr(addr_msg, session_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str) -> OfflineClientRecord {
        OfflineClientRecord {
            session_id: id.into(),
            user: "u".into(),
            hostname: "h".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            client_ip: "127.0.0.1:1".into(),
            version: "0.2.0".into(),
            tunnel_count: 0,
            disconnected_at: SystemTime::now(),
        }
    }

    /// Step 5: offline records are capped at 1000 (oldest dropped) and
    /// records older than 24h expire on insert.
    #[tokio::test]
    async fn offline_records_capped_and_expire() {
        let svc = Service::new(ServerConfig::default()).expect("default config");
        let mut stale = record("stale");
        stale.disconnected_at = SystemTime::now() - Duration::from_secs(25 * 3600);
        svc.record_offline(stale).await;
        for i in 0..(MAX_OFFLINE_CLIENTS + 1) {
            svc.record_offline(record(&format!("s{i:04}"))).await;
        }
        let offline = svc.offline_clients.lock().await;
        assert_eq!(offline.len(), MAX_OFFLINE_CLIENTS);
        assert!(!offline.contains_key("stale"), "expired record must be gone");
        assert!(
            !offline.contains_key("s0000"),
            "oldest record must be dropped at the cap"
        );
        assert!(offline.contains_key(&format!("s{MAX_OFFLINE_CLIENTS:04}")));
    }
}
