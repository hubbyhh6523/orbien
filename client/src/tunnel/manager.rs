use super::udp::run_udp_session;
use crate::plugin::{self, ConnectionInfo, Plugin, PluginContext};
use anyhow::{anyhow, Result};
use orbien_core::config::{ClientConfig, TunnelConfig};
use orbien_core::io;
use orbien_core::limit::{self, maybe_limit, BandwidthLimitSide, BandwidthLimiter};
use orbien_core::msg::StartDataConn;
use orbien_core::net::{
    addrs_from_start_data_conn, build_proxy_protocol_header, parse_proxy_protocol_version,
};
use orbien_core::transport::DynStream;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex};

struct TunnelEntry {
    cfg: TunnelConfig,
    limiter: Option<Arc<BandwidthLimiter>>,
    plugin: Option<Arc<dyn Plugin>>,
    proxy_protocol: Option<&'static str>,
    udp_cancel: Mutex<Option<oneshot::Sender<()>>>,
}

pub struct TunnelManager {
    by_name: HashMap<String, TunnelEntry>,
    udp_packet_size: usize,
    /// Max visitor sockets/tasks per UDP tunnel forwarder (#14).
    udp_max_sessions: usize,
}

impl TunnelManager {
    pub fn from_config(cfg: &ClientConfig) -> Result<Self> {
        let mut by_name = HashMap::new();
        // #17: resolve the client's own server endpoint once; the SOCKS5
        // plugin refuses targets matching these addresses.
        let server_addrs = resolve_server_addrs(&cfg.server);
        for p in &cfg.tunnels {
            let limiter = limit::limiter_if_side(
                p.transport.bandwidth,
                &p.transport.bandwidth_limit_side,
                BandwidthLimitSide::Client,
            )
            .unwrap_or_else(|e| {
                tracing::warn!(
                    tunnel = %p.name,
                    error = %e,
                    "invalid bandwidth; ignoring"
                );
                None
            });
            if let Some(ref l) = limiter {
                tracing::info!(
                    tunnel = %p.name,
                    mbps = p.transport.bandwidth,
                    bytes_per_sec = l.bytes_per_sec(),
                    side = "client",
                    "bandwidth limit enabled"
                );
            }

            let plugin = if let Some(ref pc) = p.plugin {
                if pc.plugin_type.is_empty() {
                    None
                } else {
                    let cn = pick_cert_common_name(&p.domains, &p.name);
                    let ctx = PluginContext {
                        name: p.name.clone(),
                        cert_common_name: cn,
                        server_addrs: server_addrs.clone(),
                        max_connections: p.max_connections,
                    };
                    Some(plugin::create(ctx, pc)?)
                }
            } else {
                None
            };

            let proxy_protocol = parse_proxy_protocol_version(&p.transport.proxy_protocol_version)?;
            if let Some(ver) = proxy_protocol {
                tracing::info!(
                    tunnel = %p.name,
                    version = ver,
                    "PROXY Protocol enabled (client writes header to local)"
                );
            }

            by_name.insert(
                p.name.clone(),
                TunnelEntry {
                    cfg: p.clone(),
                    limiter,
                    plugin,
                    proxy_protocol,
                    udp_cancel: Mutex::new(None),
                },
            );
        }
        Ok(Self {
            by_name,
            udp_packet_size: cfg.udp_packet_size.max(512),
            udp_max_sessions: cfg.udp_max_sessions.max(1),
        })
    }

    pub async fn handle_data_conn(&self, start: &StartDataConn, data: DynStream) -> Result<()> {
        let entry = self
            .by_name
            .get(&start.tunnel_name)
            .ok_or_else(|| anyhow!("unknown tunnel: {}", start.tunnel_name))?;

        match entry.cfg.protocol.as_str() {
            "udp" => self.handle_udp(entry, data).await,
            "tcp" | "http" | "https" => self.handle_stream(entry, start, data).await,
            other => Err(anyhow!(
                "unsupported tunnel protocol on data conn: {} ({})",
                other,
                entry.cfg.name
            )),
        }
    }

    async fn handle_stream(
        &self,
        entry: &TunnelEntry,
        start: &StartDataConn,
        data: DynStream,
    ) -> Result<()> {
        let data = maybe_limit(data, entry.limiter.clone());

        if let Some(ref plugin) = entry.plugin {
            tracing::debug!(
                tunnel = %entry.cfg.name,
                plugin = plugin.name(),
                "handle by plugin"
            );
            return plugin
                .handle(ConnectionInfo {
                    stream: data,
                    src_addr: start.src_addr.clone(),
                    src_port: start.src_port,
                    dst_addr: start.dst_addr.clone(),
                    dst_port: start.dst_port,
                })
                .await;
        }

        let (svc_host, svc_port) = entry.cfg.service_host_port()?;
        let local_addr = entry.cfg.service.trim().to_string();
        if local_addr.is_empty() || svc_port == 0 {
            return Err(anyhow!(
                "tunnel {} has empty/invalid service (local backend)",
                entry.cfg.name
            ));
        }
        let local = TcpStream::connect(&local_addr).await.map_err(|e| {
            anyhow!(
                "dial local {} for tunnel {}: {}",
                local_addr,
                entry.cfg.name,
                e
            )
        })?;
        orbien_core::net::enable_nodelay(&local);
        let mut local = local;

        if let Some(ver) = entry.proxy_protocol {
            if let Some((src, dst)) = addrs_from_start_data_conn(
                &start.src_addr,
                start.src_port,
                &start.dst_addr,
                start.dst_port,
                svc_port,
            ) {
                let hdr = build_proxy_protocol_header(src, dst, ver)?;
                local.write_all(&hdr).await?;
                tracing::debug!(
                    tunnel = %entry.cfg.name,
                    version = ver,
                    %src,
                    %dst,
                    "wrote PROXY Protocol header to local"
                );
            } else {
                tracing::debug!(
                    tunnel = %entry.cfg.name,
                    "PROXY Protocol configured but StartDataConn src empty; skip"
                );
            }
        }

        tracing::debug!(
            tunnel = %entry.cfg.name,
            %local_addr,
            host = %svc_host,
            limited = entry.limiter.is_some(),
            "joining data <-> local"
        );
        if let Err(e) = io::join(data, local).await {
            tracing::debug!(error = %e, "join ended");
        }
        Ok(())
    }

    async fn handle_udp(&self, entry: &TunnelEntry, data: DynStream) -> Result<()> {
        let local_addr: std::net::SocketAddr = entry
            .cfg
            .service
            .trim()
            .parse()
            .map_err(|e| anyhow!("invalid local udp service {}: {e}", entry.cfg.service))?;

        let (cancel_tx, cancel_rx) = oneshot::channel();
        {
            let mut slot = entry.udp_cancel.lock().await;
            if let Some(old) = slot.take() {
                let _ = old.send(());
            }
            *slot = Some(cancel_tx);
        }

        tracing::info!(
            tunnel = %entry.cfg.name,
            %local_addr,
            "udp data conn; starting forwarder"
        );

        let data = maybe_limit(data, entry.limiter.clone());

        run_udp_session(
            data,
            local_addr,
            self.udp_packet_size,
            entry.proxy_protocol.map(|s| s.to_string()),
            self.udp_max_sessions,
            cancel_rx,
        )
        .await
    }
}
fn pick_cert_common_name(domains: &[String], tunnel_name: &str) -> String {
    for d in domains {
        let d = d.trim();
        if d.is_empty() {
            continue;
        }
        if d.contains('.') && !d.contains('*') {
            return d.to_ascii_lowercase();
        }
    }
    for d in domains {
        let d = d.trim();
        if !d.is_empty() {
            return d.to_ascii_lowercase();
        }
    }
    tunnel_name.trim().to_ascii_lowercase()
}

/// Resolve the client's own server endpoint once (#17). A lookup failure
/// only warns: the plugin still runs, just without the server-address block.
fn resolve_server_addrs(server: &str) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    let (host, port) = match orbien_core::config::parse_host_port(server, 9527) {
        Ok(hp) => hp,
        Err(e) => {
            tracing::warn!(server = %server, error = %e,
                "cannot parse server address; socks5 will not block the server address");
            return Vec::new();
        }
    };
    match (host.as_str(), port).to_socket_addrs() {
        Ok(addrs) => {
            let mut out: Vec<std::net::IpAddr> = addrs.map(|a| a.ip()).collect();
            out.sort();
            out.dedup();
            out
        }
        Err(e) => {
            tracing::warn!(server = %server, error = %e,
                "cannot resolve server address; socks5 will not block the server address");
            Vec::new()
        }
    }
}
