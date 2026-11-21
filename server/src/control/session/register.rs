use super::Control;
use crate::metrics::ServerMetrics;
use crate::sanitize::sanitize_for_logging;
use crate::tunnel::{
    format_local_addr, HttpTunnel, HttpsTunnel, RegisteredTunnel, TcpTunnel, UdpTunnel,
};
use anyhow::{anyhow, Result};
use orbien_core::msg::{self, CloseTunnel, Message, NewTunnel, NewTunnelResp};
use std::sync::Arc;

impl Control {
    fn note_tunnel_registered(&self, name: &str, tunnel_type: &str) {
        self.metrics
            .new_tunnel(name, tunnel_type, &self.user, &self.session_id);
    }

    pub(super) async fn handle_new_tunnel(self: &Arc<Self>, np: NewTunnel) -> Result<()> {
        let resp = match self.register_tunnel(&np).await {
            Ok(remote_addr) => NewTunnelResp {
                tunnel_name: np.tunnel_name.clone(),
                remote_addr,
                error: String::new(),
            },
            Err(e) => {
                // #11: rejected registrations are logged with the token id
                // and the reason; client-supplied text is sanitized first.
                let token_id = self.token_id();
                tracing::warn!(
                    token_id = %token_id.get(..16).unwrap_or(token_id),
                    tunnel = %sanitize_for_logging(&np.tunnel_name),
                    error = %sanitize_for_logging(&e.to_string()),
                    "tunnel registration rejected"
                );
                NewTunnelResp {
                    tunnel_name: np.tunnel_name.clone(),
                    remote_addr: String::new(),
                    error: e.to_string(),
                }
            }
        };

        let mut writer_lock = self.writer.lock().await;
        if let Some(w) = writer_lock.as_mut() {
            msg::write_msg(w, &Message::NewTunnelResp(resp))
                .await
                .map_err(|e| anyhow!("handle_new_tunnel: {e}"))?;
        } else {
            return Err(anyhow!("handle_new_tunnel: writer not initialised"));
        }
        Ok(())
    }

    async fn register_tunnel(self: &Arc<Self>, np: &NewTunnel) -> Result<String> {
        // #11: reject over-limit registrations before any listener or
        // route is created. A rejection lands in NewTunnelResp.error via
        // handle_new_tunnel; nothing is created on this path.
        let is_reregister = self.has_tunnel(&np.tunnel_name).await;
        let tunnels_in_session = self.tunnel_count().await;
        super::validate::validate_new_tunnel(np, tunnels_in_session, is_reregister)
            .map_err(|e| anyhow!("{e}"))?;
        // #11: enforce the session token's policy before any listener or
        // route is created. A rejection lands in NewTunnelResp.error via
        // handle_new_tunnel; nothing is created on this path.
        let remote_port = if (1..=65535).contains(&np.remote_port) {
            Some(np.remote_port as u16)
        } else {
            None
        };
        self.access_policy().await.authorize_proxy(
            self.token_id(),
            &np.tunnel_name,
            &np.protocol,
            remote_port,
        )?;
        match np.protocol.as_str() {
            "tcp" => self.register_tcp_tunnel(np).await,
            "http" => self.register_http_tunnel(np).await,
            "https" => self.register_https_tunnel(np).await,
            "udp" => self.register_udp_tunnel(np).await,
            other => Err(anyhow!("unsupported tunnel protocol: {other}")),
        }
    }

    async fn register_tcp_tunnel(self: &Arc<Self>, np: &NewTunnel) -> Result<String> {
        if np.remote_port <= 0 || np.remote_port > 65535 {
            return Err(anyhow!("invalid remote_port"));
        }

        let limiter = orbien_core::limit::limiter_if_side(
            np.bandwidth,
            &np.bandwidth_limit_side,
            orbien_core::limit::BandwidthLimitSide::Server,
        )?;
        if let Some(ref l) = limiter {
            tracing::info!(
                tunnel = %np.tunnel_name,
                bytes_per_sec = l.bytes_per_sec(),
                mode = "server",
                "bandwidth limit enabled"
            );
        }

        let bind_addr = self.cfg.proxy_addr.clone();
        let remote_port = np.remote_port as u16;
        let name = np.tunnel_name.clone();
        let control = Arc::clone(self);

        {
            // #11: the old listener must be released before the new one
            // can bind the same port, so TCP keeps the remove-first order
            // (unlike HTTP/HTTPS, whose registration is atomic). A failed
            // re-bind therefore still loses the old tunnel, as before.
            let mut tm = self.tunnels.lock().await;
            if let Some(old_ty) = tm.remove(&name).await {
                self.metrics.close_tunnel(&name, old_ty);
            }
        }

        let tunnel = TcpTunnel::start(
            name.clone(),
            bind_addr,
            remote_port,
            control,
            limiter,
            self.access_policy().await,
        )
        .await?;
        let remote_addr = format!(":{}", remote_port);

        let local_addr = format_local_addr(&np.local_ip, np.local_port);
        let mut tm = self.tunnels.lock().await;
        let _ = tm
            .insert(name.clone(), RegisteredTunnel::Tcp(tunnel), local_addr)
            .await;
        self.note_tunnel_registered(&name, "tcp");
        tracing::info!(tunnel = %np.tunnel_name, port = remote_port, "tcp tunnel registered");
        Ok(remote_addr)
    }

    async fn register_http_tunnel(self: &Arc<Self>, np: &NewTunnel) -> Result<String> {
        let gw = self
            .http_gw
            .clone()
            .ok_or_else(|| anyhow!("http tunnel requires server httpGwPort > 0"))?;

        let limiter = orbien_core::limit::limiter_if_side(
            np.bandwidth,
            &np.bandwidth_limit_side,
            orbien_core::limit::BandwidthLimitSide::Server,
        )?;
        if let Some(ref l) = limiter {
            tracing::info!(
                tunnel = %np.tunnel_name,
                bytes_per_sec = l.bytes_per_sec(),
                mode = "server",
                "bandwidth limit enabled"
            );
        }

        let name = np.tunnel_name.clone();
        // #11: no tm.remove here: HttpTunnel::register is atomic (a
        // conflict adds no route), and TunnelManager::insert below closes
        // the old tunnel only after the new one succeeds, so a failed
        // registration keeps the previous tunnel of the same name.

        let tunnel = HttpTunnel::register(
            np,
            Arc::clone(self),
            Arc::clone(&gw),
            &self.cfg.root_domain,
            limiter,
        )
        .await?;

        let remote_addr = tunnel
            .domains
            .iter()
            .map(|d| format!("{d}:{}", gw.listen_port))
            .collect::<Vec<_>>()
            .join(",");

        let local_addr = format_local_addr(&np.local_ip, np.local_port);
        let mut tm = self.tunnels.lock().await;
        let _ = tm
            .insert(name.clone(), RegisteredTunnel::Http(tunnel), local_addr)
            .await;
        self.note_tunnel_registered(&name, "http");
        Ok(remote_addr)
    }

    async fn register_https_tunnel(self: &Arc<Self>, np: &NewTunnel) -> Result<String> {
        let gw = self
            .https_gw
            .clone()
            .ok_or_else(|| anyhow!("https tunnel requires server httpsGwPort > 0"))?;

        let limiter = orbien_core::limit::limiter_if_side(
            np.bandwidth,
            &np.bandwidth_limit_side,
            orbien_core::limit::BandwidthLimitSide::Server,
        )?;
        if let Some(ref l) = limiter {
            tracing::info!(
                tunnel = %np.tunnel_name,
                bytes_per_sec = l.bytes_per_sec(),
                mode = "server",
                "bandwidth limit enabled"
            );
        }

        let name = np.tunnel_name.clone();
        // #11: no tm.remove here, same as HTTP: HttpsTunnel::register is
        // atomic and insert below closes the old tunnel only on success.

        let tunnel = HttpsTunnel::register(
            np,
            Arc::clone(self),
            Arc::clone(&gw),
            &self.cfg.root_domain,
            limiter,
        )
        .await?;

        let remote_addr = tunnel
            .domains
            .iter()
            .map(|d| format!("{d}:{}", gw.listen_port))
            .collect::<Vec<_>>()
            .join(",");

        let local_addr = format_local_addr(&np.local_ip, np.local_port);
        let mut tm = self.tunnels.lock().await;
        let _ = tm
            .insert(name.clone(), RegisteredTunnel::Https(tunnel), local_addr)
            .await;
        self.note_tunnel_registered(&name, "https");
        Ok(remote_addr)
    }

    async fn register_udp_tunnel(self: &Arc<Self>, np: &NewTunnel) -> Result<String> {
        if np.remote_port <= 0 || np.remote_port > 65535 {
            return Err(anyhow!("invalid remote_port"));
        }

        let limiter = orbien_core::limit::limiter_if_side(
            np.bandwidth,
            &np.bandwidth_limit_side,
            orbien_core::limit::BandwidthLimitSide::Server,
        )?;
        if let Some(ref l) = limiter {
            tracing::info!(
                tunnel = %np.tunnel_name,
                bytes_per_sec = l.bytes_per_sec(),
                mode = "server",
                "bandwidth limit enabled"
            );
        }

        let bind_addr = self.cfg.proxy_addr.clone();
        let remote_port = np.remote_port as u16;
        let name = np.tunnel_name.clone();
        let control = Arc::clone(self);
        let packet_size = self.cfg.udp_packet_size.max(512);
        let max_connections = np.max_connections;

        {
            // #11: same as TCP above — the old socket must be released
            // before the new one can bind the same port.
            let mut tm = self.tunnels.lock().await;
            if let Some(old_ty) = tm.remove(&name).await {
                self.metrics.close_tunnel(&name, old_ty);
            }
        }

        let tunnel = UdpTunnel::start(
            name.clone(),
            bind_addr,
            remote_port,
            control,
            limiter,
            packet_size,
            max_connections,
            self.access_policy().await,
        )
        .await?;
        let remote_addr = format!(":{}", remote_port);

        let local_addr = format_local_addr(&np.local_ip, np.local_port);
        let mut tm = self.tunnels.lock().await;
        let _ = tm
            .insert(name.clone(), RegisteredTunnel::Udp(tunnel), local_addr)
            .await;
        self.note_tunnel_registered(&name, "udp");
        tracing::info!(tunnel = %np.tunnel_name, port = remote_port, "udp tunnel registered");
        Ok(remote_addr)
    }

    pub(super) async fn handle_close_tunnel(&self, cp: CloseTunnel) -> Result<()> {
        let mut tm = self.tunnels.lock().await;
        if let Some(ty) = tm.remove(&cp.tunnel_name).await {
            self.metrics.close_tunnel(&cp.tunnel_name, ty);
        }
        Ok(())
    }
}
