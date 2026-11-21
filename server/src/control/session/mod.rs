mod data_pool;
mod register;
pub(crate) mod validate;

use crate::access::AccessPolicy;
use crate::metrics::{MemMetrics, ServerMetrics};
use crate::tunnel::{HttpGw, HttpsGw, TunnelManager};
use anyhow::{anyhow, Result};
use orbien_core::config::ServerConfig;
use orbien_core::msg::{self, KickOut, Message, Ping, Pong};
use orbien_core::transport::DynStream;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tokio::task::JoinSet;
use tokio::time::sleep;

type CtrlRead = ReadHalf<DynStream>;
type CtrlWrite = WriteHalf<DynStream>;

/// Minimal interface the control session needs from the Service layer in order
/// to dispatch P2P broker messages without creating a circular dependency.
pub type P2pHandler = Arc<
    dyn Fn(
            Message,
            String, // session_id of the sender
            SocketAddr,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>
        + Send
        + Sync,
>;

pub struct Control {
    pub session_id: String,
    pub user: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub client_ip: String,
    pub connected_at: Instant,
    cfg: ServerConfig,
    reader: Mutex<CtrlRead>,
    /// WriteHalf held as `Option` so `run()` can take it for the writer task,
    /// and so `shutdown()` can call `AsyncWriteExt::shutdown` cleanly.
    /// All writes (Pong, KickOut, P2P) serialize through this single Mutex.
    writer: Mutex<Option<CtrlWrite>>,
    data_tx: mpsc::Sender<DynStream>,
    data_rx: Mutex<mpsc::Receiver<DynStream>>,
    data_notify: Notify,
    shutdown_notify: Notify,
    tunnels: Mutex<TunnelManager>,
    bg_tasks: Mutex<JoinSet<()>>,
    closed: AtomicBool,
    pool_count: usize,
    http_gw: Option<Arc<HttpGw>>,
    https_gw: Option<Arc<HttpsGw>>,
    /// Live policy reference (#11): registrations read the current policy
    /// on every call, so a reload applies to existing sessions immediately
    /// instead of only to sessions logged in after the reload.
    access: Arc<RwLock<Arc<AccessPolicy>>>,
    /// Id of the token this session logged in with (SHA-256 hex, #11).
    /// Never the raw token.
    token_id: String,
    /// Hex-encoded 32-byte secret issued at login (#11). Resume and
    /// data-connection proofs are HMACs keyed by it.
    session_secret: String,
    pub metrics: Arc<MemMetrics>,
    last_ping_unix: AtomicI64,
    peer_socket_addr: SocketAddr,
    p2p_handler: Option<P2pHandler>,
}

impl Control {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: String,
        stream: DynStream,
        cfg: ServerConfig,
        pool_count: usize,
        http_gw: Option<Arc<HttpGw>>,
        https_gw: Option<Arc<HttpsGw>>,
        access: Arc<RwLock<Arc<AccessPolicy>>>,
        user: String,
        hostname: String,
        os: String,
        arch: String,
        version: String,
        client_ip: String,
        metrics: Arc<MemMetrics>,
        token_id: String,
        session_secret: String,
    ) -> Self {
        let peer_socket_addr = client_ip
            .parse::<SocketAddr>()
            .or_else(|_| {
                client_ip
                    .parse::<IpAddr>()
                    .map(|ip| SocketAddr::new(ip, 0))
            })
            .unwrap_or_else(|_| SocketAddr::from_str("0.0.0.0:0").unwrap());

        let (reader, writer) = tokio::io::split(stream);
        // #11: the data-conn pool holds at most what the server asked the
        // client for (pool_count), not a hardcoded 64.
        let (data_tx, data_rx) = mpsc::channel(pool_count.max(1));

        Self {
            session_id,
            user,
            hostname,
            os,
            arch,
            version,
            client_ip,
            connected_at: Instant::now(),
            cfg,
            reader: Mutex::new(reader),
            writer: Mutex::new(Some(writer)),
            data_tx,
            data_rx: Mutex::new(data_rx),
            data_notify: Notify::new(),
            shutdown_notify: Notify::new(),
            tunnels: Mutex::new(TunnelManager::new()),
            bg_tasks: Mutex::new(JoinSet::new()),
            closed: AtomicBool::new(false),
            pool_count: pool_count.max(1),
            http_gw,
            https_gw,
            access,
            token_id,
            session_secret,
            metrics,
            last_ping_unix: AtomicI64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            ),
            peer_socket_addr,
            p2p_handler: None,
        }
    }

    // ── P2P helpers ────────────────────────────────────────────────────────────

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Id of the token this session logged in with (#11).
    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    /// Hex-encoded session secret issued at login (#11).
    pub fn session_secret(&self) -> &str {
        &self.session_secret
    }

    /// Current access policy (live: reloads apply immediately, #11).
    pub async fn access_policy(&self) -> Arc<AccessPolicy> {
        Arc::clone(&*self.access.read().await)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_socket_addr
    }

    pub fn set_p2p_handler(&mut self, handler: P2pHandler) {
        self.p2p_handler = Some(handler);
    }

    /// Write a P2P broker message directly onto this client's control stream.
    /// All writes go through `self.writer` so ordering with Pong/KickOut is
    /// guaranteed without a separate channel.
    pub async fn send_p2p_msg(&self, msg: Message) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(anyhow!("control closed, cannot send P2P message"));
        }
        match *self.writer.lock().await {
            Some(ref mut w) => msg::write_msg(w, &msg)
                .await
                .map_err(|e| anyhow!("send_p2p_msg: {e}")),
            None => Err(anyhow!("writer not initialised")),
        }
    }

    // ── Standard session API ──────────────────────────────────────────────────

    pub async fn tunnel_summaries(&self) -> Vec<crate::tunnel::TunnelSummary> {
        self.tunnels.lock().await.summaries()
    }

    pub async fn tunnel_count(&self) -> usize {
        self.tunnels.lock().await.len()
    }

    pub async fn has_tunnel(&self, name: &str) -> bool {
        self.tunnels.lock().await.contains(name)
    }

    pub async fn kick_tunnel(&self, name: &str) -> bool {
        let mut tm = self.tunnels.lock().await;
        if let Some(ty) = tm.remove(name).await {
            self.metrics.close_tunnel(name, ty);
            tracing::info!(
                session_id = %self.session_id,
                tunnel = %name,
                "tunnel kicked from dashboard"
            );
            true
        } else {
            false
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        for _ in 0..self.pool_count {
            if self.closed.load(Ordering::SeqCst) {
                return Ok(());
            }
            self.request_data_conn().await?;
        }

        // Heartbeat watchdog
        {
            let timeout = self.effective_ping_timeout();
            if timeout > 0 {
                let this = Arc::clone(&self);
                self.bg_tasks.lock().await.spawn(async move {
                    loop {
                        if this.closed.load(Ordering::SeqCst) {
                            break;
                        }
                        sleep(Duration::from_secs(1)).await;
                        let last = this.last_ping_unix.load(Ordering::Relaxed);
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        if last > 0 && now.saturating_sub(last) > timeout {
                            tracing::warn!(
                                session_id = %this.session_id,
                                timeout_secs = timeout,
                                "heartbeat timeout"
                            );
                            this.shutdown().await;
                            break;
                        }
                    }
                });
            }
        }

        // Message read loop
        loop {
            if self.closed.load(Ordering::SeqCst) {
                break;
            }
            let msg = tokio::select! {
                _ = self.shutdown_notify.notified() => {
                    break;
                }
                msg = async {
                    let mut reader = self.reader.lock().await;
                    msg::read_msg(&mut *reader).await
                } => {
                    match msg {
                        Ok(m) => m,
                        Err(e) => {
                            if !self.closed.load(Ordering::SeqCst) {
                                tracing::debug!(error = %e, "control read ended");
                            }
                            break;
                        }
                    }
                }
            };

            match msg {
                Message::NewTunnel(np) => self.handle_new_tunnel(np).await?,
                Message::CloseTunnel(cp) => self.handle_close_tunnel(cp).await?,
                Message::Ping(p) => self.handle_ping(p).await?,

                p2p_msg @ Message::P2pReq(_) | p2p_msg @ Message::P2pAddr(_) => {
                    if let Some(ref handler) = self.p2p_handler {
                        let peer = self.peer_socket_addr;
                        let sid = self.session_id.clone();
                        if let Err(e) = handler(p2p_msg, sid, peer).await {
                            tracing::warn!(error = %e, "P2P broker dispatch error");
                        }
                    } else {
                        tracing::warn!("P2P message received but no handler registered");
                    }
                }

                other => {
                    tracing::warn!(ty = other.type_byte(), "ignored control message");
                }
            }
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        // swap returns the *old* value; true means already shutting down.
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.shutdown_notify.notify_waiters();
        self.data_notify.notify_waiters();
        {
            let mut tm = self.tunnels.lock().await;
            for (name, ty) in tm.close_all().await {
                self.metrics.close_tunnel(&name, ty);
            }
        }
        {
            if let Some(ref mut w) = *self.writer.lock().await {
                let _ = w.shutdown().await;
            }
        }
        let mut bg = self.bg_tasks.lock().await;
        bg.abort_all();
        while bg.join_next().await.is_some() {}
    }

    pub async fn kick(&self, reason: impl Into<String>) {
        let reason = reason.into();
        {
            if let Some(ref mut w) = *self.writer.lock().await {
                let _ = msg::write_msg(
                    w,
                    &Message::KickOut(KickOut {
                        reason: reason.clone(),
                    }),
                )
                .await;
            }
        }
        tracing::info!(session_id = %self.session_id, %reason, "kicking client");
        self.shutdown().await;
    }

    fn effective_ping_timeout(&self) -> i64 {
        let hb_to = self.cfg.transport.heartbeat_timeout;
        if hb_to > 0 {
            return hb_to;
        }
        if self.cfg.transport.tcp_mux {
            let mux_ka = self.cfg.transport.mux_keepalive_secs;
            if mux_ka > 0 {
                return mux_ka.saturating_mul(3);
            }
        }
        -1
    }

    async fn handle_ping(&self, _p: Ping) -> Result<()> {
        self.last_ping_unix.store(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            Ordering::Relaxed,
        );
        if let Some(ref mut w) = *self.writer.lock().await {
            msg::write_msg(w, &Message::Pong(Pong::default())).await?;
        }
        Ok(())
    }
}
