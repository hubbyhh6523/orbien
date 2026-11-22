use crate::connector::{build_connector, Connector};
use crate::control::p2p::{run_p2p_tcp_session, run_p2p_udp_session};
use crate::sanitize::sanitize_for_logging;
use crate::session_id;
use crate::tunnel::TunnelManager;
use anyhow::{anyhow, Result};
use orbien_core::auth;
use orbien_core::config::ClientConfig;
use orbien_core::msg::{
    self, Login, Message, MessageReadError, NewDataConn, NewTunnel, P2pAddr, P2pInfo,
    P2pReady, Ping,
};
use orbien_core::p2p::{
    parse_candidates, punch, query_public_addrs, HolePunchConfig, HolePunchResult,
    StunQueryOptions,
};
use orbien_core::transport::DynStream;
use orbien_core::VERSION;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio::time::{interval, sleep};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub enum SessionEnd {
    Disconnected { session_id: String },
    Kicked { session_id: String, reason: String },
}

type CtrlRead = ReadHalf<DynStream>;
type CtrlWrite = WriteHalf<DynStream>;
type OnTunnelRemote = Arc<dyn Fn(String, String) + Send + Sync>;

/// Burst above `pool_count` the client tolerates for simultaneous
/// `ReqDataConn` handling (#13). Mirrors the server's default
/// `limits.maxOutstandingDataConns`; the server enforces its own
/// configured cap too, this is the client-side backstop.
const DATA_CONN_BURST: usize = 8;

pub struct Control {
    cfg: ClientConfig,
    session_id: String,
    /// Hex-encoded session secret issued by the server at login (#11);
    /// data-connection proofs are HMACs keyed by it.
    session_secret: String,
    reader: Mutex<CtrlRead>,
    writer: Mutex<CtrlWrite>,
    tunnels: TunnelManager,
    connector: Arc<dyn Connector>,
    cancel: CancellationToken,
    data_tasks: Mutex<JoinSet<()>>,
    /// Data connections currently being opened (#13). A plain
    /// `data_tasks.len()` cannot be used: `JoinSet::len` also counts
    /// finished-but-unjoined tasks, so it would grow forever.
    data_conns_in_flight: AtomicUsize,
    on_tunnel_remote: OnTunnelRemote,
    last_pong_unix: AtomicI64,
}

impl Control {
    pub async fn start(
        cfg: &ClientConfig,
        previous_session_id: String,
        config_path: &Path,
        parent_cancel: CancellationToken,
        on_connected: impl FnOnce(),
        on_tunnel_remote: OnTunnelRemote,
    ) -> Result<SessionEnd> {
        let session_cancel = parent_cancel.child_token();
        let connector = build_connector(cfg).await?;
        let mut stream = connector.open().await?;
        tracing::info!(
            endpoint = %cfg.server_endpoint(),
            protocol = %cfg.transport.protocol,
            tcp_mux = cfg.uses_yamux(),
            "control stream opened"
        );

        let timestamp = now_secs();
        let auth_digest = auth::compute_auth_digest(&cfg.auth.token, timestamp);
        // #11: prove possession of the previous session's secret when
        // resuming its id. Without a stored secret (or with a wrong one)
        // the server issues a new id instead of taking over the old one.
        let resume_secret = session_id::load_resume_secret(config_path);
        let resume_proof = if previous_session_id.is_empty() || resume_secret.is_empty() {
            String::new()
        } else {
            auth::compute_session_proof(
                &resume_secret,
                "resume",
                &previous_session_id,
                timestamp,
            )
        };
        let login = Login {
            version: VERSION.into(),
            hostname: hostname(),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            user: cfg.user.clone(),
            auth_digest,
            timestamp,
            session_id: previous_session_id,
            pool_count: cfg.transport.pool_count,
            resume_proof,
        };
        tracing::info!(
            hostname = %login.hostname,
            os = %login.os,
            arch = %login.arch,
            user = %login.user,
            "login identity"
        );

        msg::write_msg(&mut stream, &Message::Login(login)).await?;

        let resp = match msg::read_msg(&mut stream).await {
            Ok(Message::LoginResp(r)) => r,
            Ok(other) => {
                return Err(anyhow!(
                    "expected LoginResp, got message type {}; check server version",
                    other.type_byte()
                ));
            }
            Err(e) => {
                return Err(anyhow!(
                    "server closed connection before sending LoginResp: {e}; \
                     verify transport.tls, tcpMux, protocol, token, and bind_port match on both sides"
                ));
            }
        };

        if !resp.error.is_empty() {
            return Err(anyhow!("login rejected by server: {}", resp.error));
        }

        tracing::info!(session_id = %resp.session_id, "login ok");
        if let Err(e) = session_id::save(config_path, &resp.session_id) {
            tracing::warn!(error = %e, "failed to persist session_id");
        }
        // #11: store the new session secret for resume and data-conn
        // proofs. An old server leaves it empty; data conns then carry
        // no proof and are refused by a new server (hard cut).
        if !resp.resume_token.is_empty() {
            if let Err(e) = session_id::save_resume_secret(config_path, &resp.resume_token) {
                tracing::warn!(error = %e, "failed to persist resume secret");
            }
        }

        let (reader, writer) = tokio::io::split(stream);
        let ctl = Arc::new(Control {
            cfg: cfg.clone(),
            session_id: resp.session_id.clone(),
            session_secret: resp.resume_token.clone(),
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            tunnels: TunnelManager::from_config(cfg)?,
            connector,
            cancel: session_cancel.clone(),
            data_tasks: Mutex::new(JoinSet::new()),
            data_conns_in_flight: AtomicUsize::new(0),
            on_tunnel_remote,
            last_pong_unix: AtomicI64::new(now_secs()),
        });

        ctl.register_all_tunnels().await?;
        on_connected();

        let hb = Arc::clone(&ctl);
        let hb_cancel = session_cancel.clone();
        let heartbeat = tokio::spawn(async move {
            tokio::select! {
                _ = hb_cancel.cancelled() => {}
                _ = hb.heartbeat_loop() => {}
            }
        });

        let to = Arc::clone(&ctl);
        let to_cancel = session_cancel.clone();
        let timeout_watch = tokio::spawn(async move {
            tokio::select! {
                _ = to_cancel.cancelled() => {}
                _ = to.heartbeat_timeout_loop() => {}
            }
        });

        let result = ctl.clone().reader_loop().await;
        ctl.shutdown().await;
        heartbeat.abort();
        timeout_watch.abort();
        let _ = heartbeat.await;
        let _ = timeout_watch.await;

        match result {
            Ok(ReaderEnd::Kicked(reason)) => Ok(SessionEnd::Kicked {
                session_id: resp.session_id,
                reason,
            }),
            Ok(ReaderEnd::Closed) => Ok(SessionEnd::Disconnected {
                session_id: resp.session_id,
            }),
            Err(e) => Err(e),
        }
    }

    async fn shutdown(&self) {
        self.cancel.cancel();
        {
            let mut writer = self.writer.lock().await;
            let _ = writer.shutdown().await;
        }
        let mut tasks = self.data_tasks.lock().await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    async fn register_all_tunnels(&self) -> Result<()> {
        for p in &self.cfg.tunnels {
            let (local_ip, local_port) = p.service_host_port()?;
            if p.requires_local_service() && local_port == 0 {
                return Err(anyhow!(
                    "tunnel `{}` requires service = \"host:port\" (local backend)",
                    p.name
                ));
            }
            if p.remote_port == 0 && matches!(p.protocol.as_str(), "tcp" | "udp") {
                return Err(anyhow!(
                    "tunnel `{}` type {} requires remotePort > 0",
                    p.name,
                    p.protocol
                ));
            }
            let msg = match p.protocol.as_str() {
                "tcp" => Message::NewTunnel(new_tunnel_base(
                    &p.name, "tcp", p.remote_port as i32,
                    &local_ip, local_port, &p.transport, p.max_connections, |_| {},
                )),
                "udp" => Message::NewTunnel(new_tunnel_base(
                    &p.name, "udp", p.remote_port as i32,
                    &local_ip, local_port, &p.transport, p.max_connections, |_| {},
                )),
                "http" => Message::NewTunnel(new_tunnel_base(
                    &p.name, "http", 0, &local_ip, local_port,
                    &p.transport, p.max_connections,
                    |np| {
                        np.domains = p.domains.clone();
                        np.locations = p.locations.clone();
                        np.basic_auth_user = p.basic_auth_user.clone();
                        np.basic_auth_password = p.basic_auth_password.clone();
                        np.host_header_rewrite = p.host_header_rewrite.clone();
                        np.route_by_http_user = p.route_by_http_user.clone();
                    },
                )),
                "https" => Message::NewTunnel(new_tunnel_base(
                    &p.name, "https", 0, &local_ip, local_port,
                    &p.transport, p.max_connections,
                    |np| { np.domains = p.domains.clone(); },
                )),
                other => {
                    tracing::warn!(name = %p.name, protocol = %other, "skip unsupported tunnel protocol");
                    continue;
                }
            };
            let mut writer = self.writer.lock().await;
            msg::write_msg(&mut *writer, &msg).await?;
            match p.protocol.as_str() {
                "tcp" => tracing::info!(
                    name = %p.name, service = %p.service,
                    remote_port = p.remote_port, "sent NewTunnel"
                ),
                "udp" => tracing::info!(
                    name = %p.name, service = %p.service,
                    remote_port = p.remote_port, "sent NewTunnel udp"
                ),
                "http" => tracing::info!(
                    name = %p.name, service = %p.service,
                    domains = ?p.domains, "sent NewTunnel http"
                ),
                "https" => tracing::info!(
                    name = %p.name, service = %p.service,
                    domains = ?p.domains, "sent NewTunnel https"
                ),
                _ => {}
            }
        }
        Ok(())
    }

    async fn reader_loop(self: Arc<Self>) -> Result<ReaderEnd> {
        loop {
            if self.cancel.is_cancelled() {
                return Ok(ReaderEnd::Closed);
            }

            let msg = tokio::select! {
                _ = self.cancel.cancelled() => {
                    return Ok(ReaderEnd::Closed);
                }
                msg = async {
                    let mut reader = self.reader.lock().await;
                    msg::read_msg(&mut *reader).await
                } => {
                    match msg {
                        Ok(m) => m,
                        Err(e) if is_unexpected_eof(&e) => {
                            tracing::debug!(
                                "control stream closed (unexpected EOF treated as clean disconnect)"
                            );
                            return Ok(ReaderEnd::Closed);
                        }
                        Err(_) => return Ok(ReaderEnd::Closed),
                    }
                }
            };

            match msg {
                Message::KickOut(k) => {
                    let safe_reason = sanitize_for_logging(&k.reason);
                    tracing::warn!(reason = %safe_reason, "kicked by server — will exit");
                    return Ok(ReaderEnd::Kicked(k.reason));
                }
                Message::ReqDataConn(_) => {
                    // #13: ignore requests above pool_count + burst.
                    // A visitor flood must not turn into an unbounded
                    // flood of connection attempts to the server.
                    let cap =
                        (self.cfg.transport.pool_count.max(1) as usize) + DATA_CONN_BURST;
                    if self
                        .data_conns_in_flight
                        .fetch_add(1, Ordering::SeqCst)
                        >= cap
                    {
                        self.data_conns_in_flight
                            .fetch_sub(1, Ordering::SeqCst);
                        tracing::debug!(
                            cap,
                            "ignoring ReqDataConn: too many data connections in flight"
                        );
                        continue;
                    }
                    let ctl = Arc::clone(&self);
                    let cancel = self.cancel.clone();
                    self.data_tasks.lock().await.spawn(async move {
                        tokio::select! {
                            _ = cancel.cancelled() => {}
                            res = ctl.clone().handle_req_data_conn() => {
                                if let Err(e) = res {
                                    tracing::error!(error = %e, "data conn failed");
                                }
                            }
                        }
                        ctl.data_conns_in_flight
                            .fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Message::NewTunnelResp(resp) => {
                    if resp.error.is_empty() {
                        let remote = normalize_remote_addr(&self.cfg.server, &resp.remote_addr);
                        tracing::info!(
                            name = %resp.tunnel_name,
                            remote = %remote,
                            "tunnel started"
                        );
                        (self.on_tunnel_remote)(resp.tunnel_name.clone(), remote);
                    } else {
                        tracing::error!(
                            name = %resp.tunnel_name,
                            error = %resp.error,
                            "tunnel start failed"
                        );
                    }
                }
                Message::P2pInfo(info) => {
                    if let Err(e) = self.handle_p2p_info(info).await {
                        tracing::warn!(error = %e, "failed to handle P2pInfo; keep relay mode");
                    }
                }
                Message::P2pReady(ready) => {
                    let ctl = Arc::clone(&self);
                    let cancel = self.cancel.clone();
                    self.data_tasks.lock().await.spawn(async move {
                        run_p2p_task_with_cancel(
                            cancel,
                            ctl.handle_p2p_ready(ready),
                        )
                        .await;
                    });
                }
                Message::Pong(_) => {
                    self.last_pong_unix.store(now_secs(), Ordering::Relaxed);
                    tracing::trace!("pong");
                }
                other => {
                    tracing::warn!(ty = other.type_byte(), "ignored message");
                }
            }
        }
    }

    async fn heartbeat_loop(self: Arc<Self>) {
        let secs = self.effective_ping_interval();
        if secs <= 0 {
            tracing::debug!("app heartbeat disabled");
            std::future::pending::<()>().await;
            return;
        }
        let mut tick = interval(Duration::from_secs(secs as u64));
        tick.tick().await;
        loop {
            if self.cancel.is_cancelled() {
                break;
            }
            tick.tick().await;
            let timestamp = now_secs();
            let ping = Ping {
                auth_digest: auth::compute_auth_digest(&self.cfg.auth.token, timestamp),
                timestamp,
            };
            let mut writer = self.writer.lock().await;
            if msg::write_msg(&mut *writer, &Message::Ping(ping))
                .await
                .is_err()
            {
                break;
            }
        }
    }

    async fn heartbeat_timeout_loop(self: Arc<Self>) {
        let timeout = self.effective_pong_timeout();
        if timeout <= 0 {
            std::future::pending::<()>().await;
            return;
        }
        loop {
            if self.cancel.is_cancelled() {
                break;
            }
            sleep(Duration::from_secs(1)).await;
            let last = self.last_pong_unix.load(Ordering::Relaxed);
            let now = now_secs();
            if last > 0 && now.saturating_sub(last) > timeout {
                tracing::warn!(timeout_secs = timeout, "heartbeat timeout");
                self.cancel.cancel();
                break;
            }
        }
    }

    fn effective_ping_interval(&self) -> i64 {
        let hb = self.cfg.transport.heartbeat_interval;
        if hb > 0 {
            return hb;
        }
        if self.cfg.transport.tcp_mux {
            let mux_ka = self.cfg.transport.mux_keepalive_secs;
            if mux_ka > 0 {
                return mux_ka;
            }
        }
        -1
    }

    fn effective_pong_timeout(&self) -> i64 {
        let hb_to = self.cfg.transport.heartbeat_timeout;
        if hb_to > 0 {
            return hb_to;
        }
        if self.cfg.transport.heartbeat_interval <= 0 && self.cfg.transport.tcp_mux {
            let mux_ka = self.cfg.transport.mux_keepalive_secs;
            if mux_ka > 0 {
                return mux_ka.saturating_mul(3);
            }
        }
        -1
    }

    async fn handle_req_data_conn(self: Arc<Self>) -> Result<()> {
        let mut data = self.connector.open().await?;

        let timestamp = now_secs();
        // #11: prove this data connection belongs to this session. The
        // auth_digest is kept as a transition field; the proof is what
        // the server verifies.
        let proof = if self.session_secret.is_empty() {
            String::new()
        } else {
            auth::compute_session_proof(
                &self.session_secret,
                "data-conn",
                &self.session_id,
                timestamp,
            )
        };
        msg::write_msg(
            &mut data,
            &Message::NewDataConn(NewDataConn {
                session_id: self.session_id.clone(),
                auth_digest: auth::compute_auth_digest(&self.cfg.auth.token, timestamp),
                timestamp,
                proof,
            }),
        )
        .await?;

        let start = tokio::select! {
            _ = self.cancel.cancelled() => {
                return Ok(());
            }
            msg = msg::read_msg(&mut data) => {
                match msg? {
                    Message::StartDataConn(s) => s,
                    other => {
                        return Err(anyhow!("expected StartDataConn, got {}", other.type_byte()))
                    }
                }
            }
        };

        if !start.error.is_empty() {
            return Err(anyhow!("StartDataConn error: {}", start.error));
        }

        self.tunnels.handle_data_conn(&start, data).await
    }

    async fn handle_p2p_info(&self, info: P2pInfo) -> Result<()> {
        if !info.error.is_empty() {
            return Err(anyhow!("broker rejected P2P request: {}", info.error));
        }

        let local_candidates = self.collect_local_p2p_candidates().await;
        let candidates = join_candidates(&local_candidates);

        tracing::info!(
            token = %info.token,
            peer_addr = %info.peer_addr,
            candidates = %candidates,
            "received P2pInfo; reporting local candidates"
        );

        let msg = Message::P2pAddr(P2pAddr {
            token: info.token,
            candidates,
        });
        let mut writer = self.writer.lock().await;
        msg::write_msg(&mut *writer, &msg).await?;
        Ok(())
    }

    /// Handle a `P2pReady` message: attempt hole-punching and, on success,
    /// wire the resulting stream to the appropriate local backend.
    ///
    /// # Error / fallback policy
    ///
    /// | Situation | Action |
    /// |-----------|--------|
    /// | `P2pReady.tunnel_name` is empty (old server) | `return Ok(())` with warn |
    /// | `tunnel_name` not in client config | `return Err(...)` → warn |
    /// | tunnel has no `service` address | `return Err(...)` → warn |
    /// | TCP backend dial fails | `run_p2p_tcp_session` returns `Err` → warn |
    /// | UDP KCP init / backend connect fails | `run_p2p_udp_session` returns `Err` → warn |
    /// | hole-punch timed out / failed | `return Ok(())` with info |
    async fn handle_p2p_ready(self: Arc<Self>, ready: P2pReady) -> Result<()> {
        let local_candidates = self.collect_local_p2p_candidates().await;
        let remote_candidates = self.select_remote_candidates(&ready);

        if remote_candidates.is_empty() {
            tracing::warn!(
                token = %ready.token,
                "P2P ready received but remote candidate set is empty; keep relay mode"
            );
            return Ok(());
        }

        let timeout_secs = self.effective_p2p_timeout_secs();
        let cfg = HolePunchConfig {
            token: ready.token.clone(),
            local_candidates,
            remote_candidates: remote_candidates.clone(),
            timeout: Duration::from_secs(timeout_secs),
            enable_udp: self.cfg.p2p_enable_udp(),
            ..Default::default()
        };

        tracing::info!(
            token = %ready.token,
            tunnel = %ready.tunnel_name,
            remote_candidates = ?remote_candidates,
            timeout_secs,
            "received P2pReady; start hole punching"
        );

        match punch(cfg).await {
            // ── TCP: production data-plane ────────────────────────────────────
            HolePunchResult::Tcp(stream) => {
                let tunnel_name = ready.tunnel_name.clone();

                if tunnel_name.is_empty() {
                    tracing::warn!(
                        token = %ready.token,
                        "P2P TCP punch succeeded but P2pReady.tunnel_name is empty \
                         (old server?); keeping relay mode"
                    );
                    return Ok(());
                }

                let local_addr = self
                    .cfg
                    .tunnels
                    .iter()
                    .find(|t| t.name == tunnel_name)
                    .map(|t| t.service.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        anyhow!(
                            "P2P TCP: tunnel '{}' not found in client config \
                             or has no service address; keeping relay mode",
                            tunnel_name
                        )
                    })?;

                tracing::info!(
                    token = %ready.token,
                    tunnel = %tunnel_name,
                    %local_addr,
                    "P2P TCP hole punch succeeded; attaching to local backend"
                );

                run_p2p_tcp_session(stream, &local_addr, &tunnel_name).await
            }

            // ── UDP: production data-plane (KCP reliable layer) ───────────────
            HolePunchResult::Udp(sock) => {
                let tunnel_name = ready.tunnel_name.clone();

                // ① Empty tunnel_name — old server did not propagate it.
                if tunnel_name.is_empty() {
                    tracing::warn!(
                        token = %ready.token,
                        "P2P UDP punch succeeded but P2pReady.tunnel_name is empty \
                         (old server?); keeping relay mode"
                    );
                    return Ok(());
                }

                // ② Look up local UDP backend address from config.
                let local_addr: SocketAddr = self
                    .cfg
                    .tunnels
                    .iter()
                    .find(|t| t.name == tunnel_name)
                    .map(|t| t.service.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        anyhow!(
                            "P2P UDP: tunnel '{}' not found in client config \
                             or has no service address; keeping relay mode",
                            tunnel_name
                        )
                    })
                    .and_then(|s| {
                        s.parse().map_err(|e| {
                            anyhow!(
                                "P2P UDP: invalid service address '{}' for tunnel '{}': {}",
                                s, tunnel_name, e
                            )
                        })
                    })?;

                tracing::info!(
                    token = %ready.token,
                    tunnel = %tunnel_name,
                    %local_addr,
                    "P2P UDP hole punch succeeded; attaching to local backend via KCP"
                );

                // ③ Establish KCP session and splice streams.
                run_p2p_udp_session(sock, local_addr, &tunnel_name).await
            }

            // ── Hole-punch timed out / all candidates failed ──────────────────
            HolePunchResult::Failed => {
                tracing::info!(
                    token        = %ready.token,
                    tunnel       = %ready.tunnel_name,
                    timeout_secs,
                    "P2P hole punch timed out or all candidates failed; keeping relay mode"
                );
                Ok(())
            }
        }
    }

    // ── P2P helpers ───────────────────────────────────────────────────────────

    async fn collect_local_p2p_candidates(&self) -> Vec<SocketAddr> {
        let stun_servers = self.cfg.p2p_stun_servers();
        if stun_servers.is_empty() {
            tracing::debug!("no STUN servers configured; using local-only P2P candidates");
        }
        let opts = StunQueryOptions {
            servers: stun_servers,
            timeout: Duration::from_secs(self.effective_p2p_timeout_secs()),
        };
        query_public_addrs(opts).await
    }

    fn select_remote_candidates(&self, ready: &P2pReady) -> Vec<SocketAddr> {
        let raw = if self.is_p2p_initiator(ready) {
            &ready.responder_candidates
        } else {
            &ready.initiator_candidates
        };
        parse_candidates(raw)
    }

    fn is_p2p_initiator(&self, ready: &P2pReady) -> bool {
        self.session_id < ready.initiator_observed_addr
    }

    fn effective_p2p_timeout_secs(&self) -> u64 {
        let t = self.cfg.p2p_timeout_secs();
        if t > 0 { t as u64 } else { 10 }
    }
}

// ── Free helpers ────────────────────────────────────────────────────────────────

enum ReaderEnd {
    Closed,
    Kicked(String),
}

/// Await a `handle_p2p_ready` future and, on failure, emit a warning that
/// names the fallback / relay semantics.  This is a **pure extraction** of the
/// inline `if let Err(e) = res { tracing::warn!(...) }` block that used to
/// live inside `reader_loop`; control-flow semantics are identical.
async fn consume_p2p_ready_result_with_fallback_log<F>(fut: F)
where
    F: std::future::Future<Output = Result<()>>,
{
    if let Err(e) = fut.await {
        tracing::warn!(
            error = %e,
            "P2P punch failed or backend unavailable; keeping relay mode"
        );
    }
}

/// Exact behaviour-equivalent extraction of the `select!` block that wraps
/// each P2pReady task in `reader_loop`.
///
/// Two branches race:
/// - `cancel.cancelled()` → logs a debug message and returns immediately
///   (no fallback warning — cancellation is a clean shutdown, not a failure).
/// - `consume_p2p_ready_result_with_fallback_log(p2p_fut)` → runs the
///   P2P future to completion and emits a warning only if it returns `Err`.
///
/// Extracting this into a named function achieves two goals:
/// 1. Tests can call it directly with controlled inputs (a pending future
///    and a hot cancel token) without going through the full `Control` state
///    machine.
/// 2. The production call site (`reader_loop`) remains a single,
///    readable line that makes the intent explicit.
///
/// # Cancel-wrapper contract
///
/// This function is the **single canonical cancel-wrapper** for all P2P
/// branches.  Any new branch added to `handle_p2p_ready` MUST route through
/// this function.
///
/// Tests:
/// - `p2p_task_cancel_preempts_long_running_future` (UDP branch)
/// - `p2p_tcp_task_cancel_preempts_in_flight_session` (TCP branch)
async fn run_p2p_task_with_cancel<F>(cancel: CancellationToken, p2p_fut: F)
where
    F: std::future::Future<Output = Result<()>>,
{
    tokio::select! {
        _ = cancel.cancelled() => {
            tracing::debug!("P2P task cancelled by session shutdown");
        }
        _ = consume_p2p_ready_result_with_fallback_log(p2p_fut) => {}
    }
}

fn is_unexpected_eof(e: &MessageReadError) -> bool {
    match e {
        MessageReadError::Io(io_err) => io_err.kind() == std::io::ErrorKind::UnexpectedEof,
        _ => false,
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".into())
}

fn normalize_remote_addr(server: &str, remote_addr: &str) -> String {
    if remote_addr.starts_with(':') {
        format!("{}{}", server.split(':').next().unwrap_or(server), remote_addr)
    } else {
        remote_addr.to_owned()
    }
}

#[allow(clippy::too_many_arguments)]
fn new_tunnel_base(
    name: &str,
    protocol: &str,
    remote_port: i32,
    local_ip: &str,
    local_port: u16,
    transport: &orbien_core::config::TunnelTransportConfig,
    max_connections: usize,
    extra: impl FnOnce(&mut NewTunnel),
) -> NewTunnel {
    let mut nt = NewTunnel {
        tunnel_name: name.to_owned(),
        protocol: protocol.to_owned(),
        remote_port,
        local_ip: local_ip.to_owned(),
        local_port: local_port as i32,
        bandwidth: transport.bandwidth,
        bandwidth_limit_side: transport.bandwidth_limit_side.clone(),
        max_connections,
        ..Default::default()
    };
    extra(&mut nt);
    nt
}

fn join_candidates(addrs: &[SocketAddr]) -> String {
    addrs
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tokio::sync::oneshot;
    use tokio::time::{timeout, Duration};
    use tracing_subscriber::fmt::MakeWriter;

    // ── Minimal in-memory log collector ──────────────────────────────────────

    #[derive(Clone, Default)]
    struct SharedLogBuf(Arc<Mutex<Vec<u8>>>);

    impl SharedLogBuf {
        fn as_string(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap_or_default()
        }
    }

    struct SharedLogWriter(SharedLogBuf);

    impl io::Write for SharedLogWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0 .0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedLogBuf {
        type Writer = SharedLogWriter;
        fn make_writer(&'a self) -> Self::Writer {
            SharedLogWriter(self.clone())
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// Verifies that `run_p2p_task_with_cancel` (and therefore the P2pReady
    /// branch in `reader_loop`) correctly consumes an `Err` result and emits
    /// a fallback-relay warning log, while allowing control flow to continue.
    ///
    /// **Primary assertion (state):** the oneshot signal is sent after the
    /// helper returns, proving the task neither panicked nor hung.
    ///
    /// **Secondary assertion (log):** the warning containing relay-fallback
    /// semantics is present.
    #[tokio::test(flavor = "current_thread")]
    async fn udp_p2p_failure_fallback_consumes_err_and_keeps_control_flow_alive() {
        let logs = SharedLogBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_level(true)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let (continued_tx, continued_rx) = oneshot::channel::<()>();

        let task = tokio::spawn(async move {
            // cancel token that is never triggered — the P2P future runs to
            // completion (immediately returning Err) and the fallback branch fires.
            let cancel = CancellationToken::new();
            run_p2p_task_with_cancel(
                cancel,
                async {
                    Err(anyhow!(
                        "P2P UDP: KCP connect failed for tunnel 'demo': connect timeout"
                    ))
                },
            )
            .await;
            let _ = continued_tx.send(());
        });

        timeout(Duration::from_secs(1), task)
            .await
            .expect("fallback task hung")
            .expect("fallback task panicked");

        // ── Primary: control flow continued ────────────────────────────────
        timeout(Duration::from_secs(1), continued_rx)
            .await
            .expect("control flow did not continue after fallback")
            .expect("signal missing");

        // ── Secondary: fallback warning was logged ────────────────────────
        let rendered = logs.as_string();
        assert!(
            rendered.contains("keeping relay mode")
                || rendered.contains("backend unavailable")
                || rendered.contains("P2P punch failed"),
            "fallback warning log missing; got: {rendered}"
        );
    }

    /// Verifies the **cancel-preempts-P2P** invariant of `run_p2p_task_with_cancel`:
    ///
    /// Core invariants under test:
    /// 1. When `cancel` is triggered while the P2P future is still in-flight
    ///    (simulated with `std::future::pending()`), `select!` picks the cancel
    ///    branch and the task exits promptly — the pending future is never resolved.
    /// 2. The cancel path emits NO fallback-relay warning.  Cancellation is a
    ///    clean, intentional shutdown — the relay was never needed because the
    ///    session itself is going away.  Emitting a warning would be misleading.
    /// 3. The task completes within a tight wall-clock budget (1 s), which is
    ///    trivially satisfied once the cancel branch fires.
    ///
    /// Why `pending()` is the right mock here:
    ///    `std::future::pending::<Result<()>>()` is unconditionally unresolvable
    ///    and carries no dependency on the timer subsystem.  It is semantically
    ///    equivalent to "hole-punch still in progress, with no scheduled
    ///    completion time" — which is exactly the scenario under test.
    ///    Unlike `sleep(N)`, there is no finite N that could race with CI
    ///    scheduling jitter.
    ///
    /// Why this is not a false positive:
    ///    If the cancel branch were NOT taken, `pending()` would block forever
    ///    and the outer `timeout(1s, ...)` would expire, failing the test with
    ///    an unambiguous timeout panic.
    #[tokio::test(flavor = "current_thread")]
    async fn p2p_task_cancel_preempts_long_running_future() {
        let logs = SharedLogBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_level(true)
            .finish();
        // set_default: thread-local, no closure needed, .await valid here.
        let _guard = tracing::subscriber::set_default(subscriber);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // ── Step 1: spawn the task with a permanently pending P2P future ─────
        //
        // `std::future::pending::<Result<()>>()` never resolves, accurately
        // modelling a hole-punch that is still in flight with no timeout of
        // its own.  The cancel branch is the only exit path.
        let task = tokio::spawn(async move {
            run_p2p_task_with_cancel(
                cancel_clone,
                // Simulate: hole-punch in progress, no completion scheduled.
                // Output type Result<()> matches the generic bound directly.
                std::future::pending::<Result<()>>(),
            )
            .await;
        });

        // ── Step 2: trigger cancellation from the test body ──────────────────
        //
        // Yield once so the spawned task gets a chance to start polling and
        // reach the select! await point before cancel() is called.
        tokio::task::yield_now().await;
        cancel.cancel();

        // ── Step 3: primary assertion — task exits within 1 s ────────────────
        //
        // If the cancel branch were NOT taken, `pending()` would block forever
        // and this timeout would fire, failing the test unambiguously.
        timeout(Duration::from_secs(1), task)
            .await
            .expect(
                "P2P task did not exit after cancel — \
                 cancel branch in select! may be missing or unreachable",
            )
            .expect("P2P task panicked unexpectedly");

        // ── Step 4: secondary assertion — no fallback warning logged ─────────
        //
        // The cancel path must NOT emit a relay-fallback warning.  That warning
        // means "P2P failed, staying on relay"; a clean cancellation is neither
        // a failure nor a reason to stay on relay — the whole session is
        // shutting down.  A spurious warning here would confuse operators.
        let rendered = logs.as_string();
        assert!(
            !rendered.contains("keeping relay mode")
                && !rendered.contains("backend unavailable")
                && !rendered.contains("P2P punch failed"),
            "cancel path must not emit fallback-relay warning; got: {rendered}"
        );
    }

    /// Verifies the **TCP cancel-preempts-session** invariant of
    /// `run_p2p_task_with_cancel` for the TCP branch of `handle_p2p_ready`.
    ///
    /// # Core invariant
    ///
    /// When a TCP P2P session is in flight (simulated here as a permanently
    /// pending future that models an active `run_p2p_tcp_session` call) and
    /// `CancellationToken::cancel()` is triggered, `run_p2p_task_with_cancel`
    /// MUST:
    ///   1. Exit promptly — the cancel branch in `select!` fires before the
    ///      TCP session future resolves.
    ///   2. Emit NO fallback-relay warning.  Cancellation is a clean,
    ///      intentional shutdown; it does not mean "P2P failed, stay on relay".
    ///
    /// # Symmetry with UDP cancel test
    ///
    /// The existing `p2p_task_cancel_preempts_long_running_future` test passes
    /// a `pending::<Result<()>>()` future representing a still-in-flight UDP
    /// hole-punch.  This test passes the same mock future to represent a
    /// still-in-flight TCP session.  Both exercise the same
    /// `run_p2p_task_with_cancel` wrapper, documenting that TCP and UDP share
    /// identical control-plane cancellation semantics.
    ///
    /// # Why `pending()` is correct here
    ///
    /// A live `run_p2p_tcp_session` call requires a real TCP stream and a real
    /// backend — introducing those would make this a data-plane integration
    /// test, not a control-flow test.  `pending::<Result<()>>()` faithfully
    /// models "the TCP session is running and has not yet returned" without
    /// any networking dependency, timer jitter, or test infrastructure.  If
    /// the cancel branch were absent or broken, `pending()` would block forever
    /// and the outer timeout would fire, failing the test unambiguously.
    ///
    /// # Why this is not a false positive
    ///
    /// The `timeout(1s, task)` wrapper is the falsifiability gate: if the
    /// cancel branch is never taken the test panics with a clear timeout
    /// message.  The no-fallback-warning assertion catches the orthogonal
    /// defect of a cancel path that incorrectly emits failure telemetry.
    #[tokio::test(flavor = "current_thread")]
    async fn p2p_tcp_task_cancel_preempts_in_flight_session() {
        let logs = SharedLogBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_level(true)
            .finish();
        // set_default is thread-local and does not require a closure, so
        // .await remains valid inside the test body.
        let _guard = tracing::subscriber::set_default(subscriber);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // ── Step 1: spawn the task with a permanently pending TCP session ─────
        //
        // `std::future::pending::<Result<()>>()` models an active TCP P2P
        // session that has not yet returned — equivalent to what
        // `run_p2p_tcp_session(stream, backend_addr, tunnel_name)` looks like
        // from `run_p2p_task_with_cancel`'s perspective while the session is
        // relaying data.  The cancel branch is the only exit path.
        let task = tokio::spawn(async move {
            run_p2p_task_with_cancel(
                cancel_clone,
                // Simulates: TCP P2P session actively relaying data, no
                // completion scheduled.  The output type matches the generic
                // bound `Future<Output = Result<()>>` exactly.
                std::future::pending::<Result<()>>(),
            )
            .await;
        });

        // ── Step 2: yield, then trigger cancellation ──────────────────────────
        //
        // One yield gives the spawned task a chance to reach the `select!`
        // await point before cancel() is called.  This is necessary on
        // `current_thread` where cooperative scheduling is explicit.
        tokio::task::yield_now().await;
        cancel.cancel();

        // ── Step 3: primary assertion — task exits within 1 s ────────────────
        //
        // If cancel preemption is broken, `pending()` blocks forever and this
        // timeout expires, failing with an unambiguous message.
        timeout(Duration::from_secs(1), task)
            .await
            .expect(
                "TCP P2P task did not exit after cancel — \
                 cancel branch in select! may be missing or unreachable for TCP path",
            )
            .expect("TCP P2P task panicked unexpectedly");

        // ── Step 4: secondary assertion — no fallback-relay warning ───────────
        //
        // A clean cancellation must not be reported as a P2P failure.
        // Presence of these strings would mean the cancel path incorrectly
        // routes through the error-fallback log path.
        let rendered = logs.as_string();
        assert!(
            !rendered.contains("keeping relay mode")
                && !rendered.contains("backend unavailable")
                && !rendered.contains("P2P punch failed"),
            "TCP cancel path must not emit fallback-relay warning; got: {rendered}"
        );
    }
}
