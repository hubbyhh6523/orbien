use super::pre_login::{new_slot, PreLoginPermit, PreLoginSlot};
use super::Service;
use crate::accept::AcceptBackoff;
use anyhow::{anyhow, Result};
use orbien_core::auth;
use orbien_core::msg::{self, Message};
use orbien_core::transport::{self, boxed_stream, DynStream};
use orbien_core::VERSION;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

impl Service {
    pub(super) async fn run_tcp(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        // #13: an accept error (e.g. EMFILE) backs off and retries
        // instead of ending the server.
        let mut backoff = AcceptBackoff::new();
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(accepted) => {
                    backoff.reset();
                    accepted
                }
                Err(e) => {
                    backoff.on_error(&e.into()).await;
                    continue;
                }
            };
            let Some(permit) = self.pre_login.try_acquire(peer.ip()) else {
                // #13: over the pre-login cap — close at once, no task.
                self.metrics.inc_limit_reject("pre_login_cap");
                tracing::debug!(%peer, "pre-login cap reached; closing connection");
                drop(stream);
                continue;
            };
            let svc = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = svc.handle_tcp_or_websocket(stream, peer, permit).await {
                    tracing::warn!(%peer, error = %e, "tcp/ws connection closed with error");
                }
            });
        }
    }

    async fn handle_tcp_or_websocket(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        permit: PreLoginPermit,
    ) -> Result<()> {
        // #13: one deadline from accept to login covers the peek, the
        // WebSocket upgrade and the TLS handshake. A peer that connects
        // and sends nothing, or a byte at a time, is cut off here.
        let deadline = self.cfg.limits.pre_login_timeout();
        let physical = timeout(deadline, async {
            let mut peek_buf = [0u8; 16];
            let n = stream.peek(&mut peek_buf).await.unwrap_or(0);
            let physical = if transport::is_websocket_http_request(&peek_buf[..n]) {
                tracing::debug!(%peer, transport = "websocket", "upgrade");
                transport::accept_websocket(stream).await?
            } else {
                tracing::debug!(%peer, transport = "tcp", "incoming connection");
                boxed_stream(stream)
            };
            transport::check_and_enable_tls(
                physical,
                Arc::clone(&self.tls_config),
                self.cfg.transport.tls.force,
            )
            .await
        })
        .await
        .map_err(|_| {
            self.metrics.inc_limit_reject("pre_login_timeout");
            anyhow!("pre-login deadline exceeded")
        })??;
        self.handle_physical(physical, peer, permit).await
    }

    async fn handle_physical(
        self: Arc<Self>,
        physical: DynStream,
        peer: SocketAddr,
        permit: PreLoginPermit,
    ) -> Result<()> {
        if self.cfg.transport.tcp_mux {
            tracing::debug!(%peer, "yamux server session started");
            let slot = new_slot(permit);
            let svc = Arc::clone(&self);
            let slot_cb = Arc::clone(&slot);
            let session = transport::serve_yamux_session(
                physical,
                transport::MAX_NUM_STREAMS,
                move |stream| {
                    let svc = Arc::clone(&svc);
                    let slot = Arc::clone(&slot_cb);
                    tokio::spawn(async move {
                        if let Err(e) = svc.handle_connection(stream, peer, slot).await {
                            tracing::debug!(error = %e, "yamux stream closed with error");
                        }
                    });
                },
            );
            tokio::pin!(session);
            // #13: a yamux session that never logs in is cut off at the
            // deadline; once any stream has logged in (slot taken) the
            // session lives as long as the client does.
            let deadline = self.cfg.limits.pre_login_timeout();
            let slot_w = Arc::clone(&slot);
            tokio::select! {
                _ = sleep(deadline) => {
                    if slot_w.lock().await.is_some() {
                        self.metrics.inc_limit_reject("pre_login_timeout");
                        return Err(anyhow!("pre-login deadline exceeded"));
                    }
                    session.await.map_err(|e| yamux_err(e, peer))
                }
                r = &mut session => r.map_err(|e| yamux_err(e, peer)),
            }
        } else {
            self.handle_connection(physical, peer, new_slot(permit))
                .await
        }
    }

    pub(super) async fn run_kcp(
        self: Arc<Self>,
        mut listener: kcp_tokio::KcpListener,
    ) -> Result<()> {
        // #13: accept errors back off and retry instead of ending the server.
        let mut backoff = AcceptBackoff::new();
        loop {
            let (stream, peer) = match transport::accept_kcp(&mut listener).await {
                Ok(accepted) => {
                    backoff.reset();
                    accepted
                }
                Err(e) => {
                    backoff.on_error(&e).await;
                    continue;
                }
            };
            tracing::debug!(%peer, transport = "kcp", "incoming connection");
            let Some(permit) = self.pre_login.try_acquire(peer.ip()) else {
                self.metrics.inc_limit_reject("pre_login_cap");
                tracing::debug!(%peer, "pre-login cap reached; closing connection");
                drop(stream);
                continue;
            };
            let svc = Arc::clone(&self);
            tokio::spawn(async move {
                let deadline = svc.cfg.limits.pre_login_timeout();
                let result = async {
                    let stream = timeout(
                        deadline,
                        transport::check_and_enable_tls(
                            stream,
                            Arc::clone(&svc.tls_config),
                            svc.cfg.transport.tls.force,
                        ),
                    )
                    .await
                    .map_err(|_| {
                        svc.metrics.inc_limit_reject("pre_login_timeout");
                        anyhow!("pre-login deadline exceeded")
                    })??;
                    svc.handle_physical(stream, peer, permit).await
                }
                .await;
                if let Err(e) = result {
                    tracing::warn!(%peer, error = %e, "kcp connection closed with error");
                }
            });
        }
    }

    pub(super) async fn run_quic(self: Arc<Self>, endpoint: quinn::Endpoint) -> Result<()> {
        loop {
            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| anyhow!("quic endpoint closed"))?;
            // The peer address is only known after the handshake, so the
            // accept-time permit is keyed by the unspecified address and
            // re-keyed to the real peer in handle_quic_connection.
            let Some(permit) = self.pre_login.try_acquire(std::net::IpAddr::V4(
                std::net::Ipv4Addr::UNSPECIFIED,
            )) else {
                self.metrics.inc_limit_reject("pre_login_cap");
                tracing::debug!("pre-login cap reached; refusing quic handshake");
                continue;
            };
            let svc = Arc::clone(&self);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        let peer = conn.remote_address();
                        tracing::info!(%peer, "quic session accepted");
                        if let Err(e) = svc.handle_quic_connection(conn, permit).await {
                            tracing::debug!(%peer, error = %e, "quic session ended");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "quic accept failed"),
                }
            });
        }
    }

    async fn handle_quic_connection(
        self: Arc<Self>,
        conn: quinn::Connection,
        permit: PreLoginPermit,
    ) -> Result<()> {
        // #13: re-key the handshake permit to the real peer address, so
        // the per-IP cap counts real clients instead of one shared
        // unspecified bucket. The global count is unchanged by the swap
        // (one slot freed, one taken).
        let peer = conn.remote_address();
        let Some(real) = self.pre_login.try_acquire(peer.ip()) else {
            self.metrics.inc_limit_reject("pre_login_cap");
            conn.close(0u32.into(), b"pre-login cap reached");
            return Err(anyhow!("pre-login cap reached for {peer}"));
        };
        drop(permit);
        let slot = new_slot(real);
        // #13: a QUIC connection that never logs in is closed at the
        // deadline. The watchdog only fires while the slot is still
        // held; the first successful Login takes it and disarms it.
        let deadline = self.cfg.limits.pre_login_timeout();
        let watch_conn = conn.clone();
        let watch_slot = Arc::clone(&slot);
        let watch_metrics = Arc::clone(&self.metrics);
        tokio::spawn(async move {
            sleep(deadline).await;
            if watch_slot.lock().await.is_some() {
                watch_metrics.inc_limit_reject("pre_login_timeout");
                watch_conn.close(0u32.into(), b"pre-login deadline exceeded");
            }
        });
        loop {
            let (send, recv) = conn.accept_bi().await?;
            let stream = transport::quic_bi(send, recv);
            let svc = Arc::clone(&self);
            let peer = conn.remote_address();
            let slot = Arc::clone(&slot);
            tokio::spawn(async move {
                if let Err(e) = svc.handle_connection(stream, peer, slot).await {
                    tracing::debug!(%peer, error = %e, "quic stream closed with error");
                }
            });
        }
    }

    async fn handle_connection(
        self: Arc<Self>,
        mut stream: DynStream,
        peer: SocketAddr,
        pre_login: PreLoginSlot,
    ) -> Result<()> {
        // #12: the client announces the stream with an empty Hello and
        // the server answers with a fresh single-use Challenge; the
        // client answers that with its bound Login/NewDataConn. The
        // client must speak first: yamux 0.14 and quinn 0.11 open
        // outbound streams lazily — the peer only learns of a stream
        // when the opener writes to it — so a server-speaks-first
        // Challenge deadlocks (the client waits for a Challenge the
        // server never sends, because the server never sees the
        // stream). The whole dance shares one #13 pre-login deadline
        // from connection open, so a challenger cannot hold a slot
        // past it. The Challenge goes out on data streams too (their
        // #11 session-secret proof is bound to this nonce); the client
        // sends Hello there before NewDataConn. An old client sends
        // Login first instead of Hello and is rejected here (hard cut).
        let deadline = tokio::time::Instant::now() + self.cfg.limits.pre_login_timeout();
        let first = self.read_pre_login_msg(&mut stream, deadline).await?;
        if !matches!(first, Message::Hello(_)) {
            return Err(anyhow!(
                "unexpected first message: {:?} (expected Hello)",
                first.type_byte()
            ));
        }
        let challenge_nonce = auth::new_nonce();
        msg::write_msg(
            &mut stream,
            &Message::Challenge(msg::Challenge {
                nonce: challenge_nonce.clone(),
                version: VERSION.into(),
            }),
        )
        .await?;
        // #13: the second message has the same small size limit as the
        // first — a peer that declares a body and stalls is rejected
        // from the header alone (codec checks before allocating).
        let second = self.read_pre_login_msg(&mut stream, deadline).await?;
        match second {
            Message::Login(login) => {
                self.register_control(stream, login, peer, pre_login, &challenge_nonce)
                    .await
            }
            Message::NewDataConn(nw) => {
                self.register_data_conn(stream, nw, pre_login, &challenge_nonce)
                    .await
            }
            other => Err(anyhow!(
                "unexpected second message: {:?} (expected Login or NewDataConn)",
                other.type_byte()
            )),
        }
    }

    /// Read one pre-login message (Hello, then Login/NewDataConn)
    /// against the single #13 pre-login deadline shared by the whole
    /// challenge dance. Both reads draw down the same deadline, so a
    /// challenger cannot hold a slot past it.
    async fn read_pre_login_msg(
        &self,
        stream: &mut DynStream,
        deadline: tokio::time::Instant,
    ) -> Result<Message> {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match msg::read_msg_limited_timeout(
            stream,
            self.cfg.limits.first_message_max_bytes,
            remaining,
        )
        .await
        {
            Ok(m) => Ok(m),
            Err(msg::MessageReadError::Timeout(_)) => {
                self.metrics.inc_limit_reject("pre_login_timeout");
                Err(anyhow!("pre-login deadline exceeded"))
            }
            Err(msg::MessageReadError::TooLarge(_)) => {
                self.metrics.inc_limit_reject("first_message_too_large");
                Err(anyhow!("first message too large"))
            }
            Err(e) => Err(e.into()),
        }
    }
}

fn yamux_err(e: anyhow::Error, peer: SocketAddr) -> anyhow::Error {
    let msg = e.to_string();
    if msg.contains("unknown version: 65")
        || msg.contains("unknown version: 87")
        || msg.contains("unknown version: 72")
    {
        anyhow!(
            "yamux session {peer}: {e} — transport.tcpMux mismatch: server expects yamux \
             (tcpMux=true) but peer sent a raw control frame (Hello 'H'=72 / Login 'A'=65 / NewDataConn 'W'=87). \
             Set the same tcpMux on orbien and orbien-server, then restart both."
        )
    } else {
        anyhow!("yamux session {peer}: {e}")
    }
}
