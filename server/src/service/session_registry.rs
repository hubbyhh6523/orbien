use super::{pre_login::PreLoginSlot, OfflineClientRecord, Service};
use crate::control::{validate, Control, P2pHandler};
use crate::metrics::ServerMetrics;
use crate::sanitize::sanitize_for_logging;
use anyhow::{anyhow, Result};
use orbien_core::auth;
use orbien_core::msg::{self, Login, LoginResp, Message, NewDataConn};
use orbien_core::transport::DynStream;
use orbien_core::VERSION;
use rand::RngExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use uuid::Uuid;

/// 32 random bytes, hex-encoded: the per-session secret (#11) that resume
/// and data-connection proofs are HMACed with.
fn new_session_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Service {
    pub(crate) async fn register_control(
        self: Arc<Self>,
        stream: DynStream,
        login: Login,
        peer: SocketAddr,
        pre_login: PreLoginSlot,
        challenge_nonce: &str,
    ) -> Result<()> {
        // #12: the Login must answer the challenge this connection was
        // issued. The response binds the nonce, session id, user,
        // hostname, pool count, version and capabilities to the token,
        // so a captured Login cannot be replayed on another connection
        // and tampering with any field invalidates it. No fallback: a
        // Login without a valid response is rejected (hard cut for old
        // clients, which send Login immediately without waiting for the
        // Challenge). The timestamp-only digest is gone.
        let policy_tokens: Vec<&str> = self
            .cfg
            .auth
            .token_policies
            .iter()
            .map(|p| p.token.as_str())
            .collect();
        let Some((token_id, matched_token)) = auth::match_login_response(
            &self.cfg.auth.token,
            &policy_tokens,
            &login.challenge_response,
            challenge_nonce,
            &login.session_id,
            &login.user,
            &login.hostname,
            login.pool_count,
            &login.version,
            &login.capabilities,
        ) else {
            let mut stream = stream;
            let _ = msg::write_msg(
                &mut stream,
                &Message::LoginResp(LoginResp {
                    version: VERSION.into(),
                    session_id: String::new(),
                    error: "challenge authentication failed".into(),
                    resume_token: String::new(),
                    server_proof: String::new(),
                }),
            )
            .await;
            return Err(anyhow!("challenge authentication failed"));
        };

        // #11: reject Login strings outside the allowed length or
        // character set before anything is logged or stored from them.
        if let Err(e) = validate::validate_login(&login) {
            let mut stream = stream;
            let _ = msg::write_msg(
                &mut stream,
                &Message::LoginResp(LoginResp {
                    version: VERSION.into(),
                    session_id: String::new(),
                    error: e.clone(),
                    resume_token: String::new(),
                    server_proof: String::new(),
                }),
            )
            .await;
            return Err(anyhow!("{e}"));
        }

        // #11: session identity. A login that claims a live session id
        // must prove possession of that session's secret; without valid
        // proof the old session is left alone and the caller gets a new
        // id (even from the same address). An unknown id — e.g. after a
        // server restart, when the secret is gone — also gets a new id.
        // A fresh secret is issued on every login.
        let requested = login.session_id.clone();
        let session_id = if requested.is_empty() {
            short_session_id()
        } else {
            match self.control_by_session(&requested).await {
                Some(old)
                    if !login.resume_proof.is_empty()
                        && auth::verify_session_proof(
                            old.session_secret(),
                            "resume",
                            &requested,
                            &login.resume_proof,
                            login.timestamp,
                        ) =>
                {
                    requested
                }
                Some(_) => {
                    tracing::warn!(
                        token_id = %token_id.get(..16).unwrap_or(&token_id),
                        session_id = %requested,
                        %peer,
                        "login claimed a live session id without valid resume proof; issuing a new id"
                    );
                    short_session_id()
                }
                None => short_session_id(),
            }
        };
        let session_secret = new_session_secret();

        // #12: prove the server knows the token before the client acts
        // on anything: HMAC over the client's nonce and the session id
        // just assigned. The client verifies it right after LoginResp.
        let server_proof =
            auth::compute_server_proof(matched_token, &login.client_nonce, &session_id);

        let mut stream = stream;
        msg::write_msg(
            &mut stream,
            &Message::LoginResp(LoginResp {
                version: VERSION.into(),
                session_id: session_id.clone(),
                error: String::new(),
                resume_token: session_secret.clone(),
                server_proof,
            }),
        )
        .await?;

        tracing::info!(
            %session_id,
            %peer,
            pool = login.pool_count,
            token_id = %token_id.get(..16).unwrap_or(&token_id),
            "client logged in"
        );

        let max_pool = self.cfg.transport.max_conn_pool.max(0) as usize;
        let pool_count = (login.pool_count.max(0) as usize).min(max_pool);

        let client_ip = peer.to_string();

        let mut control = Control::new(
            session_id.clone(),
            stream,
            self.cfg.clone(),
            pool_count,
            self.http_gw.clone(),
            self.https_gw.clone(),
            Arc::clone(&self.access),
            login.user.clone(),
            login.hostname.clone(),
            login.os.clone(),
            login.arch.clone(),
            login.version.clone(),
            client_ip,
            Arc::clone(&self.metrics),
            token_id,
            session_secret,
        );

        // Wire up the P2P broker dispatch hook so the control loop can forward
        // P2pReq / P2pAddr messages to the Service without a circular Arc.
        let svc_weak = Arc::downgrade(&self);
        let p2p_hook: P2pHandler = Arc::new(move |msg, sid, peer_addr| {
            let svc_weak = svc_weak.clone();
            Box::pin(async move {
                let svc = svc_weak
                    .upgrade()
                    .ok_or_else(|| anyhow!("service dropped"))?;
                match msg {
                    Message::P2pReq(req) => {
                        // Look up initiator control by session_id so we can
                        // pass it to the broker.
                        let initiator = svc
                            .control_by_session(&sid)
                            .await
                            .ok_or_else(|| anyhow!("P2pReq: initiator session not found: {sid}"))?;
                        svc.handle_p2p_req(req, initiator, peer_addr).await
                    }
                    Message::P2pAddr(addr) => svc.handle_p2p_addr(addr, &sid).await,
                    _ => Err(anyhow!("unexpected message type in p2p_hook")),
                }
            })
        });
        control.set_p2p_handler(p2p_hook);

        let control = Arc::new(control);

        {
            let mut offline = self.offline_clients.lock().await;
            offline.remove(&session_id);
        }

        let old = {
            let mut map = self.controls.lock().await;
            map.insert(session_id.clone(), Arc::clone(&control))
        };

        if let Some(old) = old {
            old.shutdown().await;
        }

        self.metrics.new_client(&session_id);

        // #13: logged in — release the pre-login slot. The session no
        // longer counts against the unauthenticated caps, and the
        // pre-login deadline watchdog (yamux select / QUIC task) sees the
        // empty slot and stands down.
        pre_login.lock().await.take();

        let controls = Arc::clone(&self.controls);
        let metrics = Arc::clone(&self.metrics);
        let rid = session_id.clone();
        let result = Arc::clone(&control).run().await;
        control.shutdown().await;
        metrics.close_client();

        let tunnel_count = control.tunnel_count().await;
        let mut map = controls.lock().await;
        if map
            .get(&rid)
            .map(|c| Arc::ptr_eq(c, &control))
            .unwrap_or(false)
        {
            map.remove(&rid);
        }
        if !map.contains_key(&rid) {
            drop(map);
            self.record_offline(OfflineClientRecord {
                session_id: rid,
                user: control.user.clone(),
                hostname: control.hostname.clone(),
                os: control.os.clone(),
                arch: control.arch.clone(),
                client_ip: control.client_ip.clone(),
                version: control.version.clone(),
                tunnel_count,
                disconnected_at: SystemTime::now(),
            })
            .await;
        }

        result
    }

    pub(crate) async fn register_data_conn(
        self: Arc<Self>,
        stream: DynStream,
        nw: NewDataConn,
        pre_login: PreLoginSlot,
        challenge_nonce: &str,
    ) -> Result<()> {
        if nw.session_id.trim().is_empty() {
            return Err(anyhow!("empty session_id for data conn"));
        }
        let control = {
            let map = self.controls.lock().await;
            map.get(&nw.session_id).cloned()
        };
        let Some(control) = control else {
            return Err(anyhow!(
                "unknown session_id for data conn: {}",
                nw.session_id
            ));
        };
        // #11, hard cut: a data connection must prove possession of the
        // session secret (purpose "data-conn"). No legacy fallback — a
        // stream that fails the proof is closed here and never queued,
        // so it can neither read visitor traffic nor fill the pool.
        // #12: the proof is bound to this stream's fresh Challenge
        // nonce, not a client-chosen timestamp — no replay window.
        if nw.proof.is_empty()
            || !auth::verify_session_proof_nonce(
                control.session_secret(),
                "data-conn",
                &nw.session_id,
                &nw.proof,
                challenge_nonce,
            )
        {
            let token_id = control.token_id();
            tracing::warn!(
                token_id = %token_id.get(..16).unwrap_or(token_id),
                session_id = %sanitize_for_logging(&nw.session_id),
                "data conn proof rejected"
            );
            return Err(anyhow!(
                "data conn proof failed for session_id={}",
                nw.session_id
            ));
        }
        // #11: a full pool refuses the stream instead of queueing it, so
        // a flood of forged connections cannot block the real client's
        // data connections. The rejected stream is dropped (closed) here.
        if !control.push_data_conn(stream).await {
            let token_id = control.token_id();
            tracing::warn!(
                token_id = %token_id.get(..16).unwrap_or(token_id),
                session_id = %sanitize_for_logging(&nw.session_id),
                "data conn pool full; closing stream"
            );
            return Err(anyhow!(
                "data conn pool full for session_id={}",
                nw.session_id
            ));
        }
        // #13: proven data connection — release the pre-login slot.
        pre_login.lock().await.take();
        Ok(())
    }
}

fn short_session_id() -> String {
    let hex = Uuid::new_v4().simple().to_string();
    hex[..16].to_owned()
}
