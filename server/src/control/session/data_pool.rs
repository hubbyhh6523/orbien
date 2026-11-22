use super::Control;
use anyhow::{anyhow, Result};
use orbien_core::msg::{self, Message, ReqDataConn, StartDataConn};
use orbien_core::transport::DynStream;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// RAII guard for one visitor waiting on a data connection. Dropping it
/// (visitor served, refused, timed out, or the session ended) frees the
/// per-tunnel waiting slot.
struct WaitingGuard {
    ctl: Arc<Control>,
    tunnel: String,
}

impl Drop for WaitingGuard {
    fn drop(&mut self) {
        let mut waiting = self.ctl.waiting_visitors.lock().expect("waiting lock");
        if let Some(n) = waiting.get_mut(&self.tunnel) {
            *n -= 1;
            if *n == 0 {
                waiting.remove(&self.tunnel);
            }
        }
    }
}

impl Control {
    /// Queue a data connection. Returns false when the pool is full (or
    /// the session is gone); the caller then closes the stream instead of
    /// letting it wait — a full pool must never block the real client's
    /// data connections (#11). The pool holds at most `pool_count`
    /// streams, the number the server asked the client for. A queued
    /// stream resolves one outstanding `ReqDataConn` (#13).
    pub async fn push_data_conn(&self, stream: DynStream) -> bool {
        // Saturating: a stream can arrive without a matching claim
        // (stale client, test setup); never let the counter wrap.
        // Plain CAS loop, not `fetch_update`/`try_update`: the former
        // is deprecated, the latter is still unstable on the CI
        // toolchain (Rust 1.92, E0658).
        let mut cur = self.outstanding_data_conns.load(Ordering::SeqCst);
        loop {
            let next = cur.saturating_sub(1);
            match self.outstanding_data_conns.compare_exchange_weak(
                cur,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
        if self.data_tx.try_send((stream, Instant::now())).is_ok() {
            self.data_notify.notify_waiters();
            true
        } else {
            false
        }
    }

    async fn try_pop_data(&self) -> Option<DynStream> {
        let mut rx = self.data_rx.lock().await;
        // #13: drop pooled streams that sat idle longer than the TTL —
        // a middlebox may have closed them already, and handing a dead
        // stream to a visitor fails their connection.
        let ttl = self.cfg.limits.pool_idle_ttl();
        loop {
            let (stream, pushed_at) = rx.try_recv().ok()?;
            if pushed_at.elapsed() <= ttl {
                return Some(stream);
            }
        }
    }

    async fn spawn_refill(self: &Arc<Self>) {
        let ctl = Arc::clone(self);
        self.bg_tasks.lock().await.spawn(async move {
            if ctl.closed.load(Ordering::SeqCst) {
                return;
            }
            let _ = ctl.request_data_conn().await;
        });
    }

    pub async fn get_data_conn(self: &Arc<Self>, tunnel_name: &str) -> Result<DynStream> {
        if let Some(conn) = self.try_pop_data().await {
            self.spawn_refill().await;
            return Ok(conn);
        }

        // #13: at most `maxWaitingVisitorsPerTunnel` visitors may wait
        // for a data connection per tunnel; the rest are refused at
        // once instead of queueing up to 10 s each.
        // The guard's only job is its Drop impl (decrement on exit),
        // so it is deliberately never read.
        let _guard = {
            let mut waiting = self.waiting_visitors.lock().expect("waiting lock");
            let n = waiting.get(tunnel_name).copied().unwrap_or(0);
            if n >= self.cfg.limits.max_waiting_visitors_per_tunnel {
                self.metrics.inc_limit_reject("waiting_visitors");
                tracing::debug!(
                    tunnel = %tunnel_name,
                    waiting = n,
                    "waiting visitors at cap; refusing visitor"
                );
                return Err(anyhow!(
                    "too many visitors waiting for tunnel {tunnel_name}"
                ));
            }
            waiting.insert(tunnel_name.to_string(), n + 1);
            WaitingGuard {
                ctl: Arc::clone(self),
                tunnel: tunnel_name.to_string(),
            }
        };

        self.request_data_conn().await?;

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(anyhow!("control closed while waiting for data conn"));
            }
            if let Some(conn) = self.try_pop_data().await {
                self.spawn_refill().await;
                return Ok(conn);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("timeout waiting for data conn"));
            }
            tokio::select! {
                _ = self.data_notify.notified() => {}
                _ = sleep(remaining.min(Duration::from_millis(100))) => {}
            }
        }
    }

    /// Ask the client for one more data connection, unless that many
    /// are already outstanding (#13): at most `pool_count + burst`
    /// `ReqDataConn` may be unanswered per session. A request that is
    /// already in flight will fill the pool; sending another one only
    /// makes the client open a connection nobody waits for. The claim
    /// is released in `push_data_conn` when the stream arrives.
    pub(super) async fn request_data_conn(&self) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(anyhow!("control closed"));
        }
        let cap = self.pool_count + self.cfg.limits.max_outstanding_data_conns;
        if self.outstanding_data_conns.fetch_add(1, Ordering::SeqCst) >= cap {
            self.outstanding_data_conns
                .fetch_sub(1, Ordering::SeqCst);
            return Ok(());
        }
        let sent = async {
            let mut writer_lock = self.writer.lock().await;
            if let Some(w) = writer_lock.as_mut() {
                msg::write_msg(w, &Message::ReqDataConn(ReqDataConn {}))
                    .await
                    .map_err(|e| anyhow!("request_data_conn: {e}"))
            } else {
                Err(anyhow!("request_data_conn: writer not initialised"))
            }
        }
        .await;
        if sent.is_err() {
            self.outstanding_data_conns
                .fetch_sub(1, Ordering::SeqCst);
        }
        sent
    }

    pub async fn start_data_conn(
        &self,
        mut data: DynStream,
        tunnel_name: &str,
        src_addr: String,
        src_port: u16,
        dst_addr: String,
        dst_port: u16,
    ) -> Result<DynStream> {
        msg::write_msg(
            &mut data,
            &Message::StartDataConn(StartDataConn {
                tunnel_name: tunnel_name.to_string(),
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                error: String::new(),
            }),
        )
        .await?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbien_core::config::ServerConfig;
    use tokio::io::duplex;

    /// A Control far enough to test the pool: built by hand instead of
    /// through register_control, which needs a live login. Returns the
    /// duplex peer too: dropping it breaks the control's writer, so the
    /// caller must hold it for the whole test.
    fn test_control(pool_count: usize) -> (Arc<Control>, tokio::io::DuplexStream) {
        test_control_with_ttl(pool_count, 300)
    }

    fn test_control_with_ttl(
        pool_count: usize,
        pool_idle_ttl_secs: u64,
    ) -> (Arc<Control>, tokio::io::DuplexStream) {
        // 4 KiB duplex: the ReqDataConn frames (7 bytes each) must not
        // block on a full buffer while nobody reads.
        let (a, b) = duplex(4096);
        let stream = orbien_core::transport::boxed_stream(a);
        let mut cfg = ServerConfig::default();
        cfg.limits.pool_idle_ttl_secs = pool_idle_ttl_secs;
        let access = Arc::new(tokio::sync::RwLock::new(Arc::new(
            crate::access::AccessPolicy::from_server_config(&cfg)
                .expect("default config builds an access policy"),
        )));
        (
            Arc::new(Control::new(
                "test-session".into(),
                stream,
                cfg,
                pool_count,
                None,
                None,
                access,
                "user".into(),
                "host".into(),
                "linux".into(),
                "x86_64".into(),
                "0.2.0".into(),
                "127.0.0.1:1".into(),
                crate::metrics::MemMetrics::new(),
                String::new(),
                String::new(),
            )),
            b,
        )
    }

    #[tokio::test]
    async fn pool_idle_expiry_drops_stale_stream() {
        let (ctl, _peer) = test_control_with_ttl(2, 1);
        // A fresh entry pops fine.
        let _ = ctl.push_data_conn(orbien_core::transport::boxed_stream(duplex(64).0)).await;
        assert!(ctl.try_pop_data().await.is_some());
        // An entry older than the 1 s TTL is dropped, not handed out.
        let _ = ctl.push_data_conn(orbien_core::transport::boxed_stream(duplex(64).0)).await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            ctl.try_pop_data().await.is_none(),
            "stale pooled stream must be dropped, not handed to a visitor"
        );
    }

    #[tokio::test]
    async fn waiting_visitors_cap_refuses_immediately() {
        let (ctl, _peer) = test_control(1);
        // Fill the single pool slot so every get_data_conn has to wait.
        let _ = ctl.push_data_conn(orbien_core::transport::boxed_stream(duplex(64).0)).await;
        let _ = ctl.try_pop_data().await;
        // The default cap is 32; spawn 33 waiters and assert the count
        // stops at 32 and the 33rd fails at once instead of waiting 10 s.
        let mut handles = Vec::new();
        for _ in 0..33 {
            let c = Arc::clone(&ctl);
            handles.push(tokio::spawn(async move {
                c.get_data_conn("tun").await.is_ok()
            }));
        }
        // Poll until all 32 guards registered (spawn scheduling jitter).
        let mut waiting_n = 0;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            waiting_n = ctl
                .waiting_visitors
                .lock()
                .unwrap()
                .get("tun")
                .copied()
                .unwrap_or(0);
            if waiting_n == 32 {
                break;
            }
        }
        assert_eq!(waiting_n, 32, "waiting count must stop at the cap");
        ctl.shutdown().await;
        let mut oks = 0;
        for h in handles {
            if h.await.unwrap() {
                oks += 1;
            }
        }
        assert_eq!(oks, 0, "no waiter should have been served");
        assert_eq!(
            ctl.waiting_visitors.lock().unwrap().len(),
            0,
            "guards must release on exit"
        );
    }

    #[tokio::test]
    async fn request_data_conn_dedup_sends_once() {
        let (ctl, _peer) = test_control(2);
        // Cap is pool(2) + burst(8) = 10: 12 requests claim at most 10.
        for _ in 0..12 {
            let _ = ctl.request_data_conn().await;
        }
        assert_eq!(
            ctl.outstanding_data_conns.load(Ordering::SeqCst),
            10,
            "outstanding requests stop at pool_count + burst"
        );
        // One arrival releases one claim.
        let _ = ctl.push_data_conn(orbien_core::transport::boxed_stream(duplex(64).0)).await;
        assert_eq!(ctl.outstanding_data_conns.load(Ordering::SeqCst), 9);
    }
}
