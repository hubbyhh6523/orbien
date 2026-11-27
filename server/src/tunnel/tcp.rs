use crate::access::{prepare_ingress, AccessPolicy};
use crate::control::Control;
use crate::metrics;
use anyhow::Result;
use orbien_core::limit::{maybe_limit, BandwidthLimiter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::task::JoinHandle;

pub struct TcpTunnel {
    pub name: String,
    pub remote_port: u16,
    closed: Arc<AtomicBool>,
    /// Set while the accept loop is failing (#13); cleared on the next
    /// successful accept. Drives `status()` for the dashboard.
    accept_failed: Arc<AtomicBool>,
    notify: Arc<Notify>,
    accept_task: Mutex<Option<JoinHandle<()>>>,
}

impl TcpTunnel {
    pub async fn start(
        name: String,
        bind_addr: String,
        remote_port: u16,
        control: Arc<Control>,
        limiter: Option<Arc<BandwidthLimiter>>,
        access: Arc<RwLock<Arc<AccessPolicy>>>,
    ) -> Result<Self> {
        let addr = format!("{bind_addr}:{remote_port}");
        let listener = TcpListener::bind(&addr).await?;
        tracing::info!(%addr, tunnel = %name, "tcp tunnel listening");

        let closed = Arc::new(AtomicBool::new(false));
        let accept_failed = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(Notify::new());
        let closed_flag = Arc::clone(&closed);
        let accept_failed_flag = Arc::clone(&accept_failed);
        let notify_wait = Arc::clone(&notify);
        let tunnel_name = name.clone();
        let limiter_spawn = limiter.clone();

        let control_weak = Arc::downgrade(&control);

        let accept_task = tokio::spawn(async move {
            // #13: accept errors back off and retry instead of closing
            // the tunnel's port while the tunnel stays registered.
            let mut backoff = crate::accept::AcceptBackoff::new();
            loop {
                tokio::select! {
                    _ = notify_wait.notified() => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, peer)) => {
                                backoff.reset();
                                accept_failed_flag.store(false, Ordering::SeqCst);
                                orbien_core::net::enable_nodelay(&stream);
                                if closed_flag.load(Ordering::SeqCst) {
                                    break;
                                }
                                let Some(ctl) = control_weak.upgrade() else {
                                    break;
                                };
                                let pname = tunnel_name.clone();
                                let lim = limiter_spawn.clone();
                                // #15: snapshot the live policy per
                                // connection, so a reload applies to new
                                // connections of existing tunnels.
                                let access = Arc::clone(&*access.read().await);
                                tokio::spawn(async move {
                                    if let Err(e) = handle_ingress(
                                        ctl,
                                        &pname,
                                        stream,
                                        peer,
                                        lim,
                                        access,
                                    )
                                    .await
                                    {
                                        tracing::debug!(tunnel = %pname, error = %e, "ingress ended");
                                    }
                                });
                            }
                            Err(e) => {
                                accept_failed_flag.store(true, Ordering::SeqCst);
                                backoff.on_error(&e.into()).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            name,
            remote_port,
            closed,
            accept_failed,
            notify,
            accept_task: Mutex::new(Some(accept_task)),
        })
    }

    /// Dashboard status (#13): "closed" once close() ran, "failed"
    /// while the accept loop is in a failing streak, "listening"
    /// otherwise. Replaces the old hardcoded "online" for TCP tunnels.
    pub fn status(&self) -> &'static str {
        if self.closed.load(Ordering::SeqCst) {
            "closed"
        } else if self.accept_failed.load(Ordering::SeqCst) {
            "failed"
        } else {
            "listening"
        }
    }

    pub async fn close(&self) {
        tracing::info!(tunnel = %self.name, remote_port = self.remote_port, "tcp tunnel closing");
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
        if let Some(h) = self.accept_task.lock().await.take() {
            h.abort();
            let _ = h.await;
        }
    }
}

impl Drop for TcpTunnel {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
        if let Some(h) = self.accept_task.get_mut().take() {
            h.abort();
        }
    }
}

async fn handle_ingress(
    control: Arc<Control>,
    tunnel_name: &str,
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    limiter: Option<Arc<BandwidthLimiter>>,
    access: Arc<AccessPolicy>,
) -> Result<()> {
    let ingress = prepare_ingress(stream, peer, &access).await?;
    let data = control.get_data_conn(tunnel_name).await?;
    let data = control
        .start_data_conn(
            data,
            tunnel_name,
            ingress.source.ip().to_string(),
            ingress.source.port(),
            ingress
                .local
                .map(|a| a.ip().to_string())
                .unwrap_or_default(),
            ingress.local.map(|a| a.port()).unwrap_or(0),
        )
        .await?;

    let data = maybe_limit(data, limiter);

    tracing::debug!(
        tunnel = %tunnel_name,
        peer = %ingress.peer,
        source = %ingress.source,
        "joining ingress <-> data"
    );
    let idle_timeout = control.idle_timeout();
    let _ = metrics::join_and_record_idle(
        &control.metrics,
        tunnel_name,
        "tcp",
        ingress.stream,
        data,
        idle_timeout,
    )
    .await;
    Ok(())
}
