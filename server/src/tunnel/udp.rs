use crate::access::AccessPolicy;
use crate::control::Control;
use crate::metrics::{MemMetrics, ServerMetrics};
use anyhow::Result;
use orbien_core::limit::{maybe_limit, BandwidthLimiter};
use orbien_core::msg::{self, Message, UdpPacket};
use orbien_core::udp::{
    forward_user_conn, UdpDropReason, UdpForwardHooks, UdpForwardLimits, CHANNEL_CAP,
    SERVER_DATA_READ_DEADLINE,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

pub struct UdpTunnel {
    pub name: String,
    pub remote_port: u16,
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
    tasks: Mutex<Vec<JoinHandle<()>>>,

    /// Live access policy (#15): the deny check in `forward_user_conn`
    /// reads it per datagram through a closure, so reloads apply to
    /// existing tunnels.
    _access: Arc<RwLock<Arc<AccessPolicy>>>,

    _udp: Arc<UdpSocket>,
}

impl UdpTunnel {
    // #11: 8 args — `access` is the live policy for the #15 source checks,
    // `limits` the #14 operator caps (effective visitor cap + rate limits).
    // Kept explicit (rather than re-reading them off `control`) so the
    // tunnel's policy dependency is visible at the call site.
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        name: String,
        bind_addr: String,
        remote_port: u16,
        control: Arc<Control>,
        limiter: Option<Arc<BandwidthLimiter>>,
        packet_size: usize,
        limits: UdpForwardLimits,
        access: Arc<RwLock<Arc<AccessPolicy>>>,
    ) -> Result<Self> {
        let addr = format!("{bind_addr}:{remote_port}");
        let udp = Arc::new(UdpSocket::bind(&addr).await?);
        tracing::info!(%addr, tunnel = %name, "udp tunnel listening");

        let closed = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(Notify::new());

        // #15: the deny check needs the live policy, but
        // `forward_user_conn` lives in core and cannot name the
        // server's `AccessPolicy` — hand it a closure over the live
        // lock instead. `try_read`, not `blocking_read` (that panics
        // inside a runtime task): a contended read only happens while
        // a reload swaps the `Arc`, so fail closed for that instant.
        let access_f = Arc::clone(&access);
        let is_denied: Arc<dyn Fn(IpAddr) -> bool + Send + Sync> =
            Arc::new(move |ip| match access_f.try_read() {
                Ok(policy) => policy.is_denied(ip),
                Err(_) => true,
            });

        // #14: drops are reported in the `limit_rejections` metric
        // under their fixed reason, and out-traffic is counted only
        // when a reply is actually delivered to a visitor (the writer
        // task calls `on_delivered` after a successful `send_to`).
        let metrics_o = Arc::clone(&control.metrics);
        let on_drop: Arc<dyn Fn(UdpDropReason) + Send + Sync> =
            Arc::new(move |reason| metrics_o.inc_limit_reject(reason.metric_reason()));
        let metrics_d = Arc::clone(&control.metrics);
        let name_d = name.clone();
        let on_delivered: Arc<dyn Fn(u64) + Send + Sync> =
            Arc::new(move |n| metrics_d.add_traffic_out(&name_d, "udp", n));
        let hooks = Arc::new(UdpForwardHooks {
            is_denied,
            on_drop,
            on_delivered,
        });

        let (send_tx, send_rx) = mpsc::channel::<UdpPacket>(CHANNEL_CAP);
        let (read_tx, read_rx) = mpsc::channel::<UdpPacket>(CHANNEL_CAP);

        let mut tasks = Vec::new();

        {
            let udp_f = Arc::clone(&udp);
            let notify_f = Arc::clone(&notify);
            let name_f = name.clone();
            tasks.push(tokio::spawn(async move {
                tokio::select! {
                    _ = notify_f.notified() => {}
                    _ = forward_user_conn(udp_f, read_rx, send_tx, packet_size, limits, hooks, &name_f) => {}
                }
            }));
        }

        {
            let closed_flag = Arc::clone(&closed);
            let notify_wait = Arc::clone(&notify);
            let tunnel_name = name.clone();
            let control = Arc::downgrade(&control);
            tasks.push(tokio::spawn(async move {
                sleep(Duration::from_millis(500)).await;
                data_conn_loop(
                    tunnel_name,
                    control,
                    limiter,
                    send_rx,
                    read_tx,
                    closed_flag,
                    notify_wait,
                )
                .await;
            }));
        }

        Ok(Self {
            name,
            remote_port,
            closed,
            notify,
            tasks: Mutex::new(tasks),
            _access: access,
            _udp: udp,
        })
    }

    pub async fn close(&self) {
        tracing::info!(tunnel = %self.name, remote_port = self.remote_port, "udp tunnel closing");
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
        let tasks = std::mem::take(&mut *self.tasks.lock().await);
        for h in tasks {
            h.abort();
            let _ = h.await;
        }
    }
}

impl Drop for UdpTunnel {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
        for h in self.tasks.get_mut().drain(..) {
            h.abort();
        }
    }
}

async fn abort_wait(h: JoinHandle<()>) {
    h.abort();
    let _ = h.await;
}

async fn data_conn_loop(
    tunnel_name: String,
    control: std::sync::Weak<Control>,
    limiter: Option<Arc<BandwidthLimiter>>,
    mut send_rx: mpsc::Receiver<UdpPacket>,
    read_tx: mpsc::Sender<UdpPacket>,
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
) {
    while !closed.load(Ordering::SeqCst) {
        let Some(control) = control.upgrade() else {
            return;
        };

        let data = {
            tokio::select! {
                _ = notify.notified() => return,
                w = control.get_data_conn(&tunnel_name) => w,
            }
        };

        let data = match data {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(tunnel = %tunnel_name, error = %e, "udp get data conn failed");
                tokio::select! {
                    _ = notify.notified() => return,
                    _ = sleep(Duration::from_secs(1)) => continue,
                }
            }
        };

        let data = match control
            .start_data_conn(data, &tunnel_name, String::new(), 0, String::new(), 0)
            .await
        {
            Ok(w) => w,
            Err(e) => {
                tracing::warn!(tunnel = %tunnel_name, error = %e, "udp StartDataConn failed");
                sleep(Duration::from_secs(1)).await;
                continue;
            }
        };

        let data = maybe_limit(data, limiter.clone());
        let (reader, mut writer) = tokio::io::split(data);
        tracing::info!(
            tunnel = %tunnel_name,
            "udp data conn established"
        );
        let metrics = Arc::clone(&control.metrics);
        let _guard = metrics.track_connection(&tunnel_name, "udp");

        let (fail_tx, mut fail_rx) = mpsc::channel::<()>(1);
        let read_tx_r = read_tx.clone();
        let fail_r = fail_tx.clone();
        let name_r = tunnel_name.clone();
        let metrics_r = Arc::clone(&metrics);
        let mut reader_task = Some(tokio::spawn(async move {
            data_reader(reader, read_tx_r, fail_r, name_r, metrics_r).await;
        }));

        let reconnect = loop {
            tokio::select! {
                _ = notify.notified() => {
                    if let Some(h) = reader_task.take() {
                        abort_wait(h).await;
                    }
                    return;
                }
                _ = fail_rx.recv() => {
                    if let Some(h) = reader_task.take() {
                        abort_wait(h).await;
                    }
                    break true;
                }
                pkt = send_rx.recv() => {
                    match pkt {
                        Some(pkt) => {
                            let nbytes = pkt.content.len() as u64;
                            tracing::trace!(
                                tunnel = %tunnel_name,
                                len = nbytes,
                                "udp packet to data"
                            );
                            if msg::write_msg(&mut writer, &Message::UdpPacket(pkt))
                                .await
                                .is_err()
                            {
                                tracing::warn!(tunnel = %tunnel_name, "udp data write error");
                                if let Some(h) = reader_task.take() {
                                    abort_wait(h).await;
                                }
                                break true;
                            }
                            metrics.add_traffic_in(&tunnel_name, "udp", nbytes);
                        }
                        None => {
                            if let Some(h) = reader_task.take() {
                                abort_wait(h).await;
                            }
                            return;
                        }
                    }
                }
            }
        };

        if reconnect {
            tracing::info!(tunnel = %tunnel_name, "udp data conn lost; reconnecting");
        }
    }
}

async fn data_reader<R: AsyncRead + Unpin + Send + 'static>(
    mut reader: R,
    read_tx: mpsc::Sender<UdpPacket>,
    fail_tx: mpsc::Sender<()>,
    tunnel_name: String,
    metrics: Arc<MemMetrics>,
) {
    loop {
        match timeout(SERVER_DATA_READ_DEADLINE, msg::read_msg(&mut reader)).await {
            Ok(Ok(Message::Ping(_))) => {
                tracing::trace!(tunnel = %tunnel_name, "udp data ping");
            }
            Ok(Ok(Message::UdpPacket(pkt))) => {
                tracing::trace!(
                    tunnel = %tunnel_name,
                    len = pkt.content.len(),
                    "udp packet from data"
                );
                // #14: out-traffic is counted only when the reply is
                // actually delivered (via `on_delivered` in the writer
                // task), not here — a packet dropped below was counted
                // as traffic before. A full channel is a counted drop.
                if read_tx.try_send(pkt).is_err() {
                    metrics.inc_limit_reject("udp_channel_full");
                }
            }
            Ok(Ok(other)) => {
                tracing::debug!(
                    tunnel = %tunnel_name,
                    ty = other.type_byte(),
                    "udp data unexpected message"
                );
            }
            Ok(Err(e)) => {
                tracing::warn!(tunnel = %tunnel_name, error = %e, "udp data read error");
                let _ = fail_tx.send(()).await;
                return;
            }
            Err(_) => {
                tracing::warn!(tunnel = %tunnel_name, "udp data read deadline exceeded");
                let _ = fail_tx.send(()).await;
                return;
            }
        }
    }
}
