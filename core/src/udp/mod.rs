use crate::msg::{Message, Ping, UdpPacket, UdpSocketAddr};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{timeout, Instant};

pub const CHANNEL_CAP: usize = 1024;
pub const CLIENT_IDLE: Duration = Duration::from_secs(30);
pub const DATA_PING_INTERVAL: Duration = Duration::from_secs(30);
pub const SERVER_DATA_READ_DEADLINE: Duration = Duration::from_secs(60);

pub async fn forward_user_conn(
    udp: Arc<UdpSocket>,
    mut read_rx: mpsc::Receiver<UdpPacket>,
    send_tx: mpsc::Sender<UdpPacket>,
    buf_size: usize,
    max_sessions: usize,
    is_denied: Arc<dyn Fn(IpAddr) -> bool + Send + Sync>,
) {
    let udp_w = Arc::clone(&udp);
    let writer = tokio::spawn(async move {
        while let Some(pkt) = read_rx.recv().await {
            let Some(remote) = pkt.remote_addr.as_ref().and_then(|a| a.to_std()) else {
                continue;
            };
            if let Err(e) = udp_w.send_to(&pkt.content, remote).await {
                tracing::debug!(error = %e, "udp data→local write failed");
                break;
            }
        }
    });

    let seen: Mutex<HashMap<SocketAddr, Instant>> = Mutex::new(HashMap::new());
    let mut buf = vec![0u8; buf_size.max(512)];
    loop {
        match udp.recv_from(&mut buf).await {
            Ok((n, remote)) => {
                // #15: deny before the session map — a denied source
                // must not consume a #14 session slot.
                if is_denied(remote.ip()) {
                    tracing::trace!(%remote, "udp packet from denied source; drop");
                    continue;
                }
                if max_sessions > 0 {
                    let now = Instant::now();
                    let mut map = seen.lock().await;
                    map.retain(|_, last| now.duration_since(*last) < CLIENT_IDLE);
                    if let Some(last) = map.get_mut(&remote) {
                        *last = now;
                    } else if map.len() >= max_sessions {
                        tracing::trace!(%remote, max_sessions, "udp session limit reached; drop packet");
                        continue;
                    } else {
                        map.insert(remote, now);
                    }
                }
                let pkt = UdpPacket::new(buf[..n].to_vec(), Some(remote));
                if send_tx.try_send(pkt).is_err() {
                    tracing::trace!("udp sendCh full; drop packet");
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "udp local→data read ended");
                break;
            }
        }
    }

    writer.abort();
}

pub async fn forwarder(
    local_addr: SocketAddr,
    mut read_rx: mpsc::Receiver<UdpPacket>,
    send_tx: mpsc::Sender<Message>,
    buf_size: usize,
    proxy_protocol_version: Option<String>,
) {
    let map: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>> = Arc::new(Mutex::new(HashMap::new()));
    let pp_ver = proxy_protocol_version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    while let Some(pkt) = read_rx.recv().await {
        let Some(remote) = pkt.remote_addr.as_ref().and_then(|a| a.to_std()) else {
            continue;
        };

        let (udp_conn, is_new) = {
            let guard = map.lock().await;
            if let Some(c) = guard.get(&remote) {
                (Arc::clone(c), false)
            } else {
                drop(guard);
                let sock = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(error = %e, "udp bind ephemeral failed");
                        continue;
                    }
                };
                if let Err(e) = sock.connect(local_addr).await {
                    tracing::debug!(error = %e, %local_addr, "udp dial local failed");
                    continue;
                }
                let sock = Arc::new(sock);
                let mut guard = map.lock().await;
                match guard.entry(remote) {
                    std::collections::hash_map::Entry::Occupied(e) => (Arc::clone(e.get()), false),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(Arc::clone(&sock));
                        (sock, true)
                    }
                }
            }
        };

        let payload = if is_new {
            if let Some(ref ver) = pp_ver {
                match crate::net::build_proxy_protocol_header(remote, local_addr, ver) {
                    Ok(hdr) => {
                        let mut buf = Vec::with_capacity(hdr.len() + pkt.content.len());
                        buf.extend_from_slice(&hdr);
                        buf.extend_from_slice(&pkt.content);
                        buf
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "udp PROXY Protocol header build failed; send raw");
                        pkt.content
                    }
                }
            } else {
                pkt.content
            }
        } else {
            pkt.content
        };

        if let Err(e) = udp_conn.send(&payload).await {
            tracing::debug!(error = %e, "udp write to local failed");
            let mut guard = map.lock().await;
            guard.remove(&remote);
            continue;
        }

        if is_new {
            let map_w = Arc::clone(&map);
            let send_tx = send_tx.clone();
            let udp_conn = Arc::clone(&udp_conn);
            tokio::spawn(async move {
                writer_fn(LocalReaderCtx {
                    udp_conn,
                    remote,
                    map: map_w,
                    send_tx,
                    buf_size,
                })
                .await;
            });
        }
    }

    let mut guard = map.lock().await;
    guard.clear();
}

struct LocalReaderCtx {
    udp_conn: Arc<UdpSocket>,
    remote: SocketAddr,
    map: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>>,
    send_tx: mpsc::Sender<Message>,
    buf_size: usize,
}

async fn writer_fn(ctx: LocalReaderCtx) {
    let mut buf = vec![0u8; ctx.buf_size.max(512)];
    let mut last_activity = Instant::now();
    loop {
        let remaining = CLIENT_IDLE.saturating_sub(last_activity.elapsed());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, ctx.udp_conn.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                last_activity = Instant::now();
                let pkt = UdpPacket {
                    content: buf[..n].to_vec(),
                    local_addr: None,
                    remote_addr: Some(UdpSocketAddr::from_std(ctx.remote)),
                };
                if ctx.send_tx.try_send(Message::UdpPacket(pkt)).is_err() {
                    break;
                }
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }
    let mut guard = ctx.map.lock().await;
    guard.remove(&ctx.remote);
}

pub fn spawn_data_ping(send_tx: mpsc::Sender<Message>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(DATA_PING_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        tick.tick().await;
        loop {
            tick.tick().await;
            if send_tx.try_send(Message::Ping(Ping::default())).is_err() {
                break;
            }
        }
    })
}
