use crate::limit::BandwidthLimiter;
use crate::msg::{Message, Ping, UdpPacket, UdpSocketAddr};
use std::collections::{HashMap, HashSet};
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

/// How often the visitor table is swept for expired entries. Between
/// sweeps the per-packet cost is O(1) (#14: the old code ran `retain`
/// over the whole table on every datagram).
const VISITOR_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// At most one drop-summary log line per interval, per log owner.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// Winsock `WSAEMSGSIZE`: a datagram larger than the receive buffer.
/// `recv_from` on Windows reports it as an error (the datagram is
/// already consumed); Linux truncates silently instead. The value can
/// never occur as a Unix errno, so the check is portable.
const WSAEMSGSIZE: i32 = 10040;

/// Fixed reasons for UDP drops (#14). Each maps to one
/// `limit_rejections` metric key; see `ServerSnapshot::limit_rejections`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpDropReason {
    /// Source address is in `denySrcCidrs` (#15).
    Denied,
    /// Reply target never sent a datagram to this tunnel.
    NoVisitor,
    /// Visitor table is at its cap.
    SessionCap,
    /// Per-source or per-tunnel packet rate limit.
    RateLimited,
    /// Downstream channel full.
    ChannelFull,
    /// `send_to` failed.
    SendError,
    /// Datagram larger than the receive buffer.
    Truncated,
    /// `recv_from` reported connection-reset (Windows).
    RecvReset,
}

impl UdpDropReason {
    pub fn metric_reason(self) -> &'static str {
        match self {
            UdpDropReason::Denied => "deny_src_cidrs",
            UdpDropReason::NoVisitor => "udp_no_visitor",
            UdpDropReason::SessionCap => "udp_session_cap",
            UdpDropReason::RateLimited => "udp_rate_limited",
            UdpDropReason::ChannelFull => "udp_channel_full",
            UdpDropReason::SendError => "udp_send_error",
            UdpDropReason::Truncated => "udp_truncated",
            UdpDropReason::RecvReset => "udp_recv_reset",
        }
    }
}

/// Operator-set limits for one UDP tunnel (#14). `max_sessions` is the
/// effective cap: the operator's cap, with the client's `maxConnections`
/// only able to lower it.
#[derive(Debug, Clone, Copy)]
pub struct UdpForwardLimits {
    pub max_sessions: usize,
    /// Max packets/sec from one source IP; 0 = no per-source limit.
    pub per_source_pps: u64,
    /// Max packets/sec for the whole tunnel; 0 = no per-tunnel limit.
    pub per_tunnel_pps: u64,
}

impl Default for UdpForwardLimits {
    fn default() -> Self {
        Self {
            max_sessions: 1024,
            per_source_pps: 1000,
            per_tunnel_pps: 10_000,
        }
    }
}

/// Server-side hooks for `forward_user_conn` (#14). Core cannot name the
/// server's metrics, so the server passes closures (same pattern as the
/// #15 `is_denied` closure).
pub struct UdpForwardHooks {
    pub is_denied: Arc<dyn Fn(IpAddr) -> bool + Send + Sync>,
    pub on_drop: Arc<dyn Fn(UdpDropReason) + Send + Sync>,
    pub on_delivered: Arc<dyn Fn(u64) + Send + Sync>,
}

/// Always-on visitor table for one UDP tunnel (#14). The reader loop
/// records every source that sent a datagram; the reply writer only
/// sends to addresses recorded within the idle window, so a client
/// cannot make the server send datagrams to arbitrary addresses.
pub struct VisitorTable {
    cap: usize,
    idle: Duration,
    per_source_pps: u64,
    entries: HashMap<SocketAddr, Instant>,
    /// Per-source packet rate limiters, keyed by IP. Created only for
    /// tracked visitors and pruned with the table, so spoofed sources
    /// cannot grow this map beyond the visitor cap.
    limiters: HashMap<IpAddr, BandwidthLimiter>,
    last_sweep: Instant,
}

impl VisitorTable {
    pub fn new(cap: usize, idle: Duration, per_source_pps: u64) -> Self {
        Self {
            cap: cap.max(1),
            idle,
            per_source_pps,
            entries: HashMap::new(),
            limiters: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    /// Record an incoming datagram. Returns false when the table is at
    /// its cap and the source is new (caller drops the packet).
    pub fn note_seen(&mut self, addr: SocketAddr, now: Instant) -> bool {
        if now.duration_since(self.last_sweep) >= VISITOR_SWEEP_INTERVAL {
            self.sweep(now);
        }
        if let Some(last) = self.entries.get_mut(&addr) {
            *last = now;
            return true;
        }
        if self.entries.len() >= self.cap {
            return false;
        }
        self.entries.insert(addr, now);
        true
    }

    /// True when `addr` sent a datagram within the idle window.
    pub fn allows_reply(&self, addr: SocketAddr, now: Instant) -> bool {
        self.entries
            .get(&addr)
            .is_some_and(|last| now.duration_since(*last) < self.idle)
    }

    /// Per-source packet rate limit. Only called for tracked visitors;
    /// returns true when the packet may proceed.
    pub fn check_rate(&mut self, ip: IpAddr) -> bool {
        if self.per_source_pps == 0 {
            return true;
        }
        let limiter = self
            .limiters
            .entry(ip)
            .or_insert_with(|| BandwidthLimiter::new(self.per_source_pps));
        limiter.try_wait_n(1)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn sweep(&mut self, now: Instant) {
        self.last_sweep = now;
        let idle = self.idle;
        self.entries
            .retain(|_, last| now.duration_since(*last) < idle);
        if !self.limiters.is_empty() {
            let live_ips: HashSet<IpAddr> = self.entries.keys().map(|a| a.ip()).collect();
            self.limiters.retain(|ip, _| live_ips.contains(ip));
        }
    }
}

/// Counts drops per reason and logs one summary line at most once per
/// minute, so a flood cannot spam the log (#14). Each task owns its
/// own instance; counts also go to the metrics via `on_drop`.
struct DropLog {
    label: String,
    counts: HashMap<UdpDropReason, u64>,
    last_flush: Instant,
}

impl DropLog {
    fn new(label: String) -> Self {
        Self {
            label,
            counts: HashMap::new(),
            last_flush: Instant::now(),
        }
    }

    fn note(&mut self, reason: UdpDropReason) {
        *self.counts.entry(reason).or_insert(0) += 1;
        if self.last_flush.elapsed() >= DROP_LOG_INTERVAL {
            let total: u64 = self.counts.values().sum();
            tracing::debug!(label = %self.label, total, counts = ?self.counts, "udp drops in interval");
            self.counts.clear();
            self.last_flush = Instant::now();
        }
    }
}

pub async fn forward_user_conn(
    udp: Arc<UdpSocket>,
    mut read_rx: mpsc::Receiver<UdpPacket>,
    send_tx: mpsc::Sender<UdpPacket>,
    buf_size: usize,
    limits: UdpForwardLimits,
    hooks: Arc<UdpForwardHooks>,
    tunnel_name: &str,
) {
    let table: Arc<Mutex<VisitorTable>> = Arc::new(Mutex::new(VisitorTable::new(
        limits.max_sessions,
        CLIENT_IDLE,
        limits.per_source_pps,
    )));
    // Per-tunnel packet rate limit (#14); 0 = disabled.
    let tunnel_limiter = if limits.per_tunnel_pps > 0 {
        Some(BandwidthLimiter::new(limits.per_tunnel_pps))
    } else {
        None
    };

    let udp_w = Arc::clone(&udp);
    let writer = {
        let table = Arc::clone(&table);
        let hooks = Arc::clone(&hooks);
        let mut drops = DropLog::new(format!("udp:{tunnel_name} reply"));
        tokio::spawn(async move {
            while let Some(pkt) = read_rx.recv().await {
                let Some(remote) = pkt.remote_addr.as_ref().and_then(|a| a.to_std()) else {
                    continue;
                };
                // #14: reply only to an address that sent a datagram
                // within the idle window; anything else is dropped.
                let known = table.lock().await.allows_reply(remote, Instant::now());
                if !known {
                    (hooks.on_drop)(UdpDropReason::NoVisitor);
                    drops.note(UdpDropReason::NoVisitor);
                    continue;
                }
                match udp_w.send_to(&pkt.content, remote).await {
                    Ok(n) => (hooks.on_delivered)(n as u64),
                    Err(e) => {
                        tracing::debug!(error = %e, %remote, "udp data→local write failed");
                        (hooks.on_drop)(UdpDropReason::SendError);
                        drops.note(UdpDropReason::SendError);
                        // #14: one failed send must not end all replies
                        // of the tunnel; drop this datagram and continue.
                        continue;
                    }
                }
            }
        })
    };

    // One byte over the configured size: a datagram that fills the whole
    // buffer exceeded it and is truncated (#14: drop + count it instead
    // of forwarding a corrupt datagram silently).
    let buf_len = buf_size.max(512) + 1;
    let mut buf = vec![0u8; buf_len];
    let mut drops = DropLog::new(format!("udp:{tunnel_name} recv"));
    loop {
        match udp.recv_from(&mut buf).await {
            Ok((n, remote)) => {
                if n == buf.len() {
                    (hooks.on_drop)(UdpDropReason::Truncated);
                    drops.note(UdpDropReason::Truncated);
                    continue;
                }
                // #15: deny before the session map — a denied source
                // must not consume a #14 session slot.
                if (hooks.is_denied)(remote.ip()) {
                    (hooks.on_drop)(UdpDropReason::Denied);
                    drops.note(UdpDropReason::Denied);
                    continue;
                }
                let now = Instant::now();
                let mut table = table.lock().await;
                if !table.note_seen(remote, now) {
                    (hooks.on_drop)(UdpDropReason::SessionCap);
                    drops.note(UdpDropReason::SessionCap);
                    continue;
                }
                if !table.check_rate(remote.ip()) {
                    (hooks.on_drop)(UdpDropReason::RateLimited);
                    drops.note(UdpDropReason::RateLimited);
                    continue;
                }
                drop(table);
                if let Some(lim) = &tunnel_limiter {
                    if !lim.try_wait_n(1) {
                        (hooks.on_drop)(UdpDropReason::RateLimited);
                        drops.note(UdpDropReason::RateLimited);
                        continue;
                    }
                }
                let pkt = UdpPacket::new(buf[..n].to_vec(), Some(remote));
                if send_tx.try_send(pkt).is_err() {
                    (hooks.on_drop)(UdpDropReason::ChannelFull);
                    drops.note(UdpDropReason::ChannelFull);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                // #14: on Windows a UDP socket reports connection-reset
                // on receive after a send to an unreachable port; count
                // it and keep the tunnel's receive path alive.
                (hooks.on_drop)(UdpDropReason::RecvReset);
                drops.note(UdpDropReason::RecvReset);
                continue;
            }
            Err(e) if e.raw_os_error() == Some(WSAEMSGSIZE) => {
                // #14: on Windows an oversized datagram is a receive
                // error, not a truncated read; the datagram is already
                // consumed, so count it and keep the loop alive.
                (hooks.on_drop)(UdpDropReason::Truncated);
                drops.note(UdpDropReason::Truncated);
                continue;
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
    max_sessions: usize,
) {
    let map: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>> = Arc::new(Mutex::new(HashMap::new()));
    let pp_ver = proxy_protocol_version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    // #14: bind the ephemeral socket in the same address family as the
    // local service, so an IPv6 service (e.g. [::1]:53) works.
    let bind_addr = if local_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let mut drops = DropLog::new(format!("udp forwarder {local_addr}"));

    while let Some(pkt) = read_rx.recv().await {
        let Some(remote) = pkt.remote_addr.as_ref().and_then(|a| a.to_std()) else {
            continue;
        };

        let (udp_conn, is_new) = {
            let guard = map.lock().await;
            if let Some(c) = guard.get(&remote) {
                (Arc::clone(c), false)
            } else if guard.len() >= max_sessions.max(1) {
                // #14: one socket + one task per visitor address, capped.
                // The check runs under the lock in this single task and
                // only the reader tasks remove entries, so the cap holds.
                drop(guard);
                drops.note(UdpDropReason::SessionCap);
                continue;
            } else {
                drop(guard);
                let sock = match UdpSocket::bind(bind_addr).await {
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
    // One byte over the configured size so an oversized datagram is
    // detected and dropped (#14) instead of forwarded truncated.
    let buf_len = ctx.buf_size.max(512) + 1;
    let mut buf = vec![0u8; buf_len];
    let mut last_activity = Instant::now();
    loop {
        let remaining = CLIENT_IDLE.saturating_sub(last_activity.elapsed());
        if remaining.is_zero() {
            break;
        }
        match timeout(remaining, ctx.udp_conn.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if n == buf.len() {
                    tracing::trace!(remote = %ctx.remote, "udp reply larger than buffer; drop");
                    continue;
                }
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
            Ok(Err(e)) if e.raw_os_error() == Some(WSAEMSGSIZE) => {
                // #14: on Windows an oversized reply is a receive error,
                // not a truncated read; drop it and keep this visitor's
                // forwarding alive.
                tracing::trace!(remote = %ctx.remote, "udp reply larger than buffer; drop");
                continue;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[tokio::test]
    async fn visitor_table_tracks_and_allows_reply_within_idle() {
        let mut t = VisitorTable::new(10, StdDuration::from_secs(30), 0);
        let now = Instant::now();
        assert!(!t.allows_reply(addr(1001), now));
        assert!(t.note_seen(addr(1001), now));
        assert!(t.allows_reply(addr(1001), now));
        assert_eq!(t.len(), 1);
    }

    #[tokio::test]
    async fn visitor_table_cap_blocks_new_visitors_only() {
        let mut t = VisitorTable::new(2, StdDuration::from_secs(30), 0);
        let now = Instant::now();
        assert!(t.note_seen(addr(1001), now));
        assert!(t.note_seen(addr(1002), now));
        assert!(!t.note_seen(addr(1003), now));
        // A known visitor still gets through at the cap.
        assert!(t.note_seen(addr(1001), now));
        assert_eq!(t.len(), 2);
    }

    #[tokio::test]
    async fn visitor_table_reply_denied_after_idle() {
        let mut t = VisitorTable::new(10, StdDuration::from_millis(50), 0);
        let now = Instant::now();
        assert!(t.note_seen(addr(1001), now));
        tokio::time::sleep(StdDuration::from_millis(80)).await;
        assert!(!t.allows_reply(addr(1001), Instant::now()));
    }

    #[tokio::test]
    async fn visitor_table_sweep_reclaims_expired_slots() {
        let mut t = VisitorTable::new(1, StdDuration::from_millis(50), 0);
        assert!(t.note_seen(addr(1001), Instant::now()));
        assert!(!t.note_seen(addr(1002), Instant::now()));
        // The sweep runs at most once a second; wait it out.
        tokio::time::sleep(StdDuration::from_millis(1100)).await;
        assert!(t.note_seen(addr(1002), Instant::now()));
        assert_eq!(t.len(), 1);
    }

    #[tokio::test]
    async fn visitor_table_per_source_rate_limit() {
        let mut t = VisitorTable::new(10, StdDuration::from_secs(30), 2);
        let now = Instant::now();
        let ip = addr(1001).ip();
        assert!(t.note_seen(addr(1001), now));
        assert!(t.check_rate(ip));
        assert!(t.check_rate(ip));
        assert!(!t.check_rate(ip));
        // Disabled when the limit is 0.
        let mut u = VisitorTable::new(10, StdDuration::from_secs(30), 0);
        assert!(u.note_seen(addr(1001), now));
        for _ in 0..100 {
            assert!(u.check_rate(ip));
        }
    }

    #[tokio::test]
    async fn visitor_table_per_packet_cost_stays_flat() {
        // #14 acceptance: the per-packet cost must not grow with the
        // number of tracked visitors (the old code ran `retain` over
        // the whole table on every datagram).
        let mut t = VisitorTable::new(1024, StdDuration::from_secs(30), 0);
        let now = Instant::now();
        for port in 0..1024u16 {
            assert!(t.note_seen(addr(port), now));
        }
        let start = Instant::now();
        for _ in 0..100_000 {
            assert!(t.note_seen(addr(7), Instant::now()));
        }
        assert!(
            start.elapsed() < StdDuration::from_secs(1),
            "100k lookups in a full table took {:?}",
            start.elapsed()
        );
    }
}
