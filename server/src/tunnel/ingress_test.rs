//! #15 integration tests: deny/PROXY handling at the live listeners.
//!
//! The TCP tunnel tests distinguish "closed before `get_data_conn`" from
//! "waiting for a data conn": a denied visitor is closed immediately, an
//! allowed one stays open (the control's data pool is empty, so the
//! server waits up to 10s for the client to open a data conn).

use super::gw::HttpGw;
use super::http::run_http_gw_listener;
use super::https::{run_https_gw_listener, HttpsGw};
use super::tcp::TcpTunnel;
use crate::access::{AccessPolicy, Cidr};
use crate::control::Control;
use orbien_core::transport::boxed_stream;
use orbien_core::udp::{forward_user_conn, UdpDropReason, UdpForwardHooks, UdpForwardLimits};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Notify, RwLock};

/// A Control far enough to run a tunnel: built by hand instead of
/// through register_control, which needs a live login. Returns the duplex
/// peer too: dropping it breaks the control's writer, so the caller must
/// hold it for the whole test.
fn make_control(session_id: &str) -> (Arc<Control>, DuplexStream) {
    let (peer, stream) = tokio::io::duplex(64 * 1024);
    let cfg = orbien_core::config::ServerConfig::default();
    let access = Arc::new(RwLock::new(Arc::new(
        crate::access::AccessPolicy::from_server_config(&cfg)
            .expect("default config builds an access policy"),
    )));
    let control = Arc::new(Control::new(
        session_id.into(),
        boxed_stream(stream),
        cfg,
        1,
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
        format!("token-id-{session_id}"),
        "00".repeat(32),
    ));
    (control, peer)
}

/// Drain the control-stream peer so `ReqDataConn` writes never block.
fn drain_peer(mut peer: DuplexStream) {
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match peer.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
}

fn access_policy(deny: &[&str]) -> AccessPolicy {
    AccessPolicy {
        proxy_protocol: false,
        trusted_proxy_cidrs: vec![],
        deny_src_cidrs: deny.iter().map(|s| Cidr::parse(s).unwrap()).collect(),
        pp_header_timeout: Duration::from_secs(5),
        token_policies: HashMap::new(),
    }
}

fn policy_lock(deny: &[&str]) -> Arc<RwLock<Arc<AccessPolicy>>> {
    Arc::new(RwLock::new(Arc::new(access_policy(deny))))
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The server must close the connection (EOF) within 2s.
async fn read_closed_soon(mut stream: TcpStream) {
    let mut buf = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
    match r {
        Ok(Ok(0)) => {}
        Ok(Ok(_)) => panic!("expected EOF, got data"),
        Ok(Err(e)) => panic!("expected EOF, got error: {e}"),
        Err(_) => panic!("connection was not closed within 2s"),
    }
}

/// The server must keep the connection open for at least 300ms.
async fn read_stays_open(mut stream: TcpStream) {
    let mut buf = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await;
    assert!(r.is_err(), "connection closed unexpectedly: {r:?}");
}

/// Connect with retries: the gateway listener binds inside its spawned
/// task, so the first attempt can race the bind.
async fn connect_with_retry(port: u16) -> TcpStream {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(s) => return s,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(e) => panic!("could not connect to gateway on {port}: {e}"),
        }
    }
}

async fn start_tcp_tunnel(
    port: u16,
    access: Arc<RwLock<Arc<AccessPolicy>>>,
    session_id: &str,
) -> (TcpTunnel, Arc<Control>) {
    let (control, peer) = make_control(session_id);
    drain_peer(peer);
    let tunnel = TcpTunnel::start(
        "web".into(),
        "127.0.0.1".into(),
        port,
        Arc::clone(&control),
        None,
        access,
    )
    .await
    .expect("tcp tunnel binds");
    // The tunnel keeps only a Weak<Control>, so the caller must hold the
    // Arc for the whole test or the control is dropped and every visitor
    // is closed at accept.
    (tunnel, control)
}

#[tokio::test]
async fn tcp_tunnel_denied_visitor_closed_without_data_conn() {
    let port = free_port().await;
    let access = policy_lock(&["127.0.0.1/32"]);
    let (tunnel, _control) =
        start_tcp_tunnel(port, Arc::clone(&access), "sess-tcp-deny").await;
    let client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    // Before #15 this waited up to 10s for a data conn; now the deny
    // check closes it before `get_data_conn` is ever called.
    read_closed_soon(client).await;
    tunnel.close().await;
}

#[tokio::test]
async fn tcp_tunnel_allowed_visitor_waits_for_data_conn() {
    let port = free_port().await;
    let access = policy_lock(&[]);
    let (tunnel, _control) =
        start_tcp_tunnel(port, Arc::clone(&access), "sess-tcp-allow").await;
    let client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    read_stays_open(client).await;
    tunnel.close().await;
}

#[tokio::test]
async fn tcp_tunnel_live_policy_swap_applies_to_new_connections() {
    let port = free_port().await;
    let access = policy_lock(&[]);
    let (tunnel, _control) =
        start_tcp_tunnel(port, Arc::clone(&access), "sess-tcp-swap").await;
    // Allowed while the policy is empty.
    let first = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    read_stays_open(first).await;
    // Swap in a deny rule; the next connection must be refused. A
    // registration-time snapshot would keep allowing it.
    {
        let mut guard = access.write().await;
        *guard = Arc::new(access_policy(&["127.0.0.1/32"]));
    }
    let second = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    read_closed_soon(second).await;
    tunnel.close().await;
}

#[tokio::test]
async fn http_gateway_denied_visitor_closed() {
    let port = free_port().await;
    let access = policy_lock(&["127.0.0.1/32"]);
    let shutdown = Arc::new(Notify::new());
    let task = tokio::spawn(run_http_gw_listener(
        "127.0.0.1".to_string(),
        port,
        Arc::new(HttpGw::new(port)),
        access,
        Arc::clone(&shutdown),
    ));
    let client = connect_with_retry(port).await;
    read_closed_soon(client).await;
    shutdown.notify_waiters();
    let _ = task.await;
}

#[tokio::test]
async fn http_gateway_allowed_visitor_waits_for_head() {
    let port = free_port().await;
    let access = policy_lock(&[]);
    let shutdown = Arc::new(Notify::new());
    let task = tokio::spawn(run_http_gw_listener(
        "127.0.0.1".to_string(),
        port,
        Arc::new(HttpGw::new(port)),
        access,
        Arc::clone(&shutdown),
    ));
    let client = connect_with_retry(port).await;
    read_stays_open(client).await;
    shutdown.notify_waiters();
    let _ = task.await;
}

#[tokio::test]
async fn https_gateway_denied_visitor_closed() {
    let port = free_port().await;
    let access = policy_lock(&["127.0.0.1/32"]);
    let shutdown = Arc::new(Notify::new());
    let task = tokio::spawn(run_https_gw_listener(
        "127.0.0.1".to_string(),
        port,
        Arc::new(HttpsGw::new(port)),
        access,
        Arc::clone(&shutdown),
    ));
    let client = connect_with_retry(port).await;
    read_closed_soon(client).await;
    shutdown.notify_waiters();
    let _ = task.await;
}

#[tokio::test]
async fn https_gateway_allowed_visitor_waits_for_client_hello() {
    let port = free_port().await;
    let access = policy_lock(&[]);
    let shutdown = Arc::new(Notify::new());
    let task = tokio::spawn(run_https_gw_listener(
        "127.0.0.1".to_string(),
        port,
        Arc::new(HttpsGw::new(port)),
        access,
        Arc::clone(&shutdown),
    ));
    let client = connect_with_retry(port).await;
    read_stays_open(client).await;
    shutdown.notify_waiters();
    let _ = task.await;
}

#[tokio::test]
async fn udp_forward_denied_datagram_dropped() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let counters = Arc::new(HookCounters::default());
    let hooks = test_hooks(
        Arc::new(|ip| ip == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        Arc::clone(&counters),
    );
    let (_read_tx, mut send_rx, task) =
        start_forward(Arc::clone(&sock), UdpForwardLimits::default(), hooks).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"hello", addr).await.unwrap();
    let got = tokio::time::timeout(Duration::from_millis(300), send_rx.recv()).await;
    assert!(got.is_err(), "denied datagram must not be forwarded");
    assert_eq!(counters.drops(UdpDropReason::Denied), 1);
    task.abort();
}

#[tokio::test]
async fn udp_forward_allowed_datagram_reaches_send_tx() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let counters = Arc::new(HookCounters::default());
    let hooks = test_hooks(Arc::new(|_| false), Arc::clone(&counters));
    let (_read_tx, mut send_rx, task) =
        start_forward(Arc::clone(&sock), UdpForwardLimits::default(), hooks).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"hello", addr).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), send_rx.recv()).await;
    let pkt = got
        .expect("allowed datagram must be forwarded")
        .expect("channel open");
    assert_eq!(pkt.content.as_slice(), b"hello");
    task.abort();
}

/// Counters behind the `UdpForwardHooks` of the #14 tests. The drop
/// counts are meaningful even where this VM blocks UDP sendto (the
/// hooks fire before any send), while the socket-level assertions
/// need CI.
#[derive(Default)]
struct HookCounters {
    drops: Mutex<HashMap<UdpDropReason, u64>>,
    delivered_packets: AtomicU64,
}

impl HookCounters {
    fn drops(&self, reason: UdpDropReason) -> u64 {
        *self.drops.lock().unwrap().get(&reason).unwrap_or(&0)
    }
}

fn test_hooks(
    is_denied: Arc<dyn Fn(IpAddr) -> bool + Send + Sync>,
    counters: Arc<HookCounters>,
) -> Arc<UdpForwardHooks> {
    let c1 = Arc::clone(&counters);
    let c2 = Arc::clone(&counters);
    Arc::new(UdpForwardHooks {
        is_denied,
        on_drop: Arc::new(move |reason| {
            *c1.drops.lock().unwrap().entry(reason).or_insert(0) += 1;
        }),
        on_delivered: Arc::new(move |_| {
            c2.delivered_packets.fetch_add(1, Ordering::SeqCst);
        }),
    })
}

async fn start_forward(
    sock: Arc<UdpSocket>,
    limits: UdpForwardLimits,
    hooks: Arc<UdpForwardHooks>,
) -> (
    mpsc::Sender<orbien_core::msg::UdpPacket>,
    mpsc::Receiver<orbien_core::msg::UdpPacket>,
    tokio::task::JoinHandle<()>,
) {
    let (read_tx, read_rx) = mpsc::channel(16);
    let (send_tx, send_rx) = mpsc::channel(16);
    let task = tokio::spawn(forward_user_conn(
        sock, read_rx, send_tx, 1500, limits, hooks, "test",
    ));
    (read_tx, send_rx, task)
}

#[tokio::test]
async fn udp_forward_reply_to_unknown_visitor_dropped() {
    // #14: a client must not make the server send to an address that
    // never sent a datagram to the tunnel.
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let counters = Arc::new(HookCounters::default());
    let hooks = test_hooks(Arc::new(|_| false), Arc::clone(&counters));
    let (read_tx, _send_rx, task) =
        start_forward(Arc::clone(&sock), UdpForwardLimits::default(), hooks).await;
    let victim = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let victim_addr = victim.local_addr().unwrap();
    let pkt = orbien_core::msg::UdpPacket::new(b"spoofed".to_vec(), Some(victim_addr));
    read_tx.send(pkt).await.unwrap();
    // The victim must receive nothing (and the drop is counted even
    // where the VM blocks UDP sendto).
    let got =
        tokio::time::timeout(Duration::from_millis(300), victim.recv_from(&mut [0u8; 64])).await;
    assert!(got.is_err(), "reply to an unknown visitor must be dropped");
    assert_eq!(counters.drops(UdpDropReason::NoVisitor), 1);
    task.abort();
}

#[tokio::test]
async fn udp_forward_known_visitor_reply_delivered() {
    // #14: the normal path — a visitor's datagram goes to the client,
    // and the client's reply comes back to that visitor.
    // CI-only: this VM blocks UDP sendto, so the reply never lands.
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let counters = Arc::new(HookCounters::default());
    let hooks = test_hooks(Arc::new(|_| false), Arc::clone(&counters));
    let (read_tx, mut send_rx, task) =
        start_forward(Arc::clone(&sock), UdpForwardLimits::default(), hooks).await;
    let visitor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    visitor.send_to(b"hello", addr).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), send_rx.recv()).await;
    let pkt = got
        .expect("visitor datagram must be forwarded")
        .expect("channel open");
    assert_eq!(pkt.content.as_slice(), b"hello");
    let reply = orbien_core::msg::UdpPacket::new(
        b"world".to_vec(),
        pkt.remote_addr.as_ref().and_then(|a| a.to_std()),
    );
    read_tx.send(reply).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), visitor.recv_from(&mut buf))
        .await
        .expect("reply must arrive")
        .unwrap();
    assert_eq!(&buf[..n], b"world");
    assert_eq!(counters.delivered_packets.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn udp_forward_session_cap_enforced() {
    // #14: with the default cap the visitor beyond the cap is dropped
    // and counted. CI-only: the VM blocks UDP sendto.
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let counters = Arc::new(HookCounters::default());
    let hooks = test_hooks(Arc::new(|_| false), Arc::clone(&counters));
    let (_read_tx, mut send_rx, task) = start_forward(
        Arc::clone(&sock),
        UdpForwardLimits {
            max_sessions: 2,
            per_source_pps: 0,
            per_tunnel_pps: 0,
        },
        hooks,
    )
    .await;
    let mut visitors = Vec::new();
    for _ in 0..3 {
        let v = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        v.send_to(b"hi", addr).await.unwrap();
        visitors.push(v);
    }
    let mut forwarded = 0;
    for _ in 0..3 {
        match tokio::time::timeout(Duration::from_millis(300), send_rx.recv()).await {
            Ok(Some(_)) => forwarded += 1,
            _ => break,
        }
    }
    assert_eq!(forwarded, 2, "only the first two visitors fit the cap");
    assert_eq!(counters.drops(UdpDropReason::SessionCap), 1);
    task.abort();
}

#[tokio::test]
async fn udp_forward_send_error_does_not_kill_writer() {
    // #14: a failed `send_to` (port 0) drops that datagram only; later
    // replies of other visitors are still delivered. CI-only: the VM
    // blocks UDP sendto.
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let counters = Arc::new(HookCounters::default());
    let hooks = test_hooks(Arc::new(|_| false), Arc::clone(&counters));
    let (read_tx, mut send_rx, task) =
        start_forward(Arc::clone(&sock), UdpForwardLimits::default(), hooks).await;
    let visitor = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let visitor_addr = visitor.local_addr().unwrap();
    visitor.send_to(b"hello", addr).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), send_rx.recv()).await;
    got.expect("visitor datagram must be forwarded")
        .expect("channel open");
    // Reply 1: port 0 cannot be sent to.
    let bad: SocketAddr = "127.0.0.1:0".parse().unwrap();
    read_tx
        .send(orbien_core::msg::UdpPacket::new(b"bad".to_vec(), Some(bad)))
        .await
        .unwrap();
    // Reply 2: the real visitor must still get its reply.
    read_tx
        .send(orbien_core::msg::UdpPacket::new(
            b"good".to_vec(),
            Some(visitor_addr),
        ))
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), visitor.recv_from(&mut buf))
        .await
        .expect("second reply must arrive after a failed send")
        .unwrap();
    assert_eq!(&buf[..n], b"good");
    assert_eq!(counters.drops(UdpDropReason::SendError), 1);
    task.abort();
}

#[tokio::test]
async fn udp_forward_truncated_datagram_dropped_and_counted() {
    // #14: a datagram larger than the receive buffer is dropped and
    // counted, not forwarded truncated. CI-only: the VM blocks UDP.
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let counters = Arc::new(HookCounters::default());
    let hooks = test_hooks(Arc::new(|_| false), Arc::clone(&counters));
    let (_read_tx, mut send_rx, task) =
        start_forward(Arc::clone(&sock), UdpForwardLimits::default(), hooks).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&vec![0u8; 2000], addr).await.unwrap();
    let got = tokio::time::timeout(Duration::from_millis(300), send_rx.recv()).await;
    assert!(got.is_err(), "oversized datagram must not be forwarded");
    assert_eq!(counters.drops(UdpDropReason::Truncated), 1);
    task.abort();
}

#[tokio::test]
async fn udp_forward_rate_limited() {
    // #14: per-source packet rate limits drop excess packets and count
    // them. CI-only: the VM blocks UDP sendto.
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let counters = Arc::new(HookCounters::default());
    let hooks = test_hooks(Arc::new(|_| false), Arc::clone(&counters));
    let (_read_tx, mut send_rx, task) = start_forward(
        Arc::clone(&sock),
        UdpForwardLimits {
            max_sessions: 10,
            per_source_pps: 2,
            per_tunnel_pps: 0,
        },
        hooks,
    )
    .await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for _ in 0..3 {
        client.send_to(b"hi", addr).await.unwrap();
    }
    let mut forwarded = 0;
    for _ in 0..3 {
        match tokio::time::timeout(Duration::from_millis(300), send_rx.recv()).await {
            Ok(Some(_)) => forwarded += 1,
            _ => break,
        }
    }
    assert_eq!(forwarded, 2, "third packet exceeds the 2 pps limit");
    assert_eq!(counters.drops(UdpDropReason::RateLimited), 1);
    task.abort();
}

#[tokio::test]
#[cfg(windows)]
async fn udp_forward_recv_reset_continues() {
    // #14: on Windows a UDP socket reports connection-reset on receive
    // after a send to an unreachable port; the receive loop must keep
    // serving visitors afterwards.
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let counters = Arc::new(HookCounters::default());
    let hooks = test_hooks(Arc::new(|_| false), Arc::clone(&counters));
    let (_read_tx, mut send_rx, task) = start_forward(
        Arc::clone(&sock),
        UdpForwardLimits {
            max_sessions: 10,
            per_source_pps: 0,
            per_tunnel_pps: 0,
        },
        hooks,
    )
    .await;
    // Trigger ICMP port-unreachable from the tunnel socket.
    let closed: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let _ = sock.send_to(b"x", closed).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut ok = false;
    for _ in 0..20 {
        client.send_to(b"hello", addr).await.unwrap();
        if tokio::time::timeout(Duration::from_millis(100), send_rx.recv())
            .await
            .is_ok()
        {
            ok = true;
            break;
        }
    }
    assert!(ok, "receive loop must survive a connection-reset error");
    task.abort();
}
