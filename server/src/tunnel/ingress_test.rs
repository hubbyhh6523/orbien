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
use orbien_core::udp::forward_user_conn;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
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
    let (_read_tx, read_rx) = mpsc::channel(16);
    let (send_tx, mut send_rx) = mpsc::channel(16);
    let is_denied: Arc<dyn Fn(IpAddr) -> bool + Send + Sync> =
        Arc::new(|ip| ip == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    let task = tokio::spawn(forward_user_conn(
        Arc::clone(&sock),
        read_rx,
        send_tx,
        1500,
        10,
        is_denied,
    ));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"hello", addr).await.unwrap();
    let got = tokio::time::timeout(Duration::from_millis(300), send_rx.recv()).await;
    assert!(got.is_err(), "denied datagram must not be forwarded");
    task.abort();
}

#[tokio::test]
async fn udp_forward_allowed_datagram_reaches_send_tx() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    let (_read_tx, read_rx) = mpsc::channel(16);
    let (send_tx, mut send_rx) = mpsc::channel(16);
    let is_denied: Arc<dyn Fn(IpAddr) -> bool + Send + Sync> = Arc::new(|_| false);
    let task = tokio::spawn(forward_user_conn(
        Arc::clone(&sock),
        read_rx,
        send_tx,
        1500,
        10,
        is_denied,
    ));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"hello", addr).await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), send_rx.recv()).await;
    let pkt = got.expect("allowed datagram must be forwarded").expect("channel open");
    assert_eq!(pkt.content.as_slice(), b"hello");
    task.abort();
}
