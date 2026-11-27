//! #14: the client's UDP forwarder must cap its sockets/tasks and must
//! work with an IPv6 local service.
//!
//! CI-only: this VM blocks UDP sendto (even loopback), so these tests
//! fail locally with no packets delivered and are verified by CI.

use orbien_core::msg::{Message, UdpPacket};
use orbien_core::udp::forwarder;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// A UDP echo server that records the distinct source addresses it sees.
struct EchoServer {
    addr: SocketAddr,
    sources: Arc<tokio::sync::Mutex<HashSet<SocketAddr>>>,
    task: tokio::task::JoinHandle<()>,
}

impl EchoServer {
    async fn bind(bind: &str) -> Self {
        let sock = Arc::new(UdpSocket::bind(bind).await.unwrap());
        let addr = sock.local_addr().unwrap();
        let sources = Arc::new(tokio::sync::Mutex::new(HashSet::new()));
        let sources_w = Arc::clone(&sources);
        let task = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((n, peer)) => {
                        sources_w.lock().await.insert(peer);
                        let _ = sock.send_to(&buf[..n], peer).await;
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            addr,
            sources,
            task,
        }
    }

    async fn source_count(&self) -> usize {
        self.sources.lock().await.len()
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn forwarder_caps_sockets_per_visitor() {
    let echo = EchoServer::bind("127.0.0.1:0").await;
    let (read_tx, read_rx) = mpsc::channel::<UdpPacket>(64);
    let (send_tx, mut send_rx) = mpsc::channel::<Message>(64);
    let task = tokio::spawn(forwarder(echo.addr, read_rx, send_tx, 1500, None, 2));
    // Three distinct visitors; the cap is two sockets.
    for i in 0..3u16 {
        let remote: SocketAddr = format!("127.0.0.1:{}", 40000 + i).parse().unwrap();
        read_tx
            .send(UdpPacket::new(b"ping".to_vec(), Some(remote)))
            .await
            .unwrap();
    }
    // The echo server must see exactly two distinct forwarder sockets.
    let mut count = 0;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        count = echo.source_count().await;
        if count >= 2 {
            break;
        }
    }
    assert_eq!(count, 2, "forwarder must open at most its cap of sockets");
    // The two allowed visitors get echo replies back.
    let mut replies = 0;
    for _ in 0..2 {
        if tokio::time::timeout(Duration::from_secs(2), send_rx.recv())
            .await
            .is_ok()
        {
            replies += 1;
        }
    }
    assert_eq!(replies, 2);
    drop(read_tx);
    task.abort();
}

#[tokio::test]
async fn forwarder_works_with_ipv6_local_service() {
    let echo = EchoServer::bind("[::1]:0").await;
    assert!(echo.addr.is_ipv6(), "echo server must be IPv6");
    let (read_tx, read_rx) = mpsc::channel::<UdpPacket>(64);
    let (send_tx, mut send_rx) = mpsc::channel::<Message>(64);
    let task = tokio::spawn(forwarder(echo.addr, read_rx, send_tx, 1500, None, 16));
    let remote: SocketAddr = "127.0.0.1:41000".parse().unwrap();
    read_tx
        .send(UdpPacket::new(b"ping6".to_vec(), Some(remote)))
        .await
        .unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), send_rx.recv()).await;
    let msg = got
        .expect("IPv6 local service must reply")
        .expect("channel open");
    match msg {
        Message::UdpPacket(pkt) => assert_eq!(pkt.content.as_slice(), b"ping6"),
        other => panic!("unexpected message: {:?}", other.type_byte()),
    }
    drop(read_tx);
    task.abort();
}
