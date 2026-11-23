//! Criterion benchmarks for the orbien-core message codec.
//!
//! These establish a performance baseline for the hot path of the control
//! protocol: serializing a `Message` to bytes and parsing it back. Run with:
//!
//! ```shell
//! cargo bench -p orbien-core
//! ```

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use orbien_core::msg::{read_msg, write_msg, Login, Message, Ping, UdpPacket};
use tokio::io::{duplex, DuplexStream};

/// Build a representative `Message` of the given kind.
fn sample_message(kind: &str) -> Message {
    match kind {
        "login" => Message::Login(Login {
            version: "0.1.0".into(),
            hostname: "bench-host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            user: "bench-user".into(),
            timestamp: 0,
            session_id: "bench-session".into(),
            pool_count: 0,
            resume_proof: String::new(),
            challenge_response: String::new(),
            client_nonce: String::new(),
            capabilities: vec![],
        }),
        "ping" => Message::Ping(Ping::default()),
        "udp" => Message::UdpPacket(UdpPacket::new(vec![0xAB; 512], None)),
        other => panic!("unknown sample kind {other}"),
    }
}

/// Drive a single write+read roundtrip over an in-memory duplex pair.
async fn roundtrip_once(msg: &Message) {
    let (mut a, mut b): (DuplexStream, DuplexStream) = duplex(8192);
    write_msg(&mut a, msg).await.unwrap();
    let _ = read_msg(&mut b).await.unwrap();
}

fn bench_roundtrip(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let mut group = c.benchmark_group("msg_codec_roundtrip");
    for kind in ["login", "ping", "udp"] {
        let msg = sample_message(kind);
        group.bench_with_input(BenchmarkId::new("write_read", kind), &msg, |b, msg| {
            b.to_async(&rt).iter(|| roundtrip_once(black_box(msg)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_roundtrip);
criterion_main!(benches);
