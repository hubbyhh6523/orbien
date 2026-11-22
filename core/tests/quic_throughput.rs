//! Minimal loopback QUIC throughput smoke (#13).
//!
//! Transfers 32 MiB over one QUIC stream with the old windows
//! (100_000 streams, 32/64/64 MiB) and with the new defaults
//! (1_000 streams, 1/8/8 MiB) and prints both timings, so a regression
//! from the lowered defaults shows up here and in CI.
//!
//! The sender paces itself (10 ms per MiB): without pacing, the initial
//! burst on Windows loopback drops UDP datagrams, the receiver's
//! reassembly buffer overflows quinn's 1024-chunk cap ("too many gaps
//! in stream buffer") and the peer aborts the connection. 32 MiB is
//! still 32x the new 1 MiB stream window, so the window comparison
//! still shows.
//!
//! Each transfer prints its label, bytes written/received, elapsed
//! time, and the connection's path stats (RTT, congestion window,
//! packets sent/lost, congestion events), so a CI failure shows
//! exactly which leg died, how far it got, and whether the path was
//! actually losing packets — instead of just the bare error.
//!
//! The sandbox blocks UDP sendto (EPERM, even loopback), so the test
//! probes for that first and skips cleanly with a message instead of
//! failing; run it on a host with working UDP (or CI) for real numbers.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use orbien_core::config::QuicOptions;
use orbien_core::transport::{
    build_client_endpoint, build_server_endpoint, generate_self_signed_cert,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const TRANSFER_BYTES: usize = 32 * 1024 * 1024;
/// Pause the sender this long per MiB written, so bursts stay small
/// enough for the receiver's UDP socket buffer to absorb.
const PACE_PER_MIB: Duration = Duration::from_millis(10);

/// True when this machine cannot send UDP at all (sandbox EPERM).
fn udp_blocked() -> bool {
    let Ok(sock) = std::net::UdpSocket::bind("127.0.0.1:0") else {
        return true;
    };
    matches!(
        sock.send_to(b"ping", "127.0.0.1:9"),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied
    )
}

fn pem(kind: &str, der: &[u8]) -> String {
    let b64 = B64.encode(der);
    let mut out = format!("-----BEGIN {kind}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {kind}-----\n"));
    out
}

fn write_pem_files(dir: &Path) -> Result<(String, String)> {
    let gen = generate_self_signed_cert("localhost")?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, pem("CERTIFICATE", gen.certs[0].as_ref()))?;
    std::fs::write(&key_path, pem("PRIVATE KEY", gen.key.secret_pkcs8_der()))?;
    Ok((
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    ))
}

/// One leg of the smoke test. Prints its label, byte counts, elapsed
/// time, and the connection's path stats on success and on failure,
/// so a CI failure names the dying leg and shows whether the path was
/// actually losing packets.
async fn transfer(quic: &QuicOptions, cert: &str, key: &str, label: &str) -> Result<Duration> {
    eprintln!(
        "[{label}] starting {} MiB transfer",
        TRANSFER_BYTES / (1024 * 1024)
    );
    let server = build_server_endpoint("127.0.0.1:0".parse()?, quic, cert, key, "")
        .with_context(|| format!("[{label}] server endpoint"))?;
    let addr = server.local_addr()?;
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.ok_or_else(|| anyhow!("no incoming"))?;
        let conn = incoming.await.context("server handshake")?;
        let (_send, mut recv) = conn.accept_bi().await.context("accept_bi")?;
        let mut total: u64 = 0;
        let mut buf = vec![0u8; 64 * 1024];
        while let Some(n) = recv.read(&mut buf).await.context("server read")? {
            total += n as u64;
        }
        Ok::<u64, anyhow::Error>(total)
    });

    let client = build_client_endpoint(quic, "", "", "", None)
        .with_context(|| format!("[{label}] client endpoint"))?;
    let start = Instant::now();
    let conn = client
        .connect(addr, "localhost")
        .with_context(|| format!("[{label}] client connect"))?
        .await
        .with_context(|| format!("[{label}] client handshake"))?;
    let (mut send, _recv) = conn
        .open_bi()
        .await
        .with_context(|| format!("[{label}] open_bi"))?;
    let chunk = vec![0xabu8; 64 * 1024];
    let mut left = TRANSFER_BYTES;
    let mut written: u64 = 0;
    let mut since_pace = 0usize;
    while left > 0 {
        let n = left.min(chunk.len());
        if let Err(e) = send.write_all(&chunk[..n]).await {
            let s = conn.stats();
            eprintln!(
                "[{label}] client write failed after {written} bytes: {e:?}; \
                 path stats: rtt={:?} cwnd={} sent_packets={} lost_packets={} lost_bytes={} congestion_events={}",
                s.path.rtt, s.path.cwnd, s.path.sent_packets, s.path.lost_packets,
                s.path.lost_bytes, s.path.congestion_events,
            );
            return Err(e).context(format!("[{label}] client write after {written} bytes"));
        }
        left -= n;
        written += n as u64;
        since_pace += n;
        if since_pace >= 1024 * 1024 {
            since_pace = 0;
            tokio::time::sleep(PACE_PER_MIB).await;
        }
    }
    send.finish()
        .with_context(|| format!("[{label}] client finish after {written} bytes"))?;
    let elapsed = start.elapsed();
    let total = server_task
        .await
        .with_context(|| format!("[{label}] server task after {written} bytes"))?
        .with_context(|| format!("[{label}] server transfer after {written} bytes"))?;
    let s = conn.stats();
    eprintln!(
        "[{label}] done: wrote {written}, server got {total}, elapsed {elapsed:?}; \
         path stats: rtt={:?} cwnd={} sent_packets={} lost_packets={} lost_bytes={} congestion_events={}",
        s.path.rtt, s.path.cwnd, s.path.sent_packets, s.path.lost_packets,
        s.path.lost_bytes, s.path.congestion_events,
    );
    assert_eq!(
        total, TRANSFER_BYTES as u64,
        "[{label}] server received short transfer"
    );
    Ok(elapsed)
}

fn old_defaults() -> QuicOptions {
    QuicOptions {
        max_incoming_streams: 100_000,
        stream_recv_window: 32 * 1024 * 1024,
        conn_recv_window: 64 * 1024 * 1024,
        send_window: 64 * 1024 * 1024,
        ..Default::default()
    }
}

#[tokio::test]
async fn quic_throughput_old_vs_new_defaults() {
    if udp_blocked() {
        eprintln!("SKIP: UDP sendto blocked on this host (EPERM); run on a host with UDP or in CI");
        return;
    }
    let dir: PathBuf = std::env::temp_dir()
        .join(format!("orbien-quic-smoke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = write_pem_files(&dir).unwrap();
    let run = async {
        // Windows loopback cannot reassemble the old leg: its 32 MiB
        // window lets the client flood ~27k packets and the server's
        // reassembly buffer overflows quinn's 1024-chunk cap, aborting
        // the connection (seen twice on Windows CI; the client had
        // written all 32 MiB when the server died). The new leg's 1 MiB
        // window caps in-flight data at ~850 packets, so it cannot hit
        // that cap. The old-vs-new comparison still runs on Linux CI.
        let old = if cfg!(target_os = "windows") {
            None
        } else {
            Some(
                tokio::time::timeout(
                    Duration::from_secs(120),
                    transfer(&old_defaults(), &cert, &key, "old"),
                )
                .await
                .context("old-defaults transfer timed out")??,
            )
        };
        let new = tokio::time::timeout(
            Duration::from_secs(120),
            transfer(&QuicOptions::default(), &cert, &key, "new"),
        )
        .await
        .context("new-defaults transfer timed out")??;
        match old {
            Some(old) => println!(
                "QUIC loopback {} MiB: old defaults {old:?}, new defaults {new:?}",
                TRANSFER_BYTES / (1024 * 1024)
            ),
            None => println!(
                "QUIC loopback {} MiB: new defaults {new:?} (old leg skipped on Windows)",
                TRANSFER_BYTES / (1024 * 1024)
            ),
        }
        Ok::<(), anyhow::Error>(())
    };
    let result = run.await;
    let _ = std::fs::remove_dir_all(&dir);
    result.unwrap();
}
