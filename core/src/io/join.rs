use super::counting::{ByteCounter, CountingStream};
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite};
use tokio::time::sleep;

// Increased from 256KB to 512KB for better throughput on high-bandwidth links.
// Each active connection uses 2 × JOIN_BUF bytes; scale down if memory is tight.
const JOIN_BUF: usize = 512 * 1024;

/// Bidirectional copy that returns `(a_to_b, b_to_a)` on success, or
/// propagates the first I/O error encountered.
pub async fn join<A, B>(a: A, b: B) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (a_to_b, b_to_a, err) = join_counted(a, b).await;
    if let Some(e) = err {
        return Err(e);
    }
    Ok((a_to_b, b_to_a))
}

/// Like [`join`] but never fails: returns byte counts regardless of any error.
/// Use this when the caller genuinely does not care about mid-stream failures
/// (e.g. UDP splice where partial delivery is expected).
#[allow(dead_code)]
pub async fn join_discard_err<A, B>(a: A, b: B) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (sent, recv, _err) = join_counted(a, b).await;
    (sent, recv)
}

/// Full result: byte counters **and** the error (if any).
pub async fn join_counted<A, B>(a: A, b: B) -> (u64, u64, Option<std::io::Error>)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    join_counted_inner(a, b, None).await
}

/// Like [`join_counted`], but aborts both sides with [`std::io::ErrorKind::TimedOut`]
/// once no bytes have flowed in either direction for `idle_timeout`. The
/// watchdog checks the counters every second, so the abort lands within
/// `idle_timeout + 1s` of the last byte.
pub async fn join_counted_idle<A, B>(
    a: A,
    b: B,
    idle_timeout: Duration,
) -> (u64, u64, Option<std::io::Error>)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    join_counted_inner(a, b, Some(idle_timeout)).await
}

async fn join_counted_inner<A, B>(
    a: A,
    b: B,
    idle_timeout: Option<Duration>,
) -> (u64, u64, Option<std::io::Error>)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let ca = ByteCounter::new();
    let cb = ByteCounter::new();
    let mut a = CountingStream::new(a, ca.clone());
    let mut b = CountingStream::new(b, cb.clone());

    let copy = copy_bidirectional_with_sizes(&mut a, &mut b, JOIN_BUF, JOIN_BUF);
    tokio::pin!(copy);
    let err = match idle_timeout {
        None => copy.await.err(),
        Some(idle) => {
            let mut last_total = 0u64;
            let mut last_progress = Instant::now();
            loop {
                tokio::select! {
                    r = &mut copy => break r.err(),
                    _ = sleep(Duration::from_secs(1)) => {
                        // Every byte is read once from its source side,
                        // so read counters alone cover both directions.
                        let total = ca.read() + cb.read();
                        if total != last_total {
                            last_total = total;
                            last_progress = Instant::now();
                        } else if last_progress.elapsed() >= idle {
                            // Dropping `copy` (and the counting streams
                            // with it) closes both sides.
                            break Some(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "idle timeout",
                            ));
                        }
                    }
                }
            }
        }
    };

    let a_to_b = ca.read();
    let b_to_a = cb.read();
    (a_to_b, b_to_a, err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    /// No bytes for the idle window: the join aborts with TimedOut.
    /// The 1 s watchdog tick means the abort lands up to 1 s late.
    #[tokio::test]
    async fn idle_join_aborts_after_silence() {
        let (a, b) = duplex(64);
        let t0 = Instant::now();
        let (sent, received, err) =
            join_counted_idle(a, b, Duration::from_millis(300)).await;
        let elapsed = t0.elapsed();
        assert_eq!(sent, 0);
        assert_eq!(received, 0);
        assert_eq!(err.map(|e| e.kind()), Some(std::io::ErrorKind::TimedOut));
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
    }

    /// Bytes keep flowing inside the window: the join ends normally
    /// when a side closes, not with a timeout.
    #[tokio::test]
    async fn idle_join_survives_steady_traffic() {
        let (a, mut a_peer) = duplex(64);
        let (b, mut b_peer) = duplex(64);
        let joined = tokio::spawn(async move {
            join_counted_idle(a, b, Duration::from_millis(300)).await
        });
        let writer = tokio::spawn(async move {
            for _ in 0..5 {
                a_peer.write_all(b"x").await.unwrap();
                sleep(Duration::from_millis(100)).await;
            }
            drop(a_peer);
        });
        // Drain the far side so the join never blocks on it.
        let mut buf = [0u8; 16];
        let mut got = 0;
        while got < 5 {
            use tokio::io::AsyncReadExt;
            let n = b_peer.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got += n;
        }
        drop(b_peer);
        writer.await.unwrap();
        let (sent, _, err) = joined.await.unwrap();
        assert_eq!(sent, 5);
        assert!(err.is_none(), "steady traffic must not time out: {err:?}");
    }
}
