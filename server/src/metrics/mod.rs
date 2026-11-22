mod counter;
mod date_counter;
mod hour_counter;
mod mem;
mod traits;
#[cfg(test)]
mod mem_test;

pub use mem::{MemMetrics, TrafficWindow, TunnelTrafficHistory};
pub use traits::ServerMetrics;

pub const RESERVE_DAYS: usize = 7;
pub const RESERVE_HOURS: usize = 24;

/// Joins an ingress stream with a data stream, records the traffic,
/// and aborts both sides once no bytes have flowed for `idle_timeout`.
/// `None` disables the idle watchdog; a `TimedOut` abort is counted as
/// an `idle_timeout` rejection.
pub async fn join_and_record_idle<A, B>(
    metrics: &std::sync::Arc<MemMetrics>,
    name: &str,
    tunnel_type: &str,
    ingress: A,
    data: B,
    idle_timeout: Option<std::time::Duration>,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let _guard = metrics.track_connection(name, tunnel_type);
    let (to_data, from_data, err) = match idle_timeout {
        Some(idle) => orbien_core::io::join_counted_idle(ingress, data, idle).await,
        None => orbien_core::io::join_counted(ingress, data).await,
    };
    metrics.add_traffic_in(name, tunnel_type, to_data);
    metrics.add_traffic_out(name, tunnel_type, from_data);
    match err {
        None => Ok((to_data, from_data)),
        Some(e) if is_benign_close(&e) => Ok((to_data, from_data)),
        Some(e) => {
            if e.kind() == std::io::ErrorKind::TimedOut {
                metrics.inc_limit_reject("idle_timeout");
            }
            Err(e)
        }
    }
}

fn is_benign_close(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::UnexpectedEof
    )
}
