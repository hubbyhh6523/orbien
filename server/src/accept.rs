//! Accept-error backoff (#13).
//!
//! A listener that hits a resource error (`EMFILE`, `ENFILE`, `ENOBUFS`,
//! `ENOMEM`) or a transient one (`ECONNABORTED`, `EINTR`) must not take
//! the whole server down with it. Instead: log at most once per 10 s
//! per listener, wait with exponential backoff (10 ms, doubling, capped
//! at 1 s), and try again. The loops that use this have explicit
//! shutdown paths (a `Notify` or a closed flag), so there is no
//! "listener closed" error to stop on — every accept error retries.

use crate::ratelimit::LogThrottle;
use anyhow::Error;
use std::io;
use std::time::Duration;
use tokio::time::sleep;

const LOG_INTERVAL: Duration = Duration::from_secs(10);
const BACKOFF_START: Duration = Duration::from_millis(10);
const BACKOFF_MAX: Duration = Duration::from_secs(1);

pub struct AcceptBackoff {
    delay: Duration,
    throttle: LogThrottle,
}

impl AcceptBackoff {
    pub fn new() -> Self {
        Self {
            delay: BACKOFF_START,
            throttle: LogThrottle::new(LOG_INTERVAL),
        }
    }

    /// Accept succeeded: the next error starts again at 10 ms.
    pub fn reset(&mut self) {
        self.delay = BACKOFF_START;
    }

    /// Classify the error, log it at most once per 10 s, sleep the
    /// current backoff, and grow the delay for the next failure.
    pub async fn on_error(&mut self, err: &Error) {
        if self.throttle.should_log() {
            if io_error(err).map(is_resource_error).unwrap_or(false) {
                tracing::warn!(error = %err, "accept failed (resource); retrying with backoff");
            } else {
                tracing::error!(error = %err, "accept failed; retrying with backoff");
            }
        }
        sleep(self.delay).await;
        self.delay = (self.delay * 2).min(BACKOFF_MAX);
    }
}

fn io_error(err: &Error) -> Option<&io::Error> {
    err.chain().find_map(|e| e.downcast_ref::<io::Error>())
}

/// Resource exhaustion and transient aborts: the listener is fine, the
/// machine is briefly out of something. Anything else (e.g. a bad file
/// descriptor) is logged as an error but still retried.
fn is_resource_error(err: &io::Error) -> bool {
    match err.raw_os_error() {
        // ENOMEM, ENFILE, EMFILE, ENOBUFS
        Some(12) | Some(23) | Some(24) | Some(105) => true,
        _ => matches!(
            err.kind(),
            io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn classifies_resource_errors() {
        assert!(is_resource_error(&io::Error::from_raw_os_error(24))); // EMFILE
        assert!(is_resource_error(&io::Error::from_raw_os_error(23))); // ENFILE
        assert!(is_resource_error(&io::Error::from_raw_os_error(12))); // ENOMEM
        assert!(is_resource_error(&io::Error::from_raw_os_error(105))); // ENOBUFS
        assert!(is_resource_error(&io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "aborted"
        )));
        assert!(!is_resource_error(&io::Error::from_raw_os_error(22))); // EINVAL
        assert!(!is_resource_error(&io::Error::new(
            io::ErrorKind::NotFound,
            "gone"
        )));
    }

    #[test]
    fn io_error_found_through_anyhow_context() {
        let inner = io::Error::from_raw_os_error(24);
        let err = anyhow::Error::new(inner).context("kcp accept");
        assert_eq!(io_error(&err).unwrap().raw_os_error(), Some(24));
        let plain = anyhow::anyhow!("no io inside");
        assert!(io_error(&plain).is_none());
    }

    /// Backoff grows 10 ms, 20 ms, 40 ms… and `reset` restores 10 ms.
    /// Bounds are loose on purpose: CI scheduling jitter must not fail it.
    #[tokio::test]
    async fn backoff_grows_and_resets() {
        let mut b = AcceptBackoff::new();
        let err = anyhow::anyhow!("boom");
        let t0 = Instant::now();
        b.on_error(&err).await;
        b.on_error(&err).await;
        assert!(t0.elapsed() >= Duration::from_millis(30));
        assert!(t0.elapsed() < Duration::from_secs(5));
        b.reset();
        let t1 = Instant::now();
        b.on_error(&err).await;
        assert!(t1.elapsed() >= Duration::from_millis(10));
        assert!(t1.elapsed() < Duration::from_secs(5));
    }
}
