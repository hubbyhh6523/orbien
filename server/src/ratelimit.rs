//! A tiny "log at most once per interval" throttle, shared by the
//! accept-error logs, the control read loop and the P2P handler. One
//! instance per log site: the first call in an interval passes, the
//! rest are dropped until the interval has elapsed.
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct LogThrottle {
    last: Mutex<Instant>,
    interval: Duration,
}

impl LogThrottle {
    pub fn new(interval: Duration) -> Self {
        Self {
            // Start far in the past so the first call always passes.
            last: Mutex::new(Instant::now() - interval - Duration::from_secs(1)),
            interval,
        }
    }

    /// True if the caller may log now; false if a log already went out
    /// within this interval.
    pub fn should_log(&self) -> bool {
        let mut last = self.last.lock().expect("log throttle lock");
        let now = Instant::now();
        if now.duration_since(*last) >= self.interval {
            *last = now;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_passes_once_per_interval() {
        let t = LogThrottle::new(Duration::from_secs(10));
        assert!(t.should_log());
        for _ in 0..100 {
            assert!(!t.should_log());
        }
    }

    #[test]
    fn throttle_passes_again_after_interval() {
        let t = LogThrottle::new(Duration::from_millis(50));
        assert!(t.should_log());
        assert!(!t.should_log());
        std::thread::sleep(Duration::from_millis(60));
        assert!(t.should_log());
    }
}
