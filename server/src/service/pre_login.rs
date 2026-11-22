//! Pre-login connection gate (#13).
//!
//! Bounds how many connections may sit unauthenticated, globally and per
//! source IP, so a flood of idle connections cannot exhaust file
//! descriptors or tasks. One permit is held per *physical* connection
//! (one TCP/KCP/QUIC connection, one yamux session); it is released the
//! moment a Login or a proven NewDataConn succeeds, and dropped
//! automatically when the connection ends for any other reason.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub struct PreLoginGate {
    max_conns: usize,
    max_per_ip: usize,
    total: AtomicUsize,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
}

/// RAII permit: dropping it frees the global and per-IP slots.
pub struct PreLoginPermit {
    gate: Arc<PreLoginGate>,
    ip: IpAddr,
}

/// Shared slot holding the permit of one physical connection. The first
/// stream that logs in takes it (releasing the slot); everyone else finds
/// it empty. The slot is also how the pre-login deadline watchdog knows
/// the connection authenticated: `None` means logged in.
pub type PreLoginSlot = Arc<tokio::sync::Mutex<Option<PreLoginPermit>>>;

pub fn new_slot(permit: PreLoginPermit) -> PreLoginSlot {
    Arc::new(tokio::sync::Mutex::new(Some(permit)))
}

impl PreLoginGate {
    pub fn new(max_conns: usize, max_per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            max_conns,
            max_per_ip,
            total: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
        })
    }

    /// Take a permit for `ip`, or `None` when the global or per-IP cap
    /// is already reached. The check and the increment are one critical
    /// section, so the caps can never be overshot.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PreLoginPermit> {
        let mut per_ip = self.per_ip.lock().expect("pre-login gate lock");
        if self.total.load(Ordering::SeqCst) >= self.max_conns {
            return None;
        }
        let n = per_ip.get(&ip).copied().unwrap_or(0);
        if n >= self.max_per_ip {
            return None;
        }
        self.total.fetch_add(1, Ordering::SeqCst);
        per_ip.insert(ip, n + 1);
        Some(PreLoginPermit {
            gate: Arc::clone(self),
            ip,
        })
    }

    #[cfg(test)]
    pub fn total(&self) -> usize {
        self.total.load(Ordering::SeqCst)
    }
}

impl Drop for PreLoginPermit {
    fn drop(&mut self) {
        self.gate.total.fetch_sub(1, Ordering::SeqCst);
        let mut per_ip = self.gate.per_ip.lock().expect("pre-login gate lock");
        if let Some(n) = per_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                per_ip.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
    }

    #[test]
    fn global_cap_enforced_and_released_on_drop() {
        let gate = PreLoginGate::new(2, 10);
        let a = gate.try_acquire(ip(1)).expect("first");
        let _b = gate.try_acquire(ip(2)).expect("second");
        assert!(gate.try_acquire(ip(3)).is_none(), "third over global cap");
        assert_eq!(gate.total(), 2);
        drop(a);
        assert_eq!(gate.total(), 1);
        assert!(gate.try_acquire(ip(3)).is_some(), "slot freed by drop");
    }

    #[test]
    fn per_ip_cap_is_independent_of_global() {
        let gate = PreLoginGate::new(10, 2);
        let _a = gate.try_acquire(ip(1)).expect("first from ip1");
        let _b = gate.try_acquire(ip(1)).expect("second from ip1");
        assert!(gate.try_acquire(ip(1)).is_none(), "third from same ip");
        assert!(gate.try_acquire(ip(2)).is_some(), "other ip unaffected");
    }

    #[test]
    fn slot_take_marks_logged_in() {
        let gate = PreLoginGate::new(1, 1);
        let permit = gate.try_acquire(ip(1)).expect("permit");
        let slot = new_slot(permit);
        assert_eq!(gate.total(), 1);
        // Simulate the first stream logging in: taking the permit frees it.
        let taken = slot.try_lock().unwrap().take();
        assert!(taken.is_some());
        drop(taken);
        assert_eq!(gate.total(), 0);
        assert!(gate.try_acquire(ip(1)).is_some(), "cap freed after login");
    }
}
