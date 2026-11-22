#![cfg(test)]
//! Unit tests for MemMetrics — traffic accounting, connection tracking,
//! per-tunnel and server-wide snapshots, and history windows.

use super::mem::{MemMetrics, TrafficWindow};
use crate::metrics::traits::ServerMetrics;

// ── helpers ───────────────────────────────────────────────────────────────────

fn make() -> std::sync::Arc<MemMetrics> {
    MemMetrics::new()
}

// ── server snapshot ───────────────────────────────────────────────────────────

#[test]
fn server_snapshot_starts_empty() {
    let m = make();
    let s = m.server_snapshot();
    assert_eq!(s.active_connections, 0);
    assert_eq!(s.client_counts, 0);
    assert_eq!(s.total_client_counts, 0);
    assert_eq!(s.total_traffic_in, 0);
    assert_eq!(s.total_traffic_out, 0);
    assert!(s.tunnel_type_counts.is_empty());
    assert!(s.limit_rejections.is_empty());
}

// ── limit rejection counters (#13) ────────────────────────────────────────────

#[test]
fn limit_rejections_count_by_reason() {
    let m = make();
    m.inc_limit_reject("pre_login_cap");
    m.inc_limit_reject("pre_login_cap");
    m.inc_limit_reject("waiting_visitors");
    let s = m.server_snapshot();
    assert_eq!(s.limit_rejections.get("pre_login_cap"), Some(&2));
    assert_eq!(s.limit_rejections.get("waiting_visitors"), Some(&1));
    assert_eq!(s.limit_rejections.get("idle_timeout"), None);
}

#[test]
fn new_client_increments_counts() {
    let m = make();
    m.new_client("sess-1");
    m.new_client("sess-2");
    let s = m.server_snapshot();
    assert_eq!(s.client_counts, 2);
    assert_eq!(s.total_client_counts, 2);
}

#[test]
fn close_client_decrements_online_count() {
    let m = make();
    m.new_client("s1");
    m.new_client("s2");
    m.close_client();
    let s = m.server_snapshot();
    assert_eq!(s.client_counts, 1);
    // total_client_counts (unique set) is unchanged by close
    assert_eq!(s.total_client_counts, 2);
}

#[test]
fn duplicate_session_id_not_double_counted_in_seen_set() {
    let m = make();
    m.new_client("dup");
    m.new_client("dup");
    // online counter increments twice, but unique set stays 1
    assert_eq!(m.server_snapshot().client_counts, 2);
    assert_eq!(m.server_snapshot().total_client_counts, 1);
}

// ── tunnel registration ───────────────────────────────────────────────────────

#[test]
fn new_tunnel_appears_in_type_counts() {
    let m = make();
    m.new_tunnel("web", "http", "alice", "s1");
    m.new_tunnel("api", "tcp", "bob", "s2");
    let s = m.server_snapshot();
    assert_eq!(s.tunnel_type_counts.get("http"), Some(&1));
    assert_eq!(s.tunnel_type_counts.get("tcp"), Some(&1));
}

#[test]
fn close_tunnel_removes_from_type_counts() {
    let m = make();
    m.new_tunnel("t1", "tcp", "user", "s1");
    m.close_tunnel("t1", "tcp");
    let s = m.server_snapshot();
    // counter dropped to 0 → should not appear in the map
    assert_eq!(s.tunnel_type_counts.get("tcp"), None);
}

// ── traffic accounting ────────────────────────────────────────────────────────

#[test]
fn add_traffic_accumulates_per_tunnel_and_server() {
    let m = make();
    m.new_tunnel("svc", "tcp", "u", "s");
    m.add_traffic_in("svc", "tcp", 1024);
    m.add_traffic_out("svc", "tcp", 512);

    let snap = m.tunnel_snapshot("svc").expect("tunnel must exist");
    assert_eq!(snap.today_traffic_in, 1024);
    assert_eq!(snap.today_traffic_out, 512);

    let srv = m.server_snapshot();
    assert_eq!(srv.total_traffic_in, 1024);
    assert_eq!(srv.total_traffic_out, 512);
}

#[test]
fn zero_byte_traffic_is_ignored() {
    let m = make();
    m.new_tunnel("t", "tcp", "u", "s");
    m.add_traffic_in("t", "tcp", 0);
    m.add_traffic_out("t", "tcp", 0);
    let snap = m.tunnel_snapshot("t").unwrap();
    assert_eq!(snap.today_traffic_in, 0);
    assert_eq!(snap.today_traffic_out, 0);
}

#[test]
fn multiple_tunnels_accumulate_independently() {
    let m = make();
    m.new_tunnel("a", "tcp", "u", "s");
    m.new_tunnel("b", "tcp", "u", "s");
    m.add_traffic_in("a", "tcp", 100);
    m.add_traffic_in("b", "tcp", 200);

    assert_eq!(m.tunnel_snapshot("a").unwrap().today_traffic_in, 100);
    assert_eq!(m.tunnel_snapshot("b").unwrap().today_traffic_in, 200);
    // server total is the sum
    assert_eq!(m.server_snapshot().total_traffic_in, 300);
}

// ── connection tracking ───────────────────────────────────────────────────────

#[test]
fn open_and_close_connection_tracked() {
    let m = make();
    m.new_tunnel("t", "tcp", "u", "s");
    m.open_connection("t", "tcp");
    m.open_connection("t", "tcp");
    assert_eq!(m.server_snapshot().active_connections, 2);
    assert_eq!(m.tunnel_snapshot("t").unwrap().active_connections, 2);
    m.close_connection("t", "tcp");
    assert_eq!(m.server_snapshot().active_connections, 1);
}

#[test]
fn conn_guard_decrements_on_drop() {
    let m = make();
    m.new_tunnel("guarded", "tcp", "u", "s");
    {
        let _guard = m.track_connection("guarded", "tcp");
        assert_eq!(m.server_snapshot().active_connections, 1);
    } // _guard dropped here
    assert_eq!(m.server_snapshot().active_connections, 0);
}

// ── tunnel snapshot details ───────────────────────────────────────────────────

#[test]
fn tunnel_snapshot_not_found_returns_none() {
    let m = make();
    assert!(m.tunnel_snapshot("does-not-exist").is_none());
}

#[test]
fn tunnel_snapshot_records_user_and_session() {
    let m = make();
    m.new_tunnel("proxy", "http", "alice", "session-abc");
    let snap = m.tunnel_snapshot("proxy").unwrap();
    assert_eq!(snap.user, "alice");
    assert_eq!(snap.session_id, "session-abc");
    assert_eq!(snap.tunnel_type, "http");
}

#[test]
fn tunnel_snapshot_last_start_set_after_new_tunnel() {
    let m = make();
    m.new_tunnel("t", "tcp", "u", "s");
    let snap = m.tunnel_snapshot("t").unwrap();
    assert!(snap.last_start_at.is_some(), "last_start_at should be set");
    assert!(snap.last_close_at.is_none(), "last_close_at should not be set yet");
}

#[test]
fn tunnel_snapshot_last_close_set_after_close_tunnel() {
    let m = make();
    m.new_tunnel("t", "tcp", "u", "s");
    m.close_tunnel("t", "tcp");
    let snap = m.tunnel_snapshot("t").unwrap();
    assert!(snap.last_close_at.is_some(), "last_close_at should be set after close");
}

// ── traffic history windows ───────────────────────────────────────────────────

#[test]
fn tunnel_traffic_history_days7_has_correct_length() {
    let m = make();
    m.new_tunnel("t", "tcp", "u", "s");
    m.add_traffic_in("t", "tcp", 512);
    let hist = m.tunnel_traffic("t", TrafficWindow::Days7).unwrap();
    assert_eq!(hist.granularity, "day");
    assert_eq!(hist.unit, "bytes");
    assert_eq!(hist.history.len(), 7);
    // today (index 0 in result, last element) must include the 512 bytes
    let today = hist.history.last().unwrap();
    assert_eq!(today.traffic_in, 512);
}

#[test]
fn tunnel_traffic_history_hours24_has_correct_length() {
    let m = make();
    m.new_tunnel("t", "tcp", "u", "s");
    m.add_traffic_in("t", "tcp", 256);
    let hist = m.tunnel_traffic("t", TrafficWindow::Hours24).unwrap();
    assert_eq!(hist.granularity, "hour");
    assert_eq!(hist.history.len(), 24);
    let current_hour = hist.history.last().unwrap();
    assert_eq!(current_hour.traffic_in, 256);
}

#[test]
fn server_traffic_days7_returns_aggregated_history() {
    let m = make();
    m.new_tunnel("a", "tcp", "u", "s");
    m.new_tunnel("b", "http", "u", "s");
    m.add_traffic_in("a", "tcp", 100);
    m.add_traffic_in("b", "http", 200);
    m.add_traffic_out("a", "tcp", 50);
    let hist = m.server_traffic(TrafficWindow::Days7);
    assert_eq!(hist.history.len(), 7);
    let today = hist.history.last().unwrap();
    assert_eq!(today.traffic_in, 300);
    assert_eq!(today.traffic_out, 50);
}

#[test]
fn tunnel_traffic_unknown_returns_none() {
    let m = make();
    assert!(m.tunnel_traffic("ghost", TrafficWindow::Days7).is_none());
}

// ── TrafficWindow::parse ──────────────────────────────────────────────────────

#[test]
fn traffic_window_parse_24h_variants() {
    assert_eq!(TrafficWindow::parse("24h"), TrafficWindow::Hours24);
    assert_eq!(TrafficWindow::parse("hour"), TrafficWindow::Hours24);
    assert_eq!(TrafficWindow::parse("hours"), TrafficWindow::Hours24);
    assert_eq!(TrafficWindow::parse("1d"), TrafficWindow::Hours24);
    assert_eq!(TrafficWindow::parse("HOURS"), TrafficWindow::Hours24);
}

#[test]
fn traffic_window_parse_7d_default() {
    assert_eq!(TrafficWindow::parse("7d"), TrafficWindow::Days7);
    assert_eq!(TrafficWindow::parse(""), TrafficWindow::Days7);
    assert_eq!(TrafficWindow::parse("anything"), TrafficWindow::Days7);
}

// ── token_conn snapshot ───────────────────────────────────────────────────────

#[test]
fn token_conn_snapshot_empty_by_default() {
    let m = make();
    assert!(m.token_conn_snapshot().is_empty());
}

#[test]
fn token_conn_inc_dec_reflected_in_snapshot() {
    let m = make();
    m.inc_token_conn("tok-a");
    m.inc_token_conn("tok-a");
    m.inc_token_conn("tok-b");
    let snap = m.token_conn_snapshot();
    let a = snap.iter().find(|t| t.token == "tok-a").expect("tok-a");
    let b = snap.iter().find(|t| t.token == "tok-b").expect("tok-b");
    assert_eq!(a.active_conns, 2);
    assert_eq!(b.active_conns, 1);
}

#[test]
fn token_conn_dec_to_zero_removed_from_snapshot() {
    let m = make();
    m.inc_token_conn("tok");
    m.dec_token_conn("tok");
    assert!(m.token_conn_snapshot().is_empty());
}

#[test]
fn token_conn_snapshot_sorted_by_active_desc() {
    let m = make();
    m.inc_token_conn("low");
    m.inc_token_conn("high");
    m.inc_token_conn("high");
    m.inc_token_conn("high");
    let snap = m.token_conn_snapshot();
    assert_eq!(snap[0].token, "high");
    assert_eq!(snap[1].token, "low");
}
