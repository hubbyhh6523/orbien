use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_MAX_SKEW_SECS: i64 = 15 * 60;

/// Fresh single-use nonce: 32 random bytes, lowercase hex-encoded (#12).
/// Issued by the server once per connection (the Challenge) and by the
/// client once per login (client_nonce, for the mutual proof).
pub fn new_nonce() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Stable public id for a token: lowercase hex of SHA-256(token) (#11).
/// Logs, API responses and policy lookups carry only this id; the raw
/// token appears solely at config parse and inside HMAC verification.
pub fn token_id(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// First 16 chars of a token id, for display in logs and API responses.
pub fn short_token_id(token: &str) -> String {
    token_id(token).chars().take(16).collect()
}

/// HMAC-SHA256(key=secret_hex bytes) over purpose, session id and one
/// freshness value, newline-separated. Shared by the timestamp-based
/// resume proof and the nonce-based data-conn proof (#12).
fn session_proof_mac(secret_hex: &str, purpose: &str, session_id: &str, freshness: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret_hex.as_bytes())
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(purpose.as_bytes());
    mac.update(b"\n");
    mac.update(session_id.as_bytes());
    mac.update(b"\n");
    mac.update(freshness.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Proof that the holder knows a session's secret (#11, shared with #12).
///
/// The secret is the 32-byte random value the server issued at login,
/// hex-encoded in `LoginResp.resume_token`. The message binds the proof
/// to its purpose (`"resume"` or `"data-conn"`), the session id and the
/// timestamp, so a proof captured for one purpose or session cannot be
/// reused for another. The secret itself is the HMAC key, used as its
/// hex string bytes (64 chars of entropy, no decoding needed).
pub fn compute_session_proof(
    secret_hex: &str,
    purpose: &str,
    session_id: &str,
    timestamp: i64,
) -> String {
    session_proof_mac(secret_hex, purpose, session_id, &timestamp.to_string())
}

/// Nonce-bound variant (#12): the freshness value is the server-issued
/// Challenge nonce for this stream, not a client-chosen timestamp, so a
/// captured data-conn proof cannot be replayed on another connection
/// (there is no skew window at all — the nonce is single-use).
pub fn compute_session_proof_nonce(
    secret_hex: &str,
    purpose: &str,
    session_id: &str,
    nonce: &str,
) -> String {
    session_proof_mac(secret_hex, purpose, session_id, nonce)
}

pub fn verify_session_proof_nonce(
    secret_hex: &str,
    purpose: &str,
    session_id: &str,
    proof: &str,
    nonce: &str,
) -> bool {
    if secret_hex.is_empty() || proof.is_empty() || nonce.is_empty() {
        return false;
    }
    let expected = compute_session_proof_nonce(secret_hex, purpose, session_id, nonce);
    constant_time_eq(expected.as_bytes(), proof.as_bytes())
}

pub fn verify_session_proof(
    secret_hex: &str,
    purpose: &str,
    session_id: &str,
    proof: &str,
    timestamp: i64,
) -> bool {
    verify_session_proof_at(
        secret_hex,
        purpose,
        session_id,
        proof,
        timestamp,
        unix_now(),
        DEFAULT_MAX_SKEW_SECS,
    )
}

/// Injectable-clock variant of [`verify_session_proof`] (unit-testable).
pub fn verify_session_proof_at(
    secret_hex: &str,
    purpose: &str,
    session_id: &str,
    proof: &str,
    timestamp: i64,
    now: i64,
    max_skew_secs: i64,
) -> bool {
    if secret_hex.is_empty() || proof.is_empty() || timestamp <= 0 {
        return false;
    }
    if now.abs_diff(timestamp) > max_skew_secs as u64 {
        return false;
    }
    let expected = compute_session_proof(secret_hex, purpose, session_id, timestamp);
    constant_time_eq(expected.as_bytes(), proof.as_bytes())
}

/// The Login's challenge answer (#12): HMAC-SHA256(key=token) over the
/// literal `"login"`, the server-issued Challenge nonce for this
/// connection, and the Login fields that matter — session id, user,
/// hostname, pool count, version and capabilities — newline-separated.
/// Binding the fresh nonce makes a captured Login unreplayable on any
/// other connection (the next connection gets a different nonce), and
/// binding the fields makes tampering with any of them invalidate it.
/// There is no timestamp and no skew window: freshness comes from the
/// nonce, which the server issues once per connection and discards.
///
/// The parameter list is the Login's bound fields; bundling them into
/// a new struct would be an abstraction for one call site.
#[allow(clippy::too_many_arguments)]
pub fn compute_login_response(
    token: &str,
    nonce: &str,
    session_id: &str,
    user: &str,
    hostname: &str,
    pool_count: i32,
    version: &str,
    capabilities: &[String],
) -> String {
    let mut mac =
        HmacSha256::new_from_slice(token.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(b"login");
    for field in [
        nonce,
        session_id,
        user,
        hostname,
        &pool_count.to_string(),
        version,
        &capabilities.join(","),
    ] {
        mac.update(b"\n");
        mac.update(field.as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_login_response(
    token: &str,
    response: &str,
    nonce: &str,
    session_id: &str,
    user: &str,
    hostname: &str,
    pool_count: i32,
    version: &str,
    capabilities: &[String],
) -> bool {
    if token.is_empty() || response.is_empty() || nonce.is_empty() {
        return false;
    }
    let expected = compute_login_response(
        token,
        nonce,
        session_id,
        user,
        hostname,
        pool_count,
        version,
        capabilities,
    );
    constant_time_eq(expected.as_bytes(), response.as_bytes())
}

/// Match a Login challenge response against the global token and every
/// policy token (#11). Returns the matched token's id plus the matched
/// token itself (needed to compute the mutual server proof); the raw
/// token is never logged. `None` when nothing matches.
#[allow(clippy::too_many_arguments)]
pub fn match_login_response<'a>(
    global_token: &'a str,
    policy_tokens: &[&'a str],
    response: &str,
    nonce: &str,
    session_id: &str,
    user: &str,
    hostname: &str,
    pool_count: i32,
    version: &str,
    capabilities: &[String],
) -> Option<(String, &'a str)> {
    if verify_login_response(
        global_token,
        response,
        nonce,
        session_id,
        user,
        hostname,
        pool_count,
        version,
        capabilities,
    ) {
        return Some((token_id(global_token), global_token));
    }
    for policy_token in policy_tokens {
        if verify_login_response(
            policy_token,
            response,
            nonce,
            session_id,
            user,
            hostname,
            pool_count,
            version,
            capabilities,
        ) {
            return Some((token_id(policy_token), policy_token));
        }
    }
    None
}

/// The server's mutual proof (#12): HMAC-SHA256(key=token) over the
/// literal `"login-resp"`, the client's nonce and the session id the
/// server assigned. The client verifies it right after LoginResp,
/// before acting on any ReqDataConn/StartDataConn — a server that does
/// not know the token cannot make the client open a local connection.
/// This is a second layer behind verified TLS, not a replacement: it
/// does not stop an attacker who relays the exchange.
pub fn compute_server_proof(token: &str, client_nonce: &str, session_id: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(token.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(b"login-resp");
    mac.update(b"\n");
    mac.update(client_nonce.as_bytes());
    mac.update(b"\n");
    mac.update(session_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_server_proof(
    token: &str,
    proof: &str,
    client_nonce: &str,
    session_id: &str,
) -> bool {
    if token.is_empty() || proof.is_empty() || client_nonce.is_empty() || session_id.is_empty() {
        return false;
    }
    let expected = compute_server_proof(token, client_nonce, session_id);
    constant_time_eq(expected.as_bytes(), proof.as_bytes())
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Constant-time byte slice comparison (prevents timing oracle).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_diff_len() {
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn new_nonce_is_32_random_bytes_hex() {
        let a = new_nonce();
        let b = new_nonce();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two nonces must differ");
    }

    // ── #11: token ids and session proofs ──────────────────────────────────

    #[test]
    fn token_id_is_stable_sha256_hex() {
        let id = token_id("secret");
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(id, token_id("secret"));
        assert_ne!(id, token_id("other"));
        assert_eq!(short_token_id("secret"), &id[..16]);
    }

    #[test]
    fn session_proof_binds_purpose_session_and_time() {
        let secret = "ab".repeat(32); // 64 hex chars, stands in for a real secret
        let ts = 1_700_000_000;
        let proof = compute_session_proof(&secret, "resume", "sess-1", ts);
        assert!(verify_session_proof_at(&secret, "resume", "sess-1", &proof, ts, ts, 900));
        // Wrong purpose, session, secret or stale timestamp all fail.
        assert!(!verify_session_proof_at(&secret, "data-conn", "sess-1", &proof, ts, ts, 900));
        assert!(!verify_session_proof_at(&secret, "resume", "sess-2", &proof, ts, ts, 900));
        assert!(!verify_session_proof_at("cd".repeat(32).as_str(), "resume", "sess-1", &proof, ts, ts, 900));
        assert!(!verify_session_proof_at(&secret, "resume", "sess-1", &proof, ts, ts + 901, 900));
        assert!(!verify_session_proof_at("", "resume", "sess-1", &proof, ts, ts, 900));
        assert!(!verify_session_proof_at(&secret, "resume", "sess-1", "", ts, ts, 900));
    }

    // ── #12: challenge-response binding ────────────────────────────────────

    fn login_args() -> (String, &'static str, &'static str, &'static str, i32, &'static str, Vec<String>) {
        // (nonce, session_id, user, hostname, pool_count, version, capabilities)
        (
            "aa".repeat(32),
            "sess-1",
            "alice",
            "host-1",
            2,
            "0.2.0",
            vec!["challenge-auth-v1".to_string()],
        )
    }

    #[test]
    fn login_response_binds_every_field() {
        let (nonce, sid, user, host, pool, ver, caps) = login_args();
        let resp = compute_login_response("secret", &nonce, sid, user, host, pool, ver, &caps);
        assert!(verify_login_response("secret", &resp, &nonce, sid, user, host, pool, ver, &caps));
        // Tampering with any single bound field invalidates the response.
        assert!(!verify_login_response("secret", &resp, &nonce, "sess-2", user, host, pool, ver, &caps));
        assert!(!verify_login_response("secret", &resp, &nonce, sid, "mallory", host, pool, ver, &caps));
        assert!(!verify_login_response("secret", &resp, &nonce, sid, user, "host-2", pool, ver, &caps));
        assert!(!verify_login_response("secret", &resp, &nonce, sid, user, host, pool + 1, ver, &caps));
        assert!(!verify_login_response("secret", &resp, &nonce, sid, user, host, pool, "0.1.0", &caps));
        assert!(!verify_login_response("secret", &resp, &nonce, sid, user, host, pool, ver, &[]));
        // Wrong token, empty token/response/nonce all fail.
        assert!(!verify_login_response("other", &resp, &nonce, sid, user, host, pool, ver, &caps));
        assert!(!verify_login_response("", &resp, &nonce, sid, user, host, pool, ver, &caps));
        assert!(!verify_login_response("secret", "", &nonce, sid, user, host, pool, ver, &caps));
        assert!(!verify_login_response("secret", &resp, "", sid, user, host, pool, ver, &caps));
    }

    #[test]
    fn login_response_cannot_replay_on_another_connection() {
        // A captured response is bound to the nonce of its own
        // connection; the next connection gets a different nonce.
        let (nonce, sid, user, host, pool, ver, caps) = login_args();
        let resp = compute_login_response("secret", &nonce, sid, user, host, pool, ver, &caps);
        let other_nonce = "bb".repeat(32);
        assert_ne!(nonce, other_nonce);
        assert!(!verify_login_response("secret", &resp, &other_nonce, sid, user, host, pool, ver, &caps));
    }

    #[test]
    fn match_login_response_matches_global_and_policy_tokens() {
        let (nonce, sid, user, host, pool, ver, caps) = login_args();
        let global = compute_login_response("global-token", &nonce, sid, user, host, pool, ver, &caps);
        assert_eq!(
            match_login_response("global-token", &["policy-token"], &global, &nonce, sid, user, host, pool, ver, &caps),
            Some((token_id("global-token"), "global-token"))
        );
        let policy = compute_login_response("policy-token", &nonce, sid, user, host, pool, ver, &caps);
        assert_eq!(
            match_login_response("global-token", &["policy-token"], &policy, &nonce, sid, user, host, pool, ver, &caps),
            Some((token_id("policy-token"), "policy-token"))
        );
    }

    #[test]
    fn match_login_response_rejects_unknown_and_empty_tokens() {
        let (nonce, sid, user, host, pool, ver, caps) = login_args();
        let wrong = compute_login_response("no-such-token", &nonce, sid, user, host, pool, ver, &caps);
        assert_eq!(
            match_login_response("global-token", &["policy-token"], &wrong, &nonce, sid, user, host, pool, ver, &caps),
            None
        );
        assert_eq!(
            match_login_response("", &[], "", &nonce, sid, user, host, pool, ver, &caps),
            None
        );
    }

    #[test]
    fn server_proof_binds_client_nonce_and_session() {
        let proof = compute_server_proof("secret", "client-nonce", "sess-1");
        assert!(verify_server_proof("secret", &proof, "client-nonce", "sess-1"));
        assert!(!verify_server_proof("secret", &proof, "other-nonce", "sess-1"));
        assert!(!verify_server_proof("secret", &proof, "client-nonce", "sess-2"));
        assert!(!verify_server_proof("other", &proof, "client-nonce", "sess-1"));
        assert!(!verify_server_proof("secret", "", "client-nonce", "sess-1"));
        assert!(!verify_server_proof("", &proof, "client-nonce", "sess-1"));
    }

    #[test]
    fn session_proof_nonce_binds_nonce_not_timestamp() {
        let secret = "ab".repeat(32);
        let proof = compute_session_proof_nonce(&secret, "data-conn", "sess-1", "nonce-1");
        assert!(verify_session_proof_nonce(&secret, "data-conn", "sess-1", &proof, "nonce-1"));
        // A proof captured for one connection's nonce is useless on the
        // next connection: there is no skew window to replay inside.
        assert!(!verify_session_proof_nonce(&secret, "data-conn", "sess-1", &proof, "nonce-2"));
        assert!(!verify_session_proof_nonce(&secret, "resume", "sess-1", &proof, "nonce-1"));
        assert!(!verify_session_proof_nonce(&secret, "data-conn", "sess-2", &proof, "nonce-1"));
        assert!(!verify_session_proof_nonce("", "data-conn", "sess-1", &proof, "nonce-1"));
        assert!(!verify_session_proof_nonce(&secret, "data-conn", "sess-1", "", "nonce-1"));
        assert!(!verify_session_proof_nonce(&secret, "data-conn", "sess-1", &proof, ""));
    }
}
