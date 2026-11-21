use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_MAX_SKEW_SECS: i64 = 15 * 60;

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

/// Match a login digest against the global token and every policy token
/// (#11). Returns the matched token's id, or `None` when nothing matches.
/// Each candidate is checked with the same constant-time verification as
/// `verify_login_at`, so a wrong digest reveals nothing about any token.
pub fn match_token_id(
    global_token: &str,
    policy_tokens: &[&str],
    auth_digest: &str,
    timestamp: i64,
) -> Option<String> {
    match_token_id_at(
        global_token,
        policy_tokens,
        auth_digest,
        timestamp,
        unix_now(),
        DEFAULT_MAX_SKEW_SECS,
    )
}

/// Injectable-clock variant of [`match_token_id`] (unit-testable).
pub fn match_token_id_at(
    global_token: &str,
    policy_tokens: &[&str],
    auth_digest: &str,
    timestamp: i64,
    now: i64,
    max_skew_secs: i64,
) -> Option<String> {
    if verify_login_at(global_token, auth_digest, timestamp, now, max_skew_secs) {
        return Some(token_id(global_token));
    }
    for policy_token in policy_tokens {
        if verify_login_at(policy_token, auth_digest, timestamp, now, max_skew_secs) {
            return Some(token_id(policy_token));
        }
    }
    None
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
    let mut mac = HmacSha256::new_from_slice(secret_hex.as_bytes())
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(purpose.as_bytes());
    mac.update(b"\n");
    mac.update(session_id.as_bytes());
    mac.update(b"\n");
    mac.update(timestamp.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
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

/// Compute the auth_digest as HMAC-SHA256(key=token, msg=timestamp).
/// The result is lowercase hex-encoded (64 chars).
pub fn compute_auth_digest(token: &str, timestamp: i64) -> String {
    let mut mac =
        HmacSha256::new_from_slice(token.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn verify_login(token: &str, auth_digest: &str, timestamp: i64) -> bool {
    verify_login_at(
        token,
        auth_digest,
        timestamp,
        unix_now(),
        DEFAULT_MAX_SKEW_SECS,
    )
}

/// Alias kept for upstream API compatibility.
pub fn verify_auth_digest(token: &str, auth_digest: &str, timestamp: i64) -> bool {
    verify_login(token, auth_digest, timestamp)
}

/// Verification with injectable clock and skew window (unit-testable).
///
/// Security hardening over plain HMAC comparison:
/// - rejects when token is empty (unconfigured server must deny all);
/// - rejects non-positive timestamps;
/// - rejects timestamps outside `max_skew_secs` of `now` (replay protection);
/// - compares digests in constant time (timing side-channel protection).
pub fn verify_login_at(
    token: &str,
    auth_digest: &str,
    timestamp: i64,
    now: i64,
    max_skew_secs: i64,
) -> bool {
    // Reject when no token is configured — an unconfigured server must not
    // grant access to any client.
    if token.is_empty() {
        return false;
    }
    if auth_digest.is_empty() {
        return false;
    }
    if timestamp <= 0 {
        return false;
    }
    if now.abs_diff(timestamp) > max_skew_secs as u64 {
        return false;
    }
    // Constant-time comparison to prevent timing side-channels.
    let expected = compute_auth_digest(token, timestamp);
    constant_time_eq(expected.as_bytes(), auth_digest.as_bytes())
}

/// Constant-time byte slice comparison (prevents timing oracle).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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
    fn accepts_current_timestamp() {
        let ts = 1_700_000_000;
        let key = compute_auth_digest("secret", ts);
        assert!(verify_login_at("secret", &key, ts, ts, 900));
    }

    #[test]
    fn rejects_stale_timestamp() {
        let ts = 1_700_000_000;
        let key = compute_auth_digest("secret", ts);
        assert!(!verify_login_at("secret", &key, ts, ts + 901, 900));
    }

    #[test]
    fn empty_token_rejects() {
        // Empty token: authentication must fail (no auth configured = deny all).
        assert!(!verify_login_at(
            "",
            "whatever",
            1_700_000_000,
            1_700_000_000,
            900
        ));
    }

    #[test]
    fn rejects_wrong_key() {
        let ts = 1_700_000_000;
        let key = compute_auth_digest("secret", ts);
        // Flip one char — must reject.
        let mut bad = key.clone();
        let idx = bad.len() - 1;
        let last = bad.as_bytes()[idx];
        bad.replace_range(idx.., if last == b'a' { "b" } else { "a" });
        assert!(!verify_login_at("secret", &bad, ts, ts, 900));
    }

    #[test]
    fn rejects_zero_timestamp() {
        let key = compute_auth_digest("secret", 0);
        assert!(!verify_login_at("secret", &key, 0, 0, 900));
    }

    #[test]
    fn rejects_empty_digest() {
        let ts = 1_700_000_000;
        assert!(!verify_login_at("secret", "", ts, ts, 900));
    }

    #[test]
    fn constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_diff_len() {
        assert!(!constant_time_eq(b"hello", b"hell"));
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
    fn match_token_id_matches_global_and_policy_tokens() {
        let ts = 1_700_000_000;
        let global = compute_auth_digest("global-token", ts);
        assert_eq!(
            match_token_id_at("global-token", &["policy-token"], &global, ts, ts, 900),
            Some(token_id("global-token"))
        );
        let policy = compute_auth_digest("policy-token", ts);
        assert_eq!(
            match_token_id_at("global-token", &["policy-token"], &policy, ts, ts, 900),
            Some(token_id("policy-token"))
        );
    }

    #[test]
    fn match_token_id_rejects_unknown_and_empty_tokens() {
        let ts = 1_700_000_000;
        let wrong = compute_auth_digest("no-such-token", ts);
        assert_eq!(
            match_token_id_at("global-token", &["policy-token"], &wrong, ts, ts, 900),
            None
        );
        // An empty global token never matches, even with an empty digest.
        assert_eq!(
            match_token_id_at("", &[], "", ts, ts, 900),
            None
        );
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
}
