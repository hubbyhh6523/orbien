//! Field and count limits for control-plane messages (#11).
//!
//! Everything here is enforced before any listener or route is created, so
//! a rejected message has no side effects. Caps are the approved defaults:
//! Login strings <= 64 chars, tunnel names <= 64 chars of `[A-Za-z0-9_-]`,
//! <= 32 domains and <= 32 locations per tunnel, <= 64 routes per tunnel
//! (domains x locations, empty locations count as one), <= 32 header
//! entries with key/value <= 256 chars, <= 32 tunnels per session.

use orbien_core::msg::{Login, NewTunnel};

pub const MAX_LOGIN_FIELD_LEN: usize = 64;
pub const MAX_TUNNEL_NAME_LEN: usize = 64;
/// #12: a Login carries at most this many capability strings; the
/// challenge response binds them, so an unbounded list would be a
/// way to smuggle bytes past the 4 KiB Login cap.
pub const MAX_CAPABILITIES: usize = 16;
pub const MAX_DOMAINS_PER_TUNNEL: usize = 32;
pub const MAX_LOCATIONS_PER_TUNNEL: usize = 32;
pub const MAX_ROUTES_PER_TUNNEL: usize = 64;
pub const MAX_HEADERS_PER_TUNNEL: usize = 32;
pub const MAX_HEADER_LEN: usize = 256;
pub const MAX_TUNNELS_PER_SESSION: usize = 32;

/// Session ids are server-issued hex (or `-` for legacy ids): at most 64
/// chars. Same rule as the client's `session_id::load` filter.
pub fn valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_TUNNEL_NAME_LEN
        && id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn valid_login_field(s: &str) -> bool {
    s.chars().count() <= MAX_LOGIN_FIELD_LEN && !s.chars().any(|c| c.is_control())
}

/// Reject a `Login` whose strings are outside the allowed length or
/// character set. An empty `session_id` (fresh login) is allowed.
pub fn validate_login(login: &Login) -> Result<(), String> {
    for (name, value) in [
        ("hostname", &login.hostname),
        ("os", &login.os),
        ("arch", &login.arch),
        ("user", &login.user),
        ("version", &login.version),
    ] {
        if !valid_login_field(value) {
            return Err(format!(
                "invalid {name}: at most {MAX_LOGIN_FIELD_LEN} chars, no control characters"
            ));
        }
    }
    if !login.session_id.is_empty() && !valid_session_id(&login.session_id) {
        return Err("invalid session_id".into());
    }
    // #12: capabilities are bound by the challenge response, so they
    // need the same length/charset rule as the other Login strings,
    // plus a count cap. (challenge_response/client_nonce need no
    // format check here: a malformed response already fails the HMAC,
    // and the nonce is an opaque HMAC input bounded by the 4 KiB
    // Login cap.)
    if login.capabilities.len() > MAX_CAPABILITIES {
        return Err(format!(
            "too many capabilities: {} > {MAX_CAPABILITIES}",
            login.capabilities.len()
        ));
    }
    for cap in &login.capabilities {
        if !valid_login_field(cap) {
            return Err(format!(
                "invalid capability: at most {MAX_LOGIN_FIELD_LEN} chars, no control characters"
            ));
        }
    }
    Ok(())
}

fn valid_tunnel_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_TUNNEL_NAME_LEN
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Reject a `NewTunnel` above the list or count limits. `is_reregister`
/// exempts replacing a tunnel of the same name from the per-session cap.
pub fn validate_new_tunnel(
    np: &NewTunnel,
    tunnels_in_session: usize,
    is_reregister: bool,
) -> Result<(), String> {
    if !valid_tunnel_name(&np.tunnel_name) {
        return Err(format!(
            "invalid tunnel_name: at most {MAX_TUNNEL_NAME_LEN} chars of [A-Za-z0-9_-]"
        ));
    }
    if np.domains.len() > MAX_DOMAINS_PER_TUNNEL {
        return Err(format!(
            "too many domains: {} > {MAX_DOMAINS_PER_TUNNEL}",
            np.domains.len()
        ));
    }
    if np.locations.len() > MAX_LOCATIONS_PER_TUNNEL {
        return Err(format!(
            "too many locations: {} > {MAX_LOCATIONS_PER_TUNNEL}",
            np.locations.len()
        ));
    }
    let routes = np.domains.len() * np.locations.len().max(1);
    if routes > MAX_ROUTES_PER_TUNNEL {
        return Err(format!(
            "too many routes: {routes} > {MAX_ROUTES_PER_TUNNEL}"
        ));
    }
    for (map_name, map) in [
        ("headers", &np.headers),
        ("response_headers", &np.response_headers),
    ] {
        if map.len() > MAX_HEADERS_PER_TUNNEL {
            return Err(format!(
                "too many {map_name}: {} > {MAX_HEADERS_PER_TUNNEL}",
                map.len()
            ));
        }
        for (k, v) in map {
            if k.chars().count() > MAX_HEADER_LEN || v.chars().count() > MAX_HEADER_LEN {
                return Err(format!(
                    "{map_name} key/value too long: at most {MAX_HEADER_LEN} chars"
                ));
            }
        }
    }
    if !is_reregister && tunnels_in_session >= MAX_TUNNELS_PER_SESSION {
        return Err(format!(
            "too many tunnels in session: {MAX_TUNNELS_PER_SESSION}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn login() -> Login {
        Login {
            version: "0.2.0".into(),
            hostname: "host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            user: "user".into(),
            timestamp: 0,
            session_id: String::new(),
            pool_count: 1,
            resume_proof: String::new(),
            challenge_response: String::new(),
            client_nonce: String::new(),
            capabilities: vec!["challenge-auth-v1".into()],
        }
    }

    fn tunnel() -> NewTunnel {
        NewTunnel {
            tunnel_name: "web".into(),
            protocol: "http".into(),
            ..Default::default()
        }
    }

    #[test]
    fn login_field_boundaries() {
        let mut l = login();
        l.hostname = "h".repeat(64);
        assert!(validate_login(&l).is_ok());
        l.hostname = "h".repeat(65);
        assert!(validate_login(&l).is_err());
        l.hostname = "ho\nst".into();
        assert!(validate_login(&l).is_err());
        l.hostname = "host".into();
        l.session_id = "zz".into();
        assert!(validate_login(&l).is_err());
        l.session_id = "ab12-34".into();
        assert!(validate_login(&l).is_ok());
    }

    #[test]
    fn tunnel_name_boundaries() {
        let mut t = tunnel();
        assert!(validate_new_tunnel(&t, 0, false).is_ok());
        t.tunnel_name = "a.b".into();
        assert!(validate_new_tunnel(&t, 0, false).is_err());
        t.tunnel_name = String::new();
        assert!(validate_new_tunnel(&t, 0, false).is_err());
        t.tunnel_name = "a".repeat(64);
        assert!(validate_new_tunnel(&t, 0, false).is_ok());
        t.tunnel_name = "a".repeat(65);
        assert!(validate_new_tunnel(&t, 0, false).is_err());
    }

    #[test]
    fn domain_location_route_caps() {
        let mut t = tunnel();
        t.domains = (0..32).map(|i| format!("d{i}.example.com")).collect();
        t.locations = vec!["/a".into(), "/b".into()];
        assert!(validate_new_tunnel(&t, 0, false).is_ok()); // 32x2 = 64
        t.locations.push("/c".into());
        assert!(validate_new_tunnel(&t, 0, false).is_err()); // 32x3 = 96
        t.locations = vec!["/a".into()];
        t.domains.push("extra.example.com".into());
        assert!(validate_new_tunnel(&t, 0, false).is_err()); // 33 domains
        t.domains.truncate(32);
        t.locations = (0..33).map(|i| format!("/p{i}")).collect();
        assert!(validate_new_tunnel(&t, 0, false).is_err()); // 33 locations
    }

    #[test]
    fn header_caps() {
        let mut t = tunnel();
        t.headers = (0..32).map(|i| (format!("X-H{i}"), "v".into())).collect();
        assert!(validate_new_tunnel(&t, 0, false).is_ok());
        t.headers.insert("X-H32".into(), "v".into());
        assert!(validate_new_tunnel(&t, 0, false).is_err());
        t.headers = HashMap::from([("X-K".into(), "v".repeat(256))]);
        assert!(validate_new_tunnel(&t, 0, false).is_ok());
        t.headers = HashMap::from([("X-K".into(), "v".repeat(257))]);
        assert!(validate_new_tunnel(&t, 0, false).is_err());
    }

    #[test]
    fn tunnels_per_session_cap() {
        let t = tunnel();
        assert!(validate_new_tunnel(&t, 31, false).is_ok());
        assert!(validate_new_tunnel(&t, 32, false).is_err());
        assert!(validate_new_tunnel(&t, 32, true).is_ok()); // re-register exempt
    }
}
