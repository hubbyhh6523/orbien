use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

pub const TYPE_LOGIN: u8 = b'A';
pub const TYPE_LOGIN_RESP: u8 = b'a';
pub const TYPE_NEW_TUNNEL: u8 = b'T';
pub const TYPE_NEW_TUNNEL_RESP: u8 = b't';
pub const TYPE_CLOSE_TUNNEL: u8 = b'X';
pub const TYPE_NEW_DATA_CONN: u8 = b'W';
pub const TYPE_REQ_DATA_CONN: u8 = b'Q';
pub const TYPE_START_DATA_CONN: u8 = b'S';
pub const TYPE_PING: u8 = b'G';
pub const TYPE_PONG: u8 = b'g';
pub const TYPE_UDP_PACKET: u8 = b'D';
pub const TYPE_KICK_OUT: u8 = b'E';
/// Server → Client: fresh single-use login challenge (#12).
pub const TYPE_CHALLENGE: u8 = b'C';
/// Client → Server: announce a newly opened stream and ask for a
/// Challenge (#12). Empty on purpose — the stream itself is the
/// announcement (see [`Hello`]).
pub const TYPE_HELLO: u8 = b'H';

// ── P2P direct-tunnel negotiation ────────────────────────────────────────────
/// Client → Server: "I want a direct tunnel to `peer_session_id`"
pub const TYPE_P2P_REQ: u8 = b'P';
/// Server → Client: "here is your peer's observed address and a shared token"
pub const TYPE_P2P_INFO: u8 = b'p';
/// Client → Server: "here are my candidate addresses"
pub const TYPE_P2P_ADDR: u8 = b'N';
/// Server → both Clients: "start hole-punching now"
pub const TYPE_P2P_READY: u8 = b'R';

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Login {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub timestamp: i64,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub pool_count: i32,
    /// HMAC proof of the resume secret for `session_id` (#11). Empty on a
    /// fresh login or when the client has no stored secret.
    #[serde(default)]
    pub resume_proof: String,
    /// Answer to the server's Challenge for this connection (#12):
    /// HMAC-SHA256(key=token) over "login", the challenge nonce and the
    /// Login fields. Empty on an old client — the server rejects the
    /// Login (hard cut); the timestamp-only `auth_digest` is gone.
    #[serde(default)]
    pub challenge_response: String,
    /// Client-generated nonce (32 random bytes, hex) for the server's
    /// mutual proof in LoginResp (#12).
    #[serde(default)]
    pub client_nonce: String,
    /// Protocol capabilities this client speaks, e.g. "challenge-auth-v1"
    /// (#12). The server records them; the challenge response binds them.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Server → Client: fresh single-use challenge for the login on this
/// connection (#12). Sent immediately when a control or data stream
/// opens; the client's Login answers it with `challenge_response`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Hex-encoded 32 random bytes, issued fresh per connection.
    pub nonce: String,
    #[serde(default)]
    pub version: String,
}

/// Client → Server: announce a newly opened stream and ask for a
/// Challenge (#12). Empty on purpose — the stream itself is the
/// announcement. yamux 0.14 and quinn 0.11 open outbound streams
/// lazily: the peer only learns of a stream when the opener writes
/// to it. A client that only reads would deadlock — the server never
/// sees the stream, so it never sends the Challenge — so the client
/// always writes Hello first, on control and data streams alike.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Hello {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResp {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub error: String,
    /// Hex-encoded 32-byte session secret, issued by the server at login
    /// (#11). The client stores it and uses it for resume and data-conn
    /// proofs; empty when login failed.
    #[serde(default)]
    pub resume_token: String,
    /// The server's mutual proof (#12): HMAC-SHA256(key=token) over
    /// "login-resp", the client's nonce and the assigned session id. The
    /// client verifies it before acting on any ReqDataConn/StartDataConn;
    /// empty from an old server.
    #[serde(default)]
    pub server_proof: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewTunnel {
    pub tunnel_name: String,
    pub protocol: String,

    #[serde(default)]
    pub remote_port: i32,

    #[serde(default)]
    pub local_ip: String,
    #[serde(default)]
    pub local_port: i32,

    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub locations: Vec<String>,
    #[serde(default)]
    pub basic_auth_user: String,
    #[serde(default)]
    pub basic_auth_password: String,
    #[serde(default)]
    pub host_header_rewrite: String,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub response_headers: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub route_by_http_user: String,

    #[serde(default)]
    pub bandwidth: f64,

    #[serde(default)]
    pub bandwidth_limit_side: String,

    /// Maximum simultaneous connections for this tunnel.
    /// 0 means unlimited (default).
    #[serde(default, rename = "maxConnections")]
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewTunnelResp {
    pub tunnel_name: String,
    #[serde(default)]
    pub remote_addr: String,
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CloseTunnel {
    pub tunnel_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReqDataConn {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewDataConn {
    pub session_id: String,
    /// HMAC proof of the session secret, purpose `"data-conn"` (#11),
    /// bound to the fresh Challenge nonce of this stream (#12) instead
    /// of a client-chosen timestamp — no replay window. The legacy
    /// `auth_digest`/`timestamp` transition fields are gone.
    #[serde(default)]
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartDataConn {
    pub tunnel_name: String,
    #[serde(default)]
    pub src_addr: String,
    #[serde(default)]
    pub src_port: u16,
    #[serde(default)]
    pub dst_addr: String,
    #[serde(default)]
    pub dst_port: u16,
    #[serde(default)]
    pub error: String,
}

/// Heartbeat, no payload (#12): the old `auth_digest`/`timestamp`
/// fields are gone — the digest was the same timestamp-only HMAC as
/// Login's, the server already ignored it, and a heartbeat proves
/// nothing (the control stream itself is authenticated at login).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Ping {}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Pong {
    #[serde(default)]
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KickOut {
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct UdpSocketAddr {
    pub ip: String,
    pub port: u16,
}

impl UdpSocketAddr {
    pub fn from_std(addr: SocketAddr) -> Self {
        Self {
            ip: addr.ip().to_string(),
            port: addr.port(),
        }
    }

    pub fn to_std(&self) -> Option<SocketAddr> {
        let ip: IpAddr = self.ip.parse().ok()?;
        Some(SocketAddr::new(ip, self.port))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpPacket {
    #[serde(default, with = "b64_bytes", skip_serializing_if = "Vec::is_empty")]
    pub content: Vec<u8>,
    #[serde(rename = "local", default, skip_serializing_if = "Option::is_none")]
    pub local_addr: Option<UdpSocketAddr>,
    #[serde(rename = "remote", default, skip_serializing_if = "Option::is_none")]
    pub remote_addr: Option<UdpSocketAddr>,
}

impl UdpPacket {
    pub fn new(content: Vec<u8>, remote: Option<SocketAddr>) -> Self {
        Self {
            content,
            local_addr: None,
            remote_addr: remote.map(UdpSocketAddr::from_std),
        }
    }
}

// ── P2P message structs ───────────────────────────────────────────────────────

/// Client → Server: request a direct P2P tunnel to `peer_session_id`.
/// The server looks up the peer's control connection and begins the
/// broker handshake.  `token` is a client-generated nonce (UUID) used
/// to correlate the two halves of the exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pReq {
    /// Session ID of the remote peer to connect to directly.
    pub peer_session_id: String,
    /// Client-generated correlation token (UUID recommended).
    pub token: String,
    /// Optional hint: preferred local UDP port for hole-punching.
    /// 0 means "let the OS choose".
    #[serde(default)]
    pub preferred_local_port: u16,
    /// Name of the tunnel on the initiator side that this P2P session
    /// should bypass.  The broker echoes this into `P2pReady` so both
    /// sides know which local backend to dial.
    ///
    /// `#[serde(default)]` ensures old nodes that don't send this field
    /// deserialise to an empty string rather than returning an error.
    #[serde(default)]
    pub tunnel_name: String,
}

/// Server → Client: peer information needed to begin hole-punching.
/// Sent to *both* the initiator and the responder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pInfo {
    /// Shared broker token — same value echoed to both sides.
    pub token: String,
    /// Server-observed public address of the *other* peer (IP:port).
    /// May be empty if the peer has not yet reported its address.
    #[serde(default)]
    pub peer_addr: String,
    /// Non-empty when the broker cannot fulfil the request.
    #[serde(default)]
    pub error: String,
}

/// Client → Server: "here are my candidate addresses for hole-punching".
/// A client sends this after receiving `P2pInfo` from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pAddr {
    /// Same token from `P2pReq` / `P2pInfo`.
    pub token: String,
    /// Comma-separated list of `IP:port` candidates (LAN + WAN).
    pub candidates: String,
}

/// Server → both Clients: all addresses are exchanged, begin hole-punching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pReady {
    pub token: String,
    /// Candidates reported by the *initiator* side.
    pub initiator_candidates: String,
    /// Candidates reported by the *responder* side.
    pub responder_candidates: String,
    /// Server-observed address of the initiator (may differ from its LAN addr).
    #[serde(default)]
    pub initiator_observed_addr: String,
    /// Server-observed address of the responder.
    #[serde(default)]
    pub responder_observed_addr: String,
    /// Tunnel name from the initiator's `P2pReq`, echoed to both sides so
    /// each client knows which local backend to connect to after punching.
    ///
    /// `#[serde(default)]` keeps compatibility with old servers that don't
    /// populate this field — clients fall back to relay mode when empty.
    #[serde(default)]
    pub tunnel_name: String,
}

mod b64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(Vec::new());
        }
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Message {
    Login(Login),
    LoginResp(LoginResp),
    Challenge(Challenge),
    Hello(Hello),
    NewTunnel(NewTunnel),
    NewTunnelResp(NewTunnelResp),
    CloseTunnel(CloseTunnel),
    ReqDataConn(ReqDataConn),
    NewDataConn(NewDataConn),
    StartDataConn(StartDataConn),
    Ping(Ping),
    Pong(Pong),
    UdpPacket(UdpPacket),
    KickOut(KickOut),
    // P2P
    P2pReq(P2pReq),
    P2pInfo(P2pInfo),
    P2pAddr(P2pAddr),
    P2pReady(P2pReady),
}

impl Message {
    pub fn type_byte(&self) -> u8 {
        match self {
            Self::Login(_) => TYPE_LOGIN,
            Self::LoginResp(_) => TYPE_LOGIN_RESP,
            Self::Challenge(_) => TYPE_CHALLENGE,
            Self::Hello(_) => TYPE_HELLO,
            Self::NewTunnel(_) => TYPE_NEW_TUNNEL,
            Self::NewTunnelResp(_) => TYPE_NEW_TUNNEL_RESP,
            Self::CloseTunnel(_) => TYPE_CLOSE_TUNNEL,
            Self::ReqDataConn(_) => TYPE_REQ_DATA_CONN,
            Self::NewDataConn(_) => TYPE_NEW_DATA_CONN,
            Self::StartDataConn(_) => TYPE_START_DATA_CONN,
            Self::Ping(_) => TYPE_PING,
            Self::Pong(_) => TYPE_PONG,
            Self::UdpPacket(_) => TYPE_UDP_PACKET,
            Self::KickOut(_) => TYPE_KICK_OUT,
            Self::P2pReq(_) => TYPE_P2P_REQ,
            Self::P2pInfo(_) => TYPE_P2P_INFO,
            Self::P2pAddr(_) => TYPE_P2P_ADDR,
            Self::P2pReady(_) => TYPE_P2P_READY,
        }
    }
}

#[cfg(test)]
mod compat_tests {
    use super::*;

    /// Old servers omit `tunnel_name`; deserialization must succeed and
    /// produce an empty string, not an error.
    #[test]
    fn p2p_ready_missing_tunnel_name_deserialises_to_empty() {
        let json = r#"{"token":"tok","initiator_candidates":"1.2.3.4:1234",
                       "responder_candidates":"5.6.7.8:5678"}"#;
        let r: P2pReady = serde_json::from_str(json).expect("deserialise P2pReady");
        assert!(r.tunnel_name.is_empty(), "expected empty tunnel_name, got {:?}", r.tunnel_name);
    }

    /// Old clients omit `tunnel_name` in P2pReq; new server must accept it.
    #[test]
    fn p2p_req_missing_tunnel_name_deserialises_to_empty() {
        let json = r#"{"peer_session_id":"sess","token":"tok"}"#;
        let r: P2pReq = serde_json::from_str(json).expect("deserialise P2pReq");
        assert!(r.tunnel_name.is_empty(), "expected empty tunnel_name, got {:?}", r.tunnel_name);
    }

    /// New payload roundtrips correctly.
    #[test]
    fn p2p_ready_tunnel_name_roundtrips() {
        let ready = P2pReady {
            token: "t".into(),
            initiator_candidates: "a".into(),
            responder_candidates: "b".into(),
            initiator_observed_addr: String::new(),
            responder_observed_addr: String::new(),
            tunnel_name: "my-tunnel".into(),
        };
        let json = serde_json::to_string(&ready).unwrap();
        let back: P2pReady = serde_json::from_str(&json).unwrap();
        assert_eq!(back.tunnel_name, "my-tunnel");
    }
}
