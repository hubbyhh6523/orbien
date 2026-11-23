use super::types::*;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Duration;

#[derive(Debug, Error)]
pub enum MessageReadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown message type: {0}")]
    UnknownType(u8),
    #[error("message body too large: {0} bytes")]
    TooLarge(u32),
    #[error("read timed out after {0:?}")]
    Timeout(Duration),
}

#[derive(Debug, Error)]
pub enum MessageWriteError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

const MAX_MSG_SIZE: u32 = 256 * 1024;

/// Per-type body limit (#13). Login and NewDataConn carry a handful of
/// short strings; Ping/Pong and the other small control messages are a
/// few dozen bytes; NewTunnel carries bounded domain/location lists
/// (#11 caps: 32 each, strings ≤ 64 chars). UdpPacket keeps the global
/// cap because its base64 JSON body can legitimately approach it.
pub fn max_bytes_for_type(type_byte: u8) -> u32 {
    match type_byte {
        TYPE_LOGIN | TYPE_NEW_DATA_CONN => 4 * 1024,
        TYPE_NEW_TUNNEL => 64 * 1024,
        TYPE_UDP_PACKET => MAX_MSG_SIZE,
        _ => 1024,
    }
}

pub async fn write_msg<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Message,
) -> Result<(), MessageWriteError> {
    let type_byte = msg.type_byte();
    let body = match msg {
        Message::Login(m) => serde_json::to_vec(m)?,
        Message::LoginResp(m) => serde_json::to_vec(m)?,
        Message::Challenge(m) => serde_json::to_vec(m)?,
        Message::Hello(m) => serde_json::to_vec(m)?,
        Message::NewTunnel(m) => serde_json::to_vec(m)?,
        Message::NewTunnelResp(m) => serde_json::to_vec(m)?,
        Message::CloseTunnel(m) => serde_json::to_vec(m)?,
        Message::ReqDataConn(m) => serde_json::to_vec(m)?,
        Message::NewDataConn(m) => serde_json::to_vec(m)?,
        Message::StartDataConn(m) => serde_json::to_vec(m)?,
        Message::Ping(m) => serde_json::to_vec(m)?,
        Message::Pong(m) => serde_json::to_vec(m)?,
        Message::UdpPacket(m) => serde_json::to_vec(m)?,
        Message::KickOut(m) => serde_json::to_vec(m)?,
        Message::P2pReq(m) => serde_json::to_vec(m)?,
        Message::P2pInfo(m) => serde_json::to_vec(m)?,
        Message::P2pAddr(m) => serde_json::to_vec(m)?,
        Message::P2pReady(m) => serde_json::to_vec(m)?,
    };

    writer.write_u8(type_byte).await?;
    writer.write_u32_le(body.len() as u32).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_msg<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Message, MessageReadError> {
    read_msg_with_limits(reader, max_bytes_for_type).await
}

/// Like [`read_msg`] but with one size limit for every message type
/// (used for the first message of a connection, before login).
pub async fn read_msg_limited<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_size: u32,
) -> Result<Message, MessageReadError> {
    read_msg_with_limits(reader, |_| max_size).await
}

/// Like [`read_msg_limited`] but fails with [`MessageReadError::Timeout`]
/// if the full message is not received within `timeout`.
pub async fn read_msg_limited_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_size: u32,
    timeout: Duration,
) -> Result<Message, MessageReadError> {
    tokio::time::timeout(timeout, read_msg_limited(reader, max_size))
        .await
        .unwrap_or(Err(MessageReadError::Timeout(timeout)))
}

/// Core reader: the length is checked against `limit(type_byte)` *before*
/// the body buffer is allocated, so a peer that declares a huge body and
/// then stalls is rejected immediately instead of hanging the reader.
pub async fn read_msg_with_limits<R: AsyncRead + Unpin, F: Fn(u8) -> u32>(
    reader: &mut R,
    limit: F,
) -> Result<Message, MessageReadError> {
    let type_byte = reader.read_u8().await?;
    let len = reader.read_u32_le().await?;
    if len > limit(type_byte) {
        return Err(MessageReadError::TooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;

    let msg = match type_byte {
        TYPE_LOGIN => Message::Login(serde_json::from_slice(&buf)?),
        TYPE_LOGIN_RESP => Message::LoginResp(serde_json::from_slice(&buf)?),
        TYPE_CHALLENGE => Message::Challenge(serde_json::from_slice(&buf)?),
        TYPE_HELLO => Message::Hello(serde_json::from_slice(&buf)?),
        TYPE_NEW_TUNNEL => Message::NewTunnel(serde_json::from_slice(&buf)?),
        TYPE_NEW_TUNNEL_RESP => Message::NewTunnelResp(serde_json::from_slice(&buf)?),
        TYPE_CLOSE_TUNNEL => Message::CloseTunnel(serde_json::from_slice(&buf)?),
        TYPE_REQ_DATA_CONN => Message::ReqDataConn(serde_json::from_slice(&buf)?),
        TYPE_NEW_DATA_CONN => Message::NewDataConn(serde_json::from_slice(&buf)?),
        TYPE_START_DATA_CONN => Message::StartDataConn(serde_json::from_slice(&buf)?),
        TYPE_PING => Message::Ping(serde_json::from_slice(&buf)?),
        TYPE_PONG => Message::Pong(serde_json::from_slice(&buf)?),
        TYPE_UDP_PACKET => Message::UdpPacket(serde_json::from_slice(&buf)?),
        TYPE_KICK_OUT => Message::KickOut(serde_json::from_slice(&buf)?),
        TYPE_P2P_REQ => Message::P2pReq(serde_json::from_slice(&buf)?),
        TYPE_P2P_INFO => Message::P2pInfo(serde_json::from_slice(&buf)?),
        TYPE_P2P_ADDR => Message::P2pAddr(serde_json::from_slice(&buf)?),
        TYPE_P2P_READY => Message::P2pReady(serde_json::from_slice(&buf)?),
        other => return Err(MessageReadError::UnknownType(other)),
    };
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn roundtrip(msg: Message) {
        let (mut a, mut b) = duplex(4096);
        write_msg(&mut a, &msg).await.unwrap();
        let got = read_msg(&mut b).await.unwrap();
        assert_eq!(got.type_byte(), msg.type_byte());
        let (_, body) = split(&msg);
        let (_, got_body) = split(&got);
        assert_eq!(body, got_body, "message body mismatch for type {}", msg.type_byte() as char);
    }

    fn split(msg: &Message) -> (u8, Vec<u8>) {
        let body = match msg {
            Message::Login(m) => serde_json::to_vec(m).unwrap(),
            Message::LoginResp(m) => serde_json::to_vec(m).unwrap(),
            Message::Challenge(m) => serde_json::to_vec(m).unwrap(),
            Message::Hello(m) => serde_json::to_vec(m).unwrap(),
            Message::NewTunnel(m) => serde_json::to_vec(m).unwrap(),
            Message::NewTunnelResp(m) => serde_json::to_vec(m).unwrap(),
            Message::CloseTunnel(m) => serde_json::to_vec(m).unwrap(),
            Message::ReqDataConn(m) => serde_json::to_vec(m).unwrap(),
            Message::NewDataConn(m) => serde_json::to_vec(m).unwrap(),
            Message::StartDataConn(m) => serde_json::to_vec(m).unwrap(),
            Message::Ping(m) => serde_json::to_vec(m).unwrap(),
            Message::Pong(m) => serde_json::to_vec(m).unwrap(),
            Message::UdpPacket(m) => serde_json::to_vec(m).unwrap(),
            Message::KickOut(m) => serde_json::to_vec(m).unwrap(),
            Message::P2pReq(m) => serde_json::to_vec(m).unwrap(),
            Message::P2pInfo(m) => serde_json::to_vec(m).unwrap(),
            Message::P2pAddr(m) => serde_json::to_vec(m).unwrap(),
            Message::P2pReady(m) => serde_json::to_vec(m).unwrap(),
        };
        (msg.type_byte(), body)
    }

    #[tokio::test]
    async fn login_roundtrip() {
        roundtrip(Message::Login(Login {
            version: "0.1.0".into(),
            hostname: "test-host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            user: "alice".into(),
            timestamp: 1_700_000_000,
            session_id: "session-1".into(),
            pool_count: 4,
            resume_proof: String::new(),
            challenge_response: "resp".into(),
            client_nonce: "nonce".into(),
            capabilities: vec!["challenge-auth-v1".into()],
        }))
        .await;
        roundtrip(Message::Challenge(Challenge {
            nonce: "aa".repeat(32),
            version: "0.2.0".into(),
        }))
        .await;
        // #12: the Hello that announces a stream before the Challenge.
        roundtrip(Message::Hello(Hello::default())).await;
    }

    #[tokio::test]
    async fn new_tunnel_roundtrip() {
        roundtrip(Message::NewTunnel(NewTunnel {
            tunnel_name: "mysql".into(),
            protocol: "tcp".into(),
            remote_port: 6050,
            local_ip: "127.0.0.1".into(),
            local_port: 3306,
            domains: vec!["a.example.com".into()],
            locations: vec![],
            basic_auth_user: "".into(),
            basic_auth_password: "".into(),
            host_header_rewrite: "".into(),
            headers: Default::default(),
            response_headers: Default::default(),
            route_by_http_user: "".into(),
            bandwidth: 0.0,
            bandwidth_limit_side: "client".into(),
            max_connections: 100,
        }))
        .await;
    }

    #[tokio::test]
    async fn udp_packet_roundtrip() {
        let remote: std::net::SocketAddr = "1.2.3.4:5678".parse().unwrap();
        roundtrip(Message::UdpPacket(UdpPacket::new(
            vec![1, 2, 3, 4, 5],
            Some(remote),
        )))
        .await;
    }

    #[tokio::test]
    async fn ping_pong_roundtrip() {
        roundtrip(Message::Ping(Ping::default())).await;
        roundtrip(Message::Pong(Pong {
            error: "".into(),
        }))
        .await;
    }

    #[tokio::test]
    async fn kick_out_roundtrip() {
        roundtrip(Message::KickOut(KickOut {
            reason: "duplicate login".into(),
        }))
        .await;
    }

    #[tokio::test]
    async fn p2p_messages_roundtrip() {
        roundtrip(Message::P2pReq(P2pReq {
            peer_session_id: "peer-abc".into(),
            token: "tok-123".into(),
            preferred_local_port: 0,
            tunnel_name: "tun-1".into(),
        }))
        .await;

        roundtrip(Message::P2pInfo(P2pInfo {
            token: "tok-123".into(),
            peer_addr: "1.2.3.4:54321".into(),
            error: "".into(),
        }))
        .await;

        roundtrip(Message::P2pAddr(P2pAddr {
            token: "tok-123".into(),
            candidates: "192.168.1.5:40000,1.2.3.4:54321".into(),
        }))
        .await;

        roundtrip(Message::P2pReady(P2pReady {
            token: "tok-123".into(),
            initiator_candidates: "192.168.1.5:40000".into(),
            responder_candidates: "10.0.0.2:50000".into(),
            initiator_observed_addr: "1.2.3.4:54321".into(),
            responder_observed_addr: "5.6.7.8:60000".into(),
            tunnel_name: "tun-1".into(),
        }))
        .await;
    }

    #[tokio::test]
    async fn rejects_unknown_type() {
        let (mut a, mut b) = duplex(64);
        use tokio::io::AsyncWriteExt;
        a.write_u8(0x7f).await.unwrap();
        a.write_u32_le(0).await.unwrap();
        a.flush().await.unwrap();
        let err = read_msg(&mut b).await.unwrap_err();
        assert!(matches!(err, MessageReadError::UnknownType(0x7f)));
    }

    #[tokio::test]
    async fn rejects_oversized_message() {
        let (mut a, mut b) = duplex(64);
        use tokio::io::AsyncWriteExt;
        a.write_u8(TYPE_PING).await.unwrap();
        a.write_u32_le(MAX_MSG_SIZE + 1).await.unwrap();
        a.flush().await.unwrap();
        let err = read_msg(&mut b).await.unwrap_err();
        assert!(matches!(err, MessageReadError::TooLarge(_)));
    }

    /// #13: per-type limits. A Login body over 4 KiB must be rejected
    /// even though it is far under the 256 KiB global cap.
    #[tokio::test]
    async fn login_over_4k_rejected() {
        let (mut a, mut b) = duplex(8192);
        let body = vec![b'x'; 4097];
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = a.write_u8(TYPE_LOGIN).await;
            let _ = a.write_u32_le(4097).await;
            let _ = a.write_all(&body).await;
            let _ = a.flush().await;
        });
        let err = read_msg(&mut b).await.unwrap_err();
        assert!(matches!(err, MessageReadError::TooLarge(_)));
    }

    /// #13: Ping/Pong are a few dozen bytes in normal use; 1 KiB is plenty.
    #[tokio::test]
    async fn ping_over_1k_rejected() {
        let (mut a, mut b) = duplex(8192);
        let body = vec![b'x'; 1025];
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = a.write_u8(TYPE_PING).await;
            let _ = a.write_u32_le(1025).await;
            let _ = a.write_all(&body).await;
            let _ = a.flush().await;
        });
        let err = read_msg(&mut b).await.unwrap_err();
        assert!(matches!(err, MessageReadError::TooLarge(_)));
    }

    /// #13: NewTunnel is the largest small message; 64 KiB is its cap.
    #[tokio::test]
    async fn new_tunnel_over_64k_rejected() {
        let (mut a, mut b) = duplex(128 * 1024);
        let body = vec![b'x'; 65_537];
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let _ = a.write_u8(TYPE_NEW_TUNNEL).await;
            let _ = a.write_u32_le(65_537).await;
            let _ = a.write_all(&body).await;
            let _ = a.flush().await;
        });
        let err = read_msg(&mut b).await.unwrap_err();
        assert!(matches!(err, MessageReadError::TooLarge(_)));
    }

    /// #13: an over-limit first message must be rejected from the header
    /// alone, before the body is allocated or waited for. A peer that
    /// declares the body and then stalls must not hang the reader.
    #[tokio::test]
    async fn first_message_over_limit_rejected_before_body() {
        let (mut a, mut b) = duplex(64);
        use tokio::io::AsyncWriteExt;
        a.write_u8(TYPE_LOGIN).await.unwrap();
        a.write_u32_le(5000).await.unwrap();
        a.flush().await.unwrap();
        // No body is ever sent. If the reader waits for it, this times out.
        let res = tokio::time::timeout(Duration::from_millis(500), read_msg(&mut b)).await;
        let err = res
            .expect("read_msg hung waiting for a body it must reject before allocating")
            .unwrap_err();
        assert!(matches!(err, MessageReadError::TooLarge(_)));
    }

    /// #13: the per-type table itself, so a future type added to the
    /// protocol cannot silently fall through to the wrong limit.
    #[test]
    fn per_type_limit_table() {
        assert_eq!(max_bytes_for_type(TYPE_LOGIN), 4 * 1024);
        assert_eq!(max_bytes_for_type(TYPE_NEW_DATA_CONN), 4 * 1024);
        assert_eq!(max_bytes_for_type(TYPE_NEW_TUNNEL), 64 * 1024);
        assert_eq!(max_bytes_for_type(TYPE_UDP_PACKET), MAX_MSG_SIZE);
        for t in [
            TYPE_LOGIN_RESP,
            TYPE_CHALLENGE,
            TYPE_HELLO,
            TYPE_NEW_TUNNEL_RESP,
            TYPE_CLOSE_TUNNEL,
            TYPE_REQ_DATA_CONN,
            TYPE_START_DATA_CONN,
            TYPE_PING,
            TYPE_PONG,
            TYPE_KICK_OUT,
            TYPE_P2P_REQ,
            TYPE_P2P_INFO,
            TYPE_P2P_ADDR,
            TYPE_P2P_READY,
        ] {
            assert_eq!(max_bytes_for_type(t), 1024, "type {t}");
        }
    }

    /// #13: UdpPacket keeps the 256 KiB cap — a large (100 KiB payload,
    /// ~134 KiB base64 JSON) packet still roundtrips. The duplex buffer
    /// must hold the whole body: the shared `roundtrip` helper writes
    /// before reading, which deadlocks above its 4 KiB buffer.
    #[tokio::test]
    async fn udp_packet_large_roundtrip() {
        let (mut a, mut b) = duplex(256 * 1024);
        let msg = Message::UdpPacket(UdpPacket::new(vec![0xabu8; 100_000], None));
        write_msg(&mut a, &msg).await.unwrap();
        let got = read_msg(&mut b).await.unwrap();
        assert_eq!(got.type_byte(), msg.type_byte());
        let (_, body) = split(&msg);
        let (_, got_body) = split(&got);
        assert_eq!(body, got_body);
    }

    #[tokio::test]
    async fn udp_packet_over_256k_rejected() {
        let (mut a, mut b) = duplex(64);
        use tokio::io::AsyncWriteExt;
        a.write_u8(TYPE_UDP_PACKET).await.unwrap();
        a.write_u32_le(MAX_MSG_SIZE + 1).await.unwrap();
        a.flush().await.unwrap();
        let err = read_msg(&mut b).await.unwrap_err();
        assert!(matches!(err, MessageReadError::TooLarge(_)));
    }

    /// #13: the limited+timeout reader fails with Timeout when the peer
    /// sends nothing, and honours the size limit before the body.
    #[tokio::test]
    async fn read_msg_limited_timeout_times_out() {
        let (_a, mut b) = duplex(64);
        let err = read_msg_limited_timeout(&mut b, 4096, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(matches!(err, MessageReadError::Timeout(_)));
    }
}
