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

/// Default timeout applied when using [`read_msg_timeout`].
#[allow(dead_code)]
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn write_msg<W: AsyncWrite + Unpin>(
    writer: &mut W,
    msg: &Message,
) -> Result<(), MessageWriteError> {
    let type_byte = msg.type_byte();
    let body = match msg {
        Message::Login(m) => serde_json::to_vec(m)?,
        Message::LoginResp(m) => serde_json::to_vec(m)?,
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
    let type_byte = reader.read_u8().await?;
    let len = reader.read_u32_le().await?;
    if len > MAX_MSG_SIZE {
        return Err(MessageReadError::TooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;

    let msg = match type_byte {
        TYPE_LOGIN => Message::Login(serde_json::from_slice(&buf)?),
        TYPE_LOGIN_RESP => Message::LoginResp(serde_json::from_slice(&buf)?),
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

/// Like [`read_msg`] but fails with [`MessageReadError::Timeout`] if the
/// full message is not received within `timeout`.
#[allow(dead_code)]
pub async fn read_msg_timeout<R: AsyncRead + Unpin>(
    reader: &mut R,
    timeout: Duration,
) -> Result<Message, MessageReadError> {
    tokio::time::timeout(timeout, read_msg(reader))
        .await
        .unwrap_or(Err(MessageReadError::Timeout(timeout)))
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
            auth_digest: "abc123".into(),
            timestamp: 1_700_000_000,
            session_id: "session-1".into(),
            pool_count: 4,
            resume_proof: String::new(),
        }))
        .await;
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
        roundtrip(Message::Ping(Ping {
            auth_digest: "key".into(),
            timestamp: 123,
        }))
        .await;
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
}
