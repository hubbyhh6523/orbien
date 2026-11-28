use anyhow::{anyhow, Result};
use orbien_core::msg::{self, Message};
use orbien_core::transport::DynStream;
use orbien_core::udp::{forwarder, spawn_data_ping, CHANNEL_CAP};
use std::net::SocketAddr;
use tokio::io::AsyncRead;
use tokio::sync::{mpsc, oneshot};

pub async fn run_udp_session(
    data: DynStream,
    local_addr: SocketAddr,
    packet_size: usize,
    proxy_protocol_version: Option<String>,
    max_sessions: usize,
    mut cancel_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(data);

    let (to_data_tx, mut to_data_rx) = mpsc::channel::<Message>(CHANNEL_CAP);
    let (from_data_tx, from_data_rx) = mpsc::channel(CHANNEL_CAP);

    let ping = spawn_data_ping(to_data_tx.clone());
    let forward = {
        let tx = to_data_tx;
        tokio::spawn(async move {
            forwarder(
                local_addr,
                from_data_rx,
                tx,
                packet_size,
                proxy_protocol_version,
                max_sessions,
            )
            .await;
        })
    };

    let (fail_tx, mut fail_rx) = mpsc::channel::<anyhow::Error>(1);
    let from_data_tx_r = from_data_tx;
    let fail_r = fail_tx;
    let reader_task = tokio::spawn(async move {
        data_reader(reader, from_data_tx_r, fail_r).await;
    });

    let result = loop {
        tokio::select! {
            _ = &mut cancel_rx => {
                tracing::info!(%local_addr, "udp session replaced");
                break Ok(());
            }
            err = fail_rx.recv() => {
                break match err {
                    Some(e) => Err(e),
                    None => Ok(()),
                };
            }
            out = to_data_rx.recv() => {
                match out {
                    Some(m) => {
                        if let Err(e) = msg::write_msg(&mut writer, &m).await {
                            break Err(anyhow!("udp data write: {e}"));
                        }
                    }
                    None => break Ok(()),
                }
            }
        }
    };

    reader_task.abort();
    ping.abort();
    forward.abort();
    let _ = reader_task.await;
    let _ = ping.await;
    let _ = forward.await;
    result
}

async fn data_reader<R: AsyncRead + Unpin + Send + 'static>(
    mut reader: R,
    from_data_tx: mpsc::Sender<orbien_core::msg::UdpPacket>,
    fail_tx: mpsc::Sender<anyhow::Error>,
) {
    loop {
        match msg::read_msg(&mut reader).await {
            Ok(Message::UdpPacket(pkt)) => {
                tracing::trace!(len = pkt.content.len(), "udp packet from data");
                let _ = from_data_tx.try_send(pkt);
            }
            Ok(Message::Ping(_)) => {}
            Ok(other) => {
                tracing::debug!(ty = other.type_byte(), "udp data unexpected message");
            }
            Err(e) => {
                let _ = fail_tx.send(anyhow!("udp data read: {e}")).await;
                return;
            }
        }
    }
}
