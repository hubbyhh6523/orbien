use orbien_core::net::http_forward::{
    forward_one, validate_single_request, ForwardLimits,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

async fn run_wire(
    input: Vec<u8>,
    expected_body: &[u8],
    prefetch: bool,
) {
    let backend_listener =
        TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();

    let gateway_listener =
        TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = gateway_listener.local_addr().unwrap();
    let wanted = input.len();

    let backend = tokio::spawn(async move {
        let (mut stream, _) =
            backend_listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0u8; 4096];

        loop {
            match timeout(
                Duration::from_millis(250),
                stream.read(&mut buf),
            )
            .await
            {
                Err(_) => break,
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => bytes.extend_from_slice(&buf[..n]),
                Ok(Err(e)) => panic!("backend read: {e}"),
            }
        }

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK",
            )
            .await
            .unwrap();

        // Do not close the backend write half. The forwarder must finish on
        // the response's Content-Length while preventing more request bytes.
        let mut tail = Vec::new();
        timeout(
            Duration::from_secs(2),
            stream.read_to_end(&mut tail),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(
            tail.is_empty(),
            "late second request reached the backend"
        );
        bytes
    });

    let gateway = tokio::spawn(async move {
        let (mut visitor, _) =
            gateway_listener.accept().await.unwrap();
        let mut buffered = Vec::new();

        if prefetch {
            buffered.resize(wanted, 0);
            visitor.read_exact(&mut buffered).await.unwrap();
        } else {
            loop {
                buffered.push(visitor.read_u8().await.unwrap());
                if buffered.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
        }

        let upstream =
            TcpStream::connect(backend_addr).await.unwrap();

        forward_one(
            visitor,
            upstream,
            buffered,
            ForwardLimits {
                exchange_timeout: Duration::from_secs(3),
                idle_timeout: None,
            },
        )
        .await
        .unwrap()
    });

    let mut client =
        TcpStream::connect(gateway_addr).await.unwrap();
    client.write_all(&input).await.unwrap();

    let mut response = Vec::new();
    timeout(
        Duration::from_secs(3),
        client.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();

    assert!(response.ends_with(b"\r\n\r\nOK"));
    assert!(
        response
            .windows(19)
            .any(|w| w == b"Connection: close\r\n")
    );

    gateway.await.unwrap();
    let received = backend.await.unwrap();

    let end = received
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap()
        + 4;

    assert_eq!(&received[end..], expected_body);
    assert!(
        !received
            .windows(b"/second".len())
            .any(|w| w == b"/second")
    );
}

#[tokio::test]
async fn real_tcp_prefetched_and_streamed_pipeline_boundaries() {
    let second =
        b"GET /second HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Basic evil\r\n\r\n";

    for prefetch in [false, true] {
        for (head, body, expected) in [
            (
                b"GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n"
                    .as_slice(),
                b"".as_slice(),
                b"".as_slice(),
            ),
            (
                b"POST /first HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\n",
                b"\x00\xff\xfe",
                b"\x00\xff\xfe",
            ),
            (
                b"POST /first HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
                b"3;x=test\r\n\x00\xff\xfe\r\n0\r\nX-Note: ignored\r\n\r\n",
                b"3\r\n\x00\xff\xfe\r\n0\r\n\r\n",
            ),
        ] {
            let mut input = head.to_vec();
            input.extend_from_slice(body);
            input.extend_from_slice(second);

            run_wire(input, expected, prefetch).await;
        }
    }
}

#[tokio::test]
async fn continue_is_delivered_before_upload_is_complete() {
    let listener =
        TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let front =
        TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front.local_addr().unwrap();

    let backend = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();

        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }

        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .unwrap();

        let mut payload = [0u8; 3];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"\x00\xff\xfe");

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
            )
            .await
            .unwrap();

        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.unwrap();
        assert!(tail.is_empty());
    });

    let gateway = tokio::spawn(async move {
        let (mut visitor, _) = front.accept().await.unwrap();
        let mut head = Vec::new();

        while !head.ends_with(b"\r\n\r\n") {
            head.push(visitor.read_u8().await.unwrap());
        }

        let upstream = TcpStream::connect(addr).await.unwrap();

        forward_one(
            visitor,
            upstream,
            head,
            ForwardLimits {
                exchange_timeout: Duration::from_secs(3),
                idle_timeout: None,
            },
        )
        .await
        .unwrap();
    });

    timeout(Duration::from_secs(4), async {
        let mut client =
            TcpStream::connect(front_addr).await.unwrap();

        client
            .write_all(
                b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n",
            )
            .await
            .unwrap();

        let mut interim = Vec::new();
        while !interim.ends_with(b"\r\n\r\n") {
            interim.push(client.read_u8().await.unwrap());
        }

        assert!(interim.starts_with(b"HTTP/1.1 100 "));
        client.write_all(b"\x00\xff\xfe").await.unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.ends_with(b"OK"));

        gateway.await.unwrap();
        backend.await.unwrap();
    })
    .await
    .unwrap();
}

#[test]
fn rejects_framing_and_upgrade_before_opening_backend() {
    for head in [
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n"
            .as_slice(),
        b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",
    ] {
        assert!(validate_single_request(head).is_err());
    }

    assert!(
        validate_single_request(
            b"CONNECT x:443 HTTP/1.1\r\nHost: x:443\r\n\r\n"
        )
        .is_ok()
    );
}

#[tokio::test]
async fn connect_keeps_legacy_bidirectional_passthrough() {
    timeout(Duration::from_secs(4), async {
        let backend_listener =
            TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend_listener.local_addr().unwrap();

        let front =
            TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();

        let prefix =
            b"CONNECT x:443 HTTP/1.1\r\nHost: x:443\r\n\r\n\x00\xff";

        let backend = tokio::spawn(async move {
            let (mut stream, _) =
                backend_listener.accept().await.unwrap();

            let mut received = vec![0; prefix.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, prefix);

            stream
                .write_all(
                    b"HTTP/1.1 200 Connection Established\r\n\r\n\xfe\x00",
                )
                .await
                .unwrap();

            let mut tail = Vec::new();
            stream.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, b"opaque");
        });

        let gateway = tokio::spawn(async move {
            let (visitor, _) = front.accept().await.unwrap();
            let upstream =
                TcpStream::connect(backend_addr).await.unwrap();

            // In production the same prefix has already been read from visitor.
            forward_one(
                visitor,
                upstream,
                prefix.to_vec(),
                ForwardLimits::default(),
            )
            .await
            .unwrap();
        });

        let mut client =
            TcpStream::connect(front_addr).await.unwrap();

        let mut reply = vec![
            0;
            b"HTTP/1.1 200 Connection Established\r\n\r\n\xfe\x00"
                .len()
        ];
        client.read_exact(&mut reply).await.unwrap();
        assert!(reply.ends_with(b"\xfe\x00"));

        client.write_all(b"opaque").await.unwrap();
        client.shutdown().await.unwrap();

        let mut rest = Vec::new();
        client.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());

        gateway.await.unwrap();
        backend.await.unwrap();
    })
    .await
    .unwrap();
}
