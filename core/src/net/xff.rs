use super::http_head::{rewrite_request_head, Forwarded, Rewrite};
use anyhow::Result;
use std::net::IpAddr;

/// Rewrites only the first HTTP head; buffered payload is copied verbatim.
/// This helper does not enforce request boundaries or prevent pipelining.
/// Empty trusted values remove visitor fields without inserting replacements.
pub fn apply_x_forwarded_for(
    buf: &mut Vec<u8>,
    client_ip: &str,
    proto: &str,
) -> Result<()> {
    let client_ip = if client_ip.is_empty() {
        None
    } else {
        Some(client_ip.parse::<IpAddr>()?)
    };

    rewrite_request_head(
        buf,
        &Rewrite {
            forwarded: Some(Forwarded {
                client_ip,
                scheme: if proto.is_empty() { None } else { Some(proto) },
            }),
            ..Default::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_all_forwarding_headers() {
        let mut input = b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: evil-a\r\nx-forwarded-for: evil-b\r\nX-Forwarded-Proto: ftp\r\nx-forwarded-proto: evil\r\n\r\n".to_vec();
        apply_x_forwarded_for(&mut input, "192.0.2.10", "https").unwrap();
        assert_eq!(input, b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 192.0.2.10\r\nX-Forwarded-Proto: https\r\n\r\n");
    }

    #[test]
    fn binary_payload_and_header_looking_body_are_unchanged() {
        let body = b"\x00\xff\xfe\r\nHost: body\r\nX-Forwarded-For: body\r\n";
        let mut input = format!("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        input.extend_from_slice(body);
        apply_x_forwarded_for(&mut input, "192.0.2.10", "http").unwrap();
        let end = input.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(&input[end..], body);
        assert!(input[..end].windows("Content-Length: ".len()).any(|w| w == b"Content-Length: "));
    }

    #[test]
    fn empty_trusted_values_remove_forged_values() {
        let mut input = b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: evil\r\nX-Forwarded-Proto: ftp\r\n\r\n".to_vec();
        apply_x_forwarded_for(&mut input, "", "").unwrap();
        assert_eq!(input, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }

    #[test]
    fn failures_leave_input_unchanged() {
        for request in [
            b"GET / HTTP/1.1\r\nHost: x\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: x\r\n X-Forwarded-For: evil\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\n\n",
            b"GET / HTTP/1.1\r\nHost: x\r\nX-Test: a\nb\r\n\r\n",
        ] {
            let mut input = request.to_vec();
            assert!(apply_x_forwarded_for(&mut input, "192.0.2.10", "http").is_err());
            assert_eq!(input, request);
        }
        for (ip, scheme) in [("evil\r\nInjected: yes", "http"), ("192.0.2.10", "ftp")] {
            let mut input = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
            let original = input.clone();
            assert!(apply_x_forwarded_for(&mut input, ip, scheme).is_err());
            assert_eq!(input, original);
        }
    }

    #[test]
    fn supports_ipv6_and_preserves_non_utf8_header_values() {
        let mut input = b"GET / HTTP/1.1\r\nHost: x\r\nX-Opaque: \xff\r\n\r\n".to_vec();
        apply_x_forwarded_for(&mut input, "2001:db8::1", "https").unwrap();
        assert_eq!(input, b"GET / HTTP/1.1\r\nHost: x\r\nX-Opaque: \xff\r\nX-Forwarded-For: 2001:db8::1\r\nX-Forwarded-Proto: https\r\n\r\n");
    }

    #[test]
    fn supports_lf_only_without_touching_binary_body() {
        let mut input =
            b"POST / HTTP/1.1\nHost: x\nContent-Length: 3\n\n\x00\xff\xfe"
                .to_vec();

        apply_x_forwarded_for(&mut input, "192.0.2.10", "http").unwrap();

        assert_eq!(
            input,
            b"POST / HTTP/1.1\nHost: x\nContent-Length: 3\n\
X-Forwarded-For: 192.0.2.10\nX-Forwarded-Proto: http\n\n\x00\xff\xfe"
        );
    }
}
