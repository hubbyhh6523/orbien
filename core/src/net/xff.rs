use anyhow::{anyhow, ensure, Result};
use std::net::IpAddr;

fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Rewrites only the first HTTP head; buffered payload is copied verbatim.
/// This helper does not enforce request boundaries or prevent pipelining.
/// Empty trusted values remove visitor fields without inserting replacements.
pub fn apply_x_forwarded_for(buf: &mut Vec<u8>, client_ip: &str, proto: &str) -> Result<()> {
    let ip = if client_ip.is_empty() {
        None
    } else {
        Some(client_ip.parse::<IpAddr>()?)
    };
    ensure!(matches!(proto, "" | "http" | "https"), "invalid forwarded scheme");
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4).ok_or_else(|| anyhow!("incomplete HTTP head"))?;
    ensure!(end <= 64 * 1024, "HTTP head too large");
    let first = buf[..end].windows(2).position(|w| w == b"\r\n")
        .ok_or_else(|| anyhow!("missing request line"))?;
    ensure!(first > 0 && buf[..first].iter().all(|b| b.is_ascii_graphic() || *b == b' '), "invalid request line");
    let mut out = Vec::with_capacity(buf.len());
    out.extend_from_slice(&buf[..first + 2]);
    let mut pos = first + 2;
    let mut fields = 0;
    while pos < end - 2 {
        let len = buf[pos..end].windows(2).position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow!("incomplete header line"))?;
        let line = &buf[pos..pos + len];
        fields += 1;
        ensure!(fields <= 128, "too many headers");
        let colon = line.iter().position(|b| *b == b':')
            .ok_or_else(|| anyhow!("missing header colon"))?;
        let name = &line[..colon];
        ensure!(!name.is_empty() && name.iter().copied().all(token), "invalid header name or folded header");
        ensure!(line[colon + 1..].iter().all(|b| *b == b'\t' || (*b >= 0x20 && *b != 0x7f)), "invalid header value");
        if !name.eq_ignore_ascii_case(b"x-forwarded-for")
            && !name.eq_ignore_ascii_case(b"x-forwarded-proto")
        {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
        pos += len + 2;
    }
    ensure!(pos == end - 2, "invalid HTTP head ending");
    if let Some(ip) = ip {
        out.extend_from_slice(format!("X-Forwarded-For: {ip}\r\n").as_bytes());
    }
    if !proto.is_empty() {
        out.extend_from_slice(format!("X-Forwarded-Proto: {proto}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&buf[end..]);
    *buf = out;
    Ok(())
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
            b"GET / HTTP/1.1\nHost: x\n\n",
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
}
