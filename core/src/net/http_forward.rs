use super::http_head::{rewrite_request_head, Rewrite};
use anyhow::{anyhow, ensure, Context, Result};
use std::io::Cursor;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

const MAX_HEAD: usize = 64 * 1024;
const MAX_FIELDS: usize = 128;
const MAX_CHUNK_LINE: usize = 4096;
const MAX_TRAILERS: usize = 16 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct ForwardLimits {
    /// Absolute exchange deadline, not an idle timeout. CONNECT is exempt.
    pub exchange_timeout: Duration,
}

impl Default for ForwardLimits {
    fn default() -> Self {
        Self {
            exchange_timeout: Duration::from_secs(300),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ForwardStats {
    pub to_upstream: u64,
    pub to_visitor: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Body {
    Empty,
    Length(u64),
    Chunked,
    Eof,
}

struct Head {
    first: Vec<u8>,
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    end: usize,
}

fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn ows(mut b: &[u8]) -> &[u8] {
    while matches!(b.first(), Some(b' ' | b'\t')) {
        b = &b[1..];
    }
    while matches!(b.last(), Some(b' ' | b'\t')) {
        b = &b[..b.len() - 1];
    }
    b
}

fn field(line: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or_else(|| anyhow!("missing header colon"))?;

    let name = &line[..colon];
    let value = ows(&line[colon + 1..]);

    ensure!(
        !name.is_empty() && name.iter().copied().all(token),
        "invalid field name"
    );
    ensure!(
        value
            .iter()
            .all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f)),
        "invalid field value"
    );

    Ok((name.to_ascii_lowercase(), value.to_vec()))
}

fn parse_head(buf: &[u8]) -> Result<Head> {
    let mut pos = 0;
    let mut first = None;
    let mut fields = Vec::new();
    let mut crlf = None;

    loop {
        let limit = buf.len().min(MAX_HEAD);
        ensure!(pos < limit, "incomplete or oversized HTTP head");

        let n = buf[pos..limit]
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| anyhow!("incomplete or oversized HTTP head"))?;

        let raw = &buf[pos..pos + n];
        let has_cr = raw.ends_with(b"\r");

        if let Some(expected) = crlf {
            ensure!(expected == has_cr, "mixed line endings");
        }
        crlf = Some(has_cr);

        let line = if has_cr {
            &raw[..raw.len() - 1]
        } else {
            raw
        };

        ensure!(!line.contains(&b'\r'), "bare CR in HTTP head");
        pos += n + 1;

        if first.is_none() {
            ensure!(!line.is_empty(), "missing start line");
            ensure!(
                line.iter().all(|&b| b >= 0x20 && b != 0x7f),
                "invalid start line"
            );
            first = Some(line.to_vec());
        } else if line.is_empty() {
            return Ok(Head {
                first: first.unwrap(),
                fields,
                end: pos,
            });
        } else {
            ensure!(fields.len() < MAX_FIELDS, "too many HTTP fields");
            fields.push(field(line)?);
        }
    }
}

fn number(value: &[u8]) -> Result<u64> {
    ensure!(
        !value.is_empty() && value.iter().all(u8::is_ascii_digit),
        "invalid Content-Length"
    );

    value.iter().try_fold(0u64, |n, &b| {
        n.checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(b - b'0')))
            .ok_or_else(|| anyhow!("Content-Length overflow"))
    })
}

fn framing(head: &Head, eof: bool) -> Result<Body> {
    let mut length = None;
    let mut chunked = false;

    for (name, value) in &head.fields {
        match name.as_slice() {
            b"content-length" => {
                ensure!(length.is_none(), "duplicate Content-Length");
                length = Some(number(value)?);
            }
            b"transfer-encoding" => {
                ensure!(
                    !chunked && value.eq_ignore_ascii_case(b"chunked"),
                    "unsupported Transfer-Encoding"
                );
                chunked = true;
            }
            _ => {}
        }
    }

    ensure!(
        !(chunked && length.is_some()),
        "Content-Length with Transfer-Encoding"
    );

    Ok(if chunked {
        Body::Chunked
    } else if let Some(n) = length {
        Body::Length(n)
    } else if eof {
        Body::Eof
    } else {
        Body::Empty
    })
}

fn encode_head(head: &Head, close: bool) -> Result<Vec<u8>> {
    let mut out = head.first.clone();
    out.extend_from_slice(b"\r\n");

    for (name, value) in &head.fields {
        ensure!(name.as_slice() != b"upgrade", "Upgrade is not supported");

        if name.as_slice() == b"connection" {
            for part in value.split(|&b| b == b',') {
                let option = ows(part);
                ensure!(
                    option.eq_ignore_ascii_case(b"close")
                        || option.eq_ignore_ascii_case(b"keep-alive"),
                    "unsupported Connection option"
                );
            }
        }

        if matches!(
            name.as_slice(),
            b"connection"
                | b"proxy-connection"
                | b"keep-alive"
                | b"te"
                | b"trailer"
        ) {
            continue;
        }

        out.extend_from_slice(name);
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }

    if close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");

    ensure!(out.len() <= MAX_HEAD, "rewritten HTTP head too large");
    Ok(out)
}

/// Validate before requesting a data/work connection or connecting a backend.
/// The caller must already have applied its Host/set/XFF rewrites.
pub fn validate_single_request(buffered: &[u8]) -> Result<()> {
    request_plan(buffered).map(|_| ())
}

fn request_plan(buffered: &[u8]) -> Result<(Head, Body, bool, bool)> {
    let mut checked = buffered.to_vec();
    rewrite_request_head(&mut checked, &Rewrite::default())?;

    let head = parse_head(&checked)?;
    let method = head
        .first
        .split(|&b| b == b' ')
        .next()
        .unwrap_or_default();

    let connect = method.eq_ignore_ascii_case(b"CONNECT");
    let is_head = method.eq_ignore_ascii_case(b"HEAD");
    let body = framing(&head, false)?;

    if !connect {
        ensure!(
            !(head.first.ends_with(b"HTTP/1.0") && body == Body::Chunked),
            "HTTP/1.0 chunked request"
        );
        encode_head(&head, true)?;
    }

    Ok((head, body, connect, is_head))
}

async fn write_bytes<W: AsyncWrite + Unpin>(
    w: &mut W,
    b: &[u8],
    count: &mut u64,
) -> Result<()> {
    w.write_all(b).await?;
    *count = count
        .checked_add(b.len() as u64)
        .ok_or_else(|| anyhow!("byte count overflow"))?;
    Ok(())
}

async fn exact<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    mut remaining: u64,
    count: &mut u64,
) -> Result<()> {
    let mut buf = [0u8; 16 * 1024];

    while remaining != 0 {
        let wanted = remaining.min(buf.len() as u64) as usize;
        let n = r.read(&mut buf[..wanted]).await?;
        ensure!(n != 0, "incomplete HTTP body");

        write_bytes(w, &buf[..n], count).await?;
        w.flush().await?;
        remaining -= n as u64;
    }

    Ok(())
}

async fn line<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();

    loop {
        ensure!(out.len() < max, "chunk framing line too large");
        let byte = r.read_u8().await.context("EOF in chunk framing")?;
        out.push(byte);

        if byte == b'\n' {
            ensure!(
                out.ends_with(b"\r\n"),
                "chunk framing requires CRLF"
            );
            out.truncate(out.len() - 2);
            ensure!(
                !out.contains(&b'\r'),
                "bare CR in chunk framing"
            );
            return Ok(out);
        }
    }
}

fn bws(b: &[u8], i: &mut usize) {
    while b
        .get(*i)
        .is_some_and(|b| *b == b' ' || *b == b'\t')
    {
        *i += 1;
    }
}

fn chunk_size(bytes: &[u8]) -> Result<u64> {
    let mut i = 0;
    let mut size = 0u64;

    while let Some(&b) = bytes.get(i) {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => break,
        };

        size = size
            .checked_mul(16)
            .and_then(|n| n.checked_add(u64::from(digit)))
            .ok_or_else(|| anyhow!("chunk size overflow"))?;
        i += 1;
    }

    ensure!(i != 0, "missing chunk size");

    while i < bytes.len() {
        bws(bytes, &mut i);
        ensure!(
            bytes.get(i) == Some(&b';'),
            "invalid chunk extension"
        );
        i += 1;
        bws(bytes, &mut i);

        let start = i;
        while bytes.get(i).is_some_and(|&b| token(b)) {
            i += 1;
        }
        ensure!(i != start, "empty chunk extension");

        let after_name = i;
        bws(bytes, &mut i);

        if bytes.get(i) != Some(&b'=') {
            ensure!(
                i == after_name || bytes.get(i) == Some(&b';'),
                "trailing extension whitespace"
            );
            continue;
        }

        i += 1;
        bws(bytes, &mut i);

        if bytes.get(i) == Some(&b'"') {
            i += 1;

            loop {
                let b = *bytes
                    .get(i)
                    .ok_or_else(|| anyhow!("unclosed chunk extension"))?;
                i += 1;

                if b == b'"' {
                    break;
                }

                if b == b'\\' {
                    let escaped = *bytes
                        .get(i)
                        .ok_or_else(|| anyhow!("truncated escape"))?;
                    ensure!(
                        escaped == b'\t'
                            || (escaped >= 0x20 && escaped != 0x7f),
                        "invalid escape"
                    );
                    i += 1;
                } else {
                    ensure!(
                        b == b'\t' || (b >= 0x20 && b != 0x7f),
                        "invalid extension value"
                    );
                }
            }
        } else {
            let start = i;
            while bytes.get(i).is_some_and(|&b| token(b)) {
                i += 1;
            }
            ensure!(i != start, "empty extension value");
        }
    }

    Ok(size)
}

async fn body<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    mode: Body,
    count: &mut u64,
) -> Result<()> {
    match mode {
        Body::Empty => {}
        Body::Length(n) => exact(r, w, n, count).await?,
        Body::Eof => {
            let mut buf = [0u8; 16 * 1024];

            loop {
                let n = r.read(&mut buf).await?;
                if n == 0 {
                    break;
                }

                write_bytes(w, &buf[..n], count).await?;
                w.flush().await?;
            }
        }
        Body::Chunked => loop {
            let size =
                chunk_size(&line(r, MAX_CHUNK_LINE).await?)?;

            if size == 0 {
                let mut bytes = 0usize;
                let mut fields = 0usize;

                loop {
                    let trailer =
                        line(r, MAX_TRAILERS - bytes).await?;
                    bytes += trailer.len() + 2;
                    ensure!(
                        bytes <= MAX_TRAILERS,
                        "trailers too large"
                    );

                    if trailer.is_empty() {
                        break;
                    }

                    fields += 1;
                    ensure!(
                        fields <= MAX_FIELDS,
                        "too many trailers"
                    );
                    field(&trailer)?;
                }

                // Trailers are validated but never merged into the head or
                // forwarded. Their declaration was removed by encode_head.
                write_bytes(w, b"0\r\n\r\n", count).await?;
                break;
            }

            write_bytes(
                w,
                format!("{size:x}\r\n").as_bytes(),
                count,
            )
            .await?;
            exact(r, w, size, count).await?;

            let mut end = [0u8; 2];
            r.read_exact(&mut end)
                .await
                .context("incomplete chunk ending")?;
            ensure!(&end == b"\r\n", "invalid chunk ending");
            write_bytes(w, b"\r\n", count).await?;
        },
    }

    w.flush().await?;
    Ok(())
}

async fn response_head<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Head> {
    let mut buf = Vec::new();
    let mut start = 0;

    loop {
        ensure!(buf.len() < MAX_HEAD, "response head too large");
        let byte = r.read_u8().await.context("EOF in response head")?;
        buf.push(byte);

        if byte == b'\n' {
            let line = &buf[start..buf.len() - 1];
            if line.is_empty() || line == b"\r" {
                return parse_head(&buf);
            }
            start = buf.len();
        }
    }
}

async fn response<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    r: &mut R,
    w: &mut W,
    is_head: bool,
    count: &mut u64,
) -> Result<()> {
    for _ in 0..16 {
        let head = response_head(r).await?;
        let parts: Vec<&[u8]> = head
            .first
            .splitn(3, |&b| b == b' ')
            .collect();

        ensure!(
            parts.len() >= 2
                && matches!(parts[0], b"HTTP/1.0" | b"HTTP/1.1"),
            "invalid response line"
        );
        ensure!(
            parts[1].len() == 3
                && parts[1].iter().all(u8::is_ascii_digit),
            "invalid status code"
        );

        let status = number(parts[1])?;
        ensure!(
            (100..=599).contains(&status) && status != 101,
            "unsupported response status"
        );

        let framing = framing(&head, true)?;

        if status < 200 {
            ensure!(
                framing == Body::Eof || framing == Body::Length(0),
                "informational response with body framing"
            );
            write_bytes(w, &encode_head(&head, false)?, count).await?;
            w.flush().await?;
            continue;
        }

        let mode = if is_head || status == 204 || status == 304 {
            Body::Empty
        } else {
            framing
        };

        write_bytes(w, &encode_head(&head, true)?, count).await?;
        w.flush().await?;
        body(r, w, mode, count).await?;
        w.shutdown().await?;
        return Ok(());
    }

    Err(anyhow!("too many informational responses"))
}

/// Own both streams; no caller can resume raw HTTP forwarding afterwards.
///
/// CONNECT is the existing legacy passthrough exception: this function does
/// not synthesize a 200 response or add new CONNECT authorization semantics.
pub async fn forward_one<V, U>(
    mut visitor: V,
    mut upstream: U,
    buffered: Vec<u8>,
    limits: ForwardLimits,
) -> Result<ForwardStats>
where
    V: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let (head, mode, connect, is_head) = request_plan(&buffered)?;

    if connect {
        upstream.write_all(&buffered).await?;
        upstream.flush().await?;

        let (sent, received) =
            tokio::io::copy_bidirectional(&mut visitor, &mut upstream)
                .await?;

        return Ok(ForwardStats {
            to_upstream: buffered.len() as u64 + sent,
            to_visitor: received,
        });
    }

    let rewritten = encode_head(&head, true)?;
    let pending = buffered[head.end..].to_vec();

    let (vr, mut vw) = tokio::io::split(visitor);
    let (mut ur, mut uw) = tokio::io::split(upstream);
    let mut sent = 0u64;
    let mut received = 0u64;

    timeout(limits.exchange_timeout, async {
        {
            let upload = async {
                write_bytes(&mut uw, &rewritten, &mut sent).await?;
                uw.flush().await?;

                let mut source = Cursor::new(pending).chain(vr);
                body(&mut source, &mut uw, mode, &mut sent).await
            };

            let download =
                response(&mut ur, &mut vw, is_head, &mut received);

            tokio::pin!(upload);
            tokio::pin!(download);

            tokio::select! {
                result = &mut upload => {
                    result?;
                    download.await?;
                }
                result = &mut download => {
                    result?;
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("HTTP exchange deadline exceeded")??;

    Ok(ForwardStats {
        to_upstream: sent,
        to_visitor: received,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn incomplete_bodies_never_finish_successfully() {
        for (wire, mode) in [
            (b"ab".as_slice(), Body::Length(3)),
            (b"3\r\nab", Body::Chunked),
            (b"3\r\nabc\r\n0\r\n", Body::Chunked),
            (b"0\r\nX-Test: value\r\n", Body::Chunked),
        ] {
            let mut source = Cursor::new(wire);
            let mut out = Vec::new();
            let mut count = 0;

            assert!(
                body(&mut source, &mut out, mode, &mut count)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn head_204_and_304_have_no_response_body() {
        for (wire, is_head) in [
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 123\r\n\r\n"
                    .as_slice(),
                true,
            ),
            (b"HTTP/1.1 204 No Content\r\n\r\n", false),
            (
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 123\r\n\r\n",
                false,
            ),
        ] {
            let mut source = Cursor::new(wire);
            let mut out = Vec::new();
            let mut count = 0;

            response(&mut source, &mut out, is_head, &mut count)
                .await
                .unwrap();
            assert!(out.ends_with(b"\r\n\r\n"));
        }
    }

    #[test]
    fn chunk_extensions_and_overflow() {
        assert_eq!(chunk_size(b"3;name=token").unwrap(), 3);
        assert_eq!(chunk_size(b"3;name=\"a\\\"b\"").unwrap(), 3);

        for bad in [
            b"".as_slice(),
            b"-1",
            b"0x10",
            b"1;",
            b"1;name=",
            b"1;name=\"bad",
            b"10000000000000000",
        ] {
            assert!(chunk_size(bad).is_err(), "{bad:?}");
        }
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    #[tokio::test]
    async fn chunked_response_stops_before_additional_bytes() {
        let mut source = Cursor::new(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Note\r\n\r\n3;x=test\r\n\x00\xff\xfe\r\n0\r\nX-Note: ignored\r\n\r\nMUST-NOT-FORWARD"
                .as_slice(),
        );
        let mut out = Vec::new();
        let mut count = 0;

        response(&mut source, &mut out, false, &mut count)
            .await
            .unwrap();

        assert!(out.ends_with(b"3\r\n\x00\xff\xfe\r\n0\r\n\r\n"));
        assert!(
            !out.windows(b"MUST-NOT-FORWARD".len())
                .any(|w| w == b"MUST-NOT-FORWARD")
        );

        let mut remaining = Vec::new();
        source.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(remaining, b"MUST-NOT-FORWARD");
    }
}
