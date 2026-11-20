use anyhow::{anyhow, ensure, Result};
use std::collections::HashSet;
use std::net::IpAddr;

const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 128;

#[derive(Debug, Clone, Copy)]
pub struct Forwarded<'a> {
    pub client_ip: Option<IpAddr>,
    pub scheme: Option<&'a str>,
}

#[derive(Debug, Default)]
pub struct Rewrite<'a> {
    pub host: Option<&'a str>,
    pub set: &'a [(String, String)],

    /// None preserves existing forwarding headers.
    ///
    /// Some removes every incoming X-Forwarded-For/X-Forwarded-Proto
    /// and optionally inserts the trusted values.
    pub forwarded: Option<Forwarded<'a>>,
}

struct Field<'a> {
    name: &'a [u8],
    raw: &'a [u8],
}

struct ParsedHead<'a> {
    first: &'a [u8],
    fields: Vec<Field<'a>>,
    ending: &'static [u8],
    end: usize,
}

fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn valid_value(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }

    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }

    value
}

fn validate_host(host: &[u8]) -> Result<()> {
    ensure!(!host.is_empty(), "empty Host value");

    ensure!(
        host.iter().all(|&b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        }),
        "invalid Host value"
    );

    Ok(())
}

fn protected_set_name(name: &[u8]) -> bool {
    [
        b"host".as_slice(),
        b"content-length",
        b"transfer-encoding",
        b"connection",
        b"proxy-connection",
        b"keep-alive",
        b"upgrade",
        b"te",
        b"trailer",
        b"x-forwarded-for",
        b"x-forwarded-proto",
    ]
    .iter()
    .any(|protected| name.eq_ignore_ascii_case(protected))
}

/// Validate configuration without needing an incoming HTTP request.
///
/// Errors intentionally do not include configured values, which may contain
/// secrets.
pub fn validate_rewrite_config(
    host: Option<&str>,
    set: &[(String, String)],
) -> Result<()> {
    if let Some(host) = host {
        validate_host(host.as_bytes())?;
    }

    let mut names = HashSet::new();

    for (name, value) in set {
        ensure!(
            !name.is_empty() && name.bytes().all(is_token),
            "invalid configured header name"
        );

        ensure!(
            valid_value(value.as_bytes()),
            "invalid configured header value"
        );

        ensure!(
            !protected_set_name(name.as_bytes()),
            "configured header is protected"
        );

        ensure!(
            names.insert(name.to_ascii_lowercase()),
            "duplicate configured header name"
        );
    }

    Ok(())
}

fn read_line<'a>(
    buf: &'a [u8],
    start: usize,
    ending: &[u8],
) -> Result<(&'a [u8], usize)> {
    ensure!(start < MAX_HEAD_BYTES, "HTTP head too large");

    let limit = buf.len().min(MAX_HEAD_BYTES);
    ensure!(start < limit, "incomplete HTTP head");

    let relative = buf[start..limit]
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| anyhow!("incomplete or oversized HTTP head"))?;

    let newline = start + relative;
    let raw = &buf[start..newline];

    let line = if ending == b"\r\n" {
        raw.strip_suffix(b"\r")
            .ok_or_else(|| anyhow!("mixed HTTP line endings"))?
    } else {
        ensure!(!raw.ends_with(b"\r"), "mixed HTTP line endings");
        raw
    };

    ensure!(!line.contains(&b'\r'), "bare CR in HTTP head");

    Ok((line, newline + 1))
}

fn parse_head(buf: &[u8]) -> Result<ParsedHead<'_>> {
    let limit = buf.len().min(MAX_HEAD_BYTES);

    let first_newline = buf[..limit]
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| anyhow!("incomplete or oversized HTTP head"))?;

    let ending: &'static [u8] =
        if first_newline > 0 && buf[first_newline - 1] == b'\r' {
            b"\r\n"
        } else {
            b"\n"
        };

    let (first, mut position) = read_line(buf, 0, ending)?;

    let parts: Vec<&[u8]> = first.split(|&b| b == b' ').collect();

    ensure!(
        parts.len() == 3 && parts.iter().all(|part| !part.is_empty()),
        "invalid HTTP request line"
    );

    ensure!(
        parts[0].iter().copied().all(is_token),
        "invalid HTTP method"
    );

    ensure!(
        parts[1].iter().all(u8::is_ascii_graphic),
        "invalid HTTP request target"
    );

    ensure!(
        parts[2] == b"HTTP/1.1" || parts[2] == b"HTTP/1.0",
        "unsupported HTTP version"
    );

    let mut fields = Vec::new();
    let mut hosts = 0usize;
    let mut content_length = false;
    let mut transfer_encoding = false;

    loop {
        let (line, next) = read_line(buf, position, ending)?;
        position = next;

        if line.is_empty() {
            break;
        }

        ensure!(fields.len() < MAX_HEADERS, "too many HTTP headers");

        let colon = line
            .iter()
            .position(|&b| b == b':')
            .ok_or_else(|| anyhow!("missing header colon"))?;

        let name = &line[..colon];
        let value = trim_ows(&line[colon + 1..]);

        ensure!(
            !name.is_empty() && name.iter().copied().all(is_token),
            "invalid header name or folded header"
        );

        ensure!(valid_value(value), "invalid header value");

        if name.eq_ignore_ascii_case(b"host") {
            hosts += 1;
            ensure!(hosts == 1, "duplicate Host");
            validate_host(value)?;
        }

        if name.eq_ignore_ascii_case(b"content-length") {
            ensure!(!content_length, "duplicate Content-Length");
            content_length = true;

            ensure!(
                !value.is_empty() && value.iter().all(u8::is_ascii_digit),
                "invalid Content-Length"
            );

            // Check overflow without converting the head or body to text.
            let mut length = 0u64;
            for &digit in value {
                length = length
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(u64::from(digit - b'0')))
                    .ok_or_else(|| anyhow!("Content-Length overflow"))?;
            }
        }

        if name.eq_ignore_ascii_case(b"transfer-encoding") {
            ensure!(!transfer_encoding, "duplicate Transfer-Encoding");
            transfer_encoding = true;
        }

        fields.push(Field { name, raw: line });
    }

    ensure!(
        !(content_length && transfer_encoding),
        "Content-Length and Transfer-Encoding cannot coexist"
    );

    Ok(ParsedHead {
        first,
        fields,
        ending,
        end: position,
    })
}

fn append_field(out: &mut Vec<u8>, name: &[u8], value: &[u8], ending: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(ending);
}

/// Rewrite only the first request head.
///
/// Everything after its terminating empty line is copied byte for byte.
/// On validation failure, `buf` is unchanged.
///
/// This function does not parse request bodies or enforce request boundaries.
/// It does not prevent a pipelined second request from being forwarded later.
pub fn rewrite_request_head(buf: &mut Vec<u8>, rewrite: &Rewrite<'_>) -> Result<()> {
    validate_rewrite_config(rewrite.host, rewrite.set)?;

    if let Some(forwarded) = rewrite.forwarded {
        if let Some(scheme) = forwarded.scheme {
            ensure!(
                scheme == "http" || scheme == "https",
                "invalid forwarded scheme"
            );
        }
    }

    let parsed = parse_head(buf)?;

    let replacements: HashSet<Vec<u8>> = rewrite
        .set
        .iter()
        .map(|(name, _)| name.as_bytes().to_ascii_lowercase())
        .collect();

    let mut out = Vec::with_capacity(buf.len());

    out.extend_from_slice(parsed.first);
    out.extend_from_slice(parsed.ending);

    for field in &parsed.fields {
        if rewrite.host.is_some() && field.name.eq_ignore_ascii_case(b"host") {
            continue;
        }

        if rewrite.forwarded.is_some()
            && (field.name.eq_ignore_ascii_case(b"x-forwarded-for")
                || field.name.eq_ignore_ascii_case(b"x-forwarded-proto"))
        {
            continue;
        }

        if replacements.contains(&field.name.to_ascii_lowercase()) {
            continue;
        }

        // Preserve untouched header bytes, including non-UTF-8 values.
        out.extend_from_slice(field.raw);
        out.extend_from_slice(parsed.ending);
    }

    if let Some(host) = rewrite.host {
        append_field(&mut out, b"Host", host.as_bytes(), parsed.ending);
    }

    for (name, value) in rewrite.set {
        append_field(
            &mut out,
            name.as_bytes(),
            value.as_bytes(),
            parsed.ending,
        );
    }

    if let Some(forwarded) = rewrite.forwarded {
        if let Some(ip) = forwarded.client_ip {
            append_field(
                &mut out,
                b"X-Forwarded-For",
                ip.to_string().as_bytes(),
                parsed.ending,
            );
        }

        if let Some(scheme) = forwarded.scheme {
            append_field(
                &mut out,
                b"X-Forwarded-Proto",
                scheme.as_bytes(),
                parsed.ending,
            );
        }
    }

    // Bound only the rewritten head, not a body read in the same socket read.
    ensure!(
        out.len() + parsed.ending.len() <= MAX_HEAD_BYTES,
        "rewritten HTTP head too large"
    );

    out.extend_from_slice(parsed.ending);
    out.extend_from_slice(&buf[parsed.end..]);

    *buf = out;
    Ok(())
}
