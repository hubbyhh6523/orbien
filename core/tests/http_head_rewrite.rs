use orbien_core::net::http_head::{
    rewrite_request_head, validate_rewrite_config, Rewrite,
};
use orbien_core::net::apply_x_forwarded_for;

fn body_start(bytes: &[u8], ending: &[u8]) -> usize {
    let separator = if ending == b"\r\n" {
        b"\r\n\r\n".as_slice()
    } else {
        b"\n\n".as_slice()
    };

    bytes
        .windows(separator.len())
        .position(|window| window == separator)
        .unwrap()
        + separator.len()
}

fn field_values(bytes: &[u8], name: &[u8], ending: &[u8]) -> Vec<Vec<u8>> {
    let end = body_start(bytes, ending);
    let mut result = Vec::new();

    for raw in bytes[..end].split(|&b| b == b'\n').skip(1) {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);

        if line.is_empty() {
            break;
        }

        if let Some(colon) = line.iter().position(|&b| b == b':') {
            if line[..colon].eq_ignore_ascii_case(name) {
                let mut value = &line[colon + 1..];
                while matches!(value.first(), Some(b' ' | b'\t')) {
                    value = &value[1..];
                }
                result.push(value.to_vec());
            }
        }
    }

    result
}

#[test]
fn host_and_set_then_xff_preserve_binary_body_for_both_endings() {
    let body = b"\x00\xff\xfe\nHost: body\nX-Forwarded-For: body\n";

    for ending in [b"\r\n".as_slice(), b"\n".as_slice()] {
        let eol = std::str::from_utf8(ending).unwrap();

        let mut input = format!(
            "POST /upload HTTP/1.1{eol}\
             Host: public.example{eol}\
             Content-Length: {}{eol}\
             X-App: attacker-a{eol}\
             x-app: attacker-b{eol}\
             X-Forwarded-For: forged-a{eol}\
             x-forwarded-for: forged-b{eol}\
             X-Forwarded-Proto: ftp{eol}{eol}",
            body.len()
        )
        .into_bytes();

        input.extend_from_slice(body);

        let set = vec![("X-App".to_owned(), "trusted".to_owned())];

        rewrite_request_head(
            &mut input,
            &Rewrite {
                host: Some("backend.example"),
                set: &set,
                ..Default::default()
            },
        )
        .unwrap();

        apply_x_forwarded_for(&mut input, "192.0.2.10", "https").unwrap();

        assert_eq!(&input[body_start(&input, ending)..], body);
        assert_eq!(
            field_values(&input, b"host", ending),
            vec![b"backend.example".to_vec()]
        );
        assert_eq!(
            field_values(&input, b"x-app", ending),
            vec![b"trusted".to_vec()]
        );
        assert_eq!(
            field_values(&input, b"x-forwarded-for", ending),
            vec![b"192.0.2.10".to_vec()]
        );
        assert_eq!(
            field_values(&input, b"x-forwarded-proto", ending),
            vec![b"https".to_vec()]
        );
        assert_eq!(
            field_values(&input, b"content-length", ending),
            vec![body.len().to_string().into_bytes()]
        );

        if ending == b"\n" {
            assert!(!input[..body_start(&input, ending)].contains(&b'\r'));
        }
    }
}

#[test]
fn no_rewrite_is_byte_for_byte_noop_including_opaque_header_values() {
    for input in [
        b"POST / HTTP/1.1\r\nHost: x\r\nX-Opaque: \xff\r\nContent-Length: 3\r\n\r\n\x00\xff\xfe"
            .as_slice(),
        b"POST / HTTP/1.1\nHost: x\nX-Opaque: \xff\nContent-Length: 3\n\n\x00\xff\xfe",
    ] {
        let mut actual = input.to_vec();
        rewrite_request_head(&mut actual, &Rewrite::default()).unwrap();
        assert_eq!(actual, input);
    }
}

#[test]
fn missing_host_is_inserted_without_matching_a_body_line() {
    let body = b"Host: body.example\r\n";

    let mut input = format!(
        "POST http://public.example/ HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    input.extend_from_slice(body);

    rewrite_request_head(
        &mut input,
        &Rewrite {
            host: Some("backend.example"),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(
        field_values(&input, b"host", b"\r\n"),
        vec![b"backend.example".to_vec()]
    );
    assert_eq!(&input[body_start(&input, b"\r\n")..], body);
}

#[test]
fn set_inserts_absent_field_and_replaces_every_existing_case_variant() {
    let mut input =
        b"GET / HTTP/1.1\r\nHost: x\r\nX-App: one\r\nx-app: two\r\n\r\n".to_vec();

    let set = vec![
        ("X-App".to_owned(), "trusted".to_owned()),
        ("X-New".to_owned(), "inserted".to_owned()),
    ];

    rewrite_request_head(
        &mut input,
        &Rewrite {
            set: &set,
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(
        field_values(&input, b"x-app", b"\r\n"),
        vec![b"trusted".to_vec()]
    );
    assert_eq!(
        field_values(&input, b"x-new", b"\r\n"),
        vec![b"inserted".to_vec()]
    );
}

#[test]
fn invalid_heads_are_rejected_atomically() {
    let cases: &[&[u8]] = &[
        b"GET / HTTP/1.1\r\nHost: a\r\nhost: b\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\n Host: b\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\n\n",
        b"GET / HTTP/1.1\nHost: a\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\nX: a\rb\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551616\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a\r\n",
    ];

    for input in cases {
        let mut actual = input.to_vec();

        assert!(
            rewrite_request_head(
                &mut actual,
                &Rewrite {
                    host: Some("backend.example"),
                    ..Default::default()
                },
            )
            .is_err(),
            "accepted invalid head: {input:?}"
        );

        assert_eq!(&actual, input);
    }
}

#[test]
fn invalid_configuration_is_rejected_without_mutation() {
    let cases = [
        vec![("X-Test".to_owned(), "ok\r\nInjected: yes".to_owned())],
        vec![("X-Test".to_owned(), "ok\nInjected: yes".to_owned())],
        vec![("Bad\r\nName".to_owned(), "value".to_owned())],
        vec![("Content-Length".to_owned(), "100".to_owned())],
        vec![("transfer-encoding".to_owned(), "chunked".to_owned())],
        vec![("CONNECTION".to_owned(), "keep-alive".to_owned())],
        vec![("X-Forwarded-For".to_owned(), "forged".to_owned())],
        vec![
            ("X-App".to_owned(), "one".to_owned()),
            ("x-app".to_owned(), "two".to_owned()),
        ],
    ];

    for set in cases {
        assert!(validate_rewrite_config(None, &set).is_err());

        let mut input = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let original = input.clone();

        assert!(
            rewrite_request_head(
                &mut input,
                &Rewrite {
                    set: &set,
                    ..Default::default()
                },
            )
            .is_err()
        );

        assert_eq!(input, original);
    }

    assert!(
        validate_rewrite_config(Some("backend.example\r\nInjected: yes"), &[])
            .is_err()
    );
}

#[test]
fn host_and_set_do_not_remove_forwarded_fields_until_xff_stage() {
    let mut input =
        b"GET / HTTP/1.1\nHost: x\nX-Forwarded-For: forged\n\n".to_vec();

    rewrite_request_head(
        &mut input,
        &Rewrite {
            host: Some("backend.example"),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(
        field_values(&input, b"x-forwarded-for", b"\n"),
        vec![b"forged".to_vec()]
    );

    apply_x_forwarded_for(&mut input, "", "").unwrap();

    assert!(field_values(&input, b"x-forwarded-for", b"\n").is_empty());
}
