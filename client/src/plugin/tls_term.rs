use super::{ConnectionInfo, Plugin, PluginContext};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use httparse::Status;
use orbien_core::config::PluginConfig;
use orbien_core::net::http_forward::{
    forward_one, validate_single_request, ForwardLimits,
};
use orbien_core::net::http_head::{
    rewrite_request_head, validate_rewrite_config, Rewrite,
};
use orbien_core::tls::load_or_generate_https_server_config;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;

pub struct TlsTermPlugin {
    local_addr: String,
    host_header_rewrite: String,
    request_headers: Vec<(String, String)>,
    acceptor: TlsAcceptor,
}

impl TlsTermPlugin {
    pub fn new(ctx: PluginContext, cfg: &PluginConfig) -> Result<Self> {
        let local_addr = cfg.service.trim().to_string();

        if local_addr.is_empty() {
            bail!(
                "tls-term requires plugin.service \
                 (e.g. \"127.0.0.1:80\")"
            );
        }

        let mut request_headers: Vec<(String, String)> = cfg
            .request_headers
            .set
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();

        request_headers.sort_by(|left, right| {
            left.0
                .to_ascii_lowercase()
                .cmp(&right.0.to_ascii_lowercase())
        });

        validate_rewrite_config(
            if cfg.host_header_rewrite.is_empty() {
                None
            } else {
                Some(cfg.host_header_rewrite.as_str())
            },
            &request_headers,
        )?;

        let common_name = if ctx.cert_common_name.is_empty() {
            "localhost".to_string()
        } else {
            ctx.cert_common_name.clone()
        };

        let tls_config = load_or_generate_https_server_config(
            &cfg.cert_file,
            &cfg.key_file,
            &common_name,
        )?;

        let acceptor = TlsAcceptor::from(tls_config);

        tracing::info!(
            tunnel = %ctx.name,
            local = %local_addr,
            "plugin tls-term ready (TLS terminates on agent)"
        );

        Ok(Self {
            local_addr,
            host_header_rewrite: cfg.host_header_rewrite.clone(),
            request_headers,
            acceptor,
        })
    }
}

#[async_trait]
impl Plugin for TlsTermPlugin {
    fn name(&self) -> &str {
        "tls-term"
    }

    async fn handle(&self, conn: ConnectionInfo) -> Result<()> {
        let mut tls = self
            .acceptor
            .accept(conn.stream)
            .await
            .map_err(|e| anyhow!("tls-term TLS accept failed: {e}"))?;

        let mut head = read_http_request_head(&mut tls).await?;

        rewrite_request_head(
            &mut head,
            &Rewrite {
                host: if self.host_header_rewrite.is_empty() {
                    None
                } else {
                    Some(self.host_header_rewrite.as_str())
                },
                set: &self.request_headers,
                ..Default::default()
            },
        )?;

        orbien_core::net::apply_x_forwarded_for(
            &mut head,
            &conn.src_addr,
            "https",
        )?;
        validate_single_request(&head)?;

        let local = TcpStream::connect(&self.local_addr)
            .await
            .map_err(|e| anyhow!("tls-term dial {}: {e}", self.local_addr))?;
        orbien_core::net::enable_nodelay(&local);

        forward_one(tls, local, head, ForwardLimits::default()).await?;
        Ok(())
    }
}

async fn read_http_request_head<R: AsyncReadExt + Unpin>(
    stream: &mut R,
) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];

    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("client closed before http headers completed");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 {
            bail!("http headers too large");
        }

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(&buf)? {
            Status::Complete(_) => return Ok(buf),
            Status::Partial => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> PluginContext {
        PluginContext {
            name: "rewrite-test".to_owned(),
            cert_common_name: "localhost".to_owned(),
        }
    }

    fn config() -> PluginConfig {
        PluginConfig {
            service: "127.0.0.1:8080".to_owned(),
            ..Default::default()
        }
    }

    fn startup_error(cfg: &PluginConfig) -> String {
        match TlsTermPlugin::new(context(), cfg) {
            Ok(_) => panic!("invalid rewrite configuration was accepted"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn startup_rejects_header_value_injection() {
        for value in [
            "ok\r\nInjected: yes",
            "ok\nInjected: yes",
            "ok\rInjected: yes",
        ] {
            let mut cfg = config();
            cfg.request_headers
                .set
                .insert("X-Test".to_owned(), value.to_owned());

            assert!(
                startup_error(&cfg).contains("invalid configured header value")
            );
        }
    }

    #[test]
    fn startup_rejects_protected_headers() {
        for name in [
            "Content-Length",
            "transfer-encoding",
            "CONNECTION",
            "Host",
            "X-Forwarded-For",
            "X-Forwarded-Proto",
        ] {
            let mut cfg = config();
            cfg.request_headers
                .set
                .insert(name.to_owned(), "value".to_owned());

            assert!(startup_error(&cfg).contains("protected"));
        }
    }

    #[test]
    fn startup_rejects_case_insensitive_duplicates() {
        let mut cfg = config();

        cfg.request_headers
            .set
            .insert("X-App".to_owned(), "one".to_owned());

        cfg.request_headers
            .set
            .insert("x-app".to_owned(), "two".to_owned());

        assert!(
            startup_error(&cfg).contains("duplicate configured header name")
        );
    }

    #[test]
    fn startup_rejects_invalid_name() {
        let mut cfg = config();

        cfg.request_headers
            .set
            .insert("X-Test\r\nInjected".to_owned(), "value".to_owned());

        assert!(
            startup_error(&cfg).contains("invalid configured header name")
        );
    }

    #[test]
    fn startup_rejects_host_injection() {
        let mut cfg = config();
        cfg.host_header_rewrite =
            "backend.example\r\nInjected: yes".to_owned();

        assert!(startup_error(&cfg).contains("invalid Host value"));
    }

    #[test]
    fn startup_validation_precedes_certificate_loading() {
        let mut cfg = config();
        cfg.cert_file = "does-not-exist-test-cert.pem".to_owned();
        cfg.key_file = "does-not-exist-test-key.pem".to_owned();

        cfg.request_headers
            .set
            .insert("Connection".to_owned(), "keep-alive".to_owned());

        assert!(startup_error(&cfg).contains("protected"));
    }

    #[tokio::test]
    async fn plugin_reader_then_shared_rewriter_preserves_body() {
        let body = b"\x00\xff\xfe\r\nHost: body.example\r\n";

        for eol in ["\r\n", "\n"] {
            let mut bytes = format!(
                "POST / HTTP/1.1{eol}\
                 Host: public.example{eol}\
                 Content-Length: {}{eol}\
                 X-App: forged-a{eol}\
                 x-app: forged-b{eol}{eol}",
                body.len()
            )
            .into_bytes();

            bytes.extend_from_slice(body);

            let mut reader = std::io::Cursor::new(bytes);
            let mut buffered = read_http_request_head(&mut reader).await.unwrap();

            let set = vec![("X-App".to_owned(), "trusted".to_owned())];

            rewrite_request_head(
                &mut buffered,
                &Rewrite {
                    host: Some("backend.example"),
                    set: &set,
                    ..Default::default()
                },
            )
            .unwrap();

            orbien_core::net::apply_x_forwarded_for(
                &mut buffered,
                "192.0.2.10",
                "https",
            )
            .unwrap();

            let separator = format!("{eol}{eol}").into_bytes();
            let end = buffered
                .windows(separator.len())
                .position(|window| window == separator)
                .unwrap()
                + separator.len();

            assert_eq!(&buffered[end..], body);

            let text = std::str::from_utf8(&buffered[..end]).unwrap();

            assert_eq!(text.matches("X-App: trusted").count(), 1);
            assert!(!text.contains("forged-a"));
            assert!(!text.contains("forged-b"));
            assert!(text.contains("Host: backend.example"));
            assert!(text.contains("X-Forwarded-For: 192.0.2.10"));
        }
    }
}
