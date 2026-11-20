use super::vhost::{build_domains, normalize_host, HttpRoute, HttpVhost};
use super::{acquire_conn, ConnGuard};
use crate::access::{prepare_visitor, AccessPolicy};
use crate::control::Control;
use crate::metrics::ServerMetrics;
use anyhow::{anyhow, bail, Result};
use httparse::Status;
use orbien_core::limit::{maybe_limit, BandwidthLimiter};
use orbien_core::msg::NewProxy;
use orbien_core::net::http_head::{rewrite_request_head, Rewrite};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

pub struct HttpProxy {
    pub name: String,
    pub domains: Vec<String>,
    run_id: String,
    vhost: Arc<HttpVhost>,
    closed: AtomicBool,
}

impl HttpProxy {
    pub async fn register(
        np: &NewProxy,
        control: Arc<Control>,
        vhost: Arc<HttpVhost>,
        sub_domain_host: &str,
        limiter: Option<Arc<BandwidthLimiter>>,
    ) -> Result<Self> {
        let domains = build_domains(&np.custom_domains, &np.subdomain, sub_domain_host)?;
        let name = np.proxy_name.clone();
        let locations = np.locations.clone();
        let rewrite = np.host_header_rewrite.clone();
        let active_conns = Arc::new(AtomicUsize::new(0));

        for domain in &domains {
            if let Err(e) = vhost
                .register(
                    domain,
                    HttpRoute {
                        proxy_name: name.clone(),
                        run_id: control.run_id.clone(),
                        control: Arc::downgrade(&control),
                        locations: locations.clone(),
                        host_header_rewrite: rewrite.clone(),
                        limiter: limiter.clone(),
                        active_conns: Arc::clone(&active_conns),
                        max_connections: np.max_connections,
                    },
                )
                .await
            {
                vhost.unregister_proxy(&name, &control.run_id).await;
                return Err(e);
            }
        }

        tracing::info!(
            proxy = %name,
            domains = ?domains,
            "http proxy registered"
        );

        Ok(Self {
            name,
            domains,
            run_id: control.run_id.clone(),
            vhost,
            closed: AtomicBool::new(false),
        })
    }

    pub async fn close(&self) {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.vhost.unregister_proxy(&self.name, &self.run_id).await;
        }
    }
}

pub async fn run_vhost_http_listener(
    bind_addr: String,
    port: u16,
    vhost: Arc<HttpVhost>,
    access: Arc<AccessPolicy>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let addr = format!("{bind_addr}:{port}");
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "http vhost listener ready");

    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let vhost = Arc::clone(&vhost);
                        let access = Arc::clone(&access);
                        tokio::spawn(async move {
                            if let Err(e) = handle_http_visitor(vhost, stream, peer, access).await {
                                tracing::debug!(%peer, error = %e, "http visitor ended");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "http vhost accept failed");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_http_visitor(
    vhost: Arc<HttpVhost>,
    stream: TcpStream,
    peer: std::net::SocketAddr,
    access: Arc<AccessPolicy>,
) -> Result<()> {
    let mut visitor = prepare_visitor(stream, peer, &access).await?;
    let (mut head, host, path) = read_http_request_head(&mut visitor.stream).await?;
    let Some(route) = vhost.lookup(&host, &path).await else {
        tracing::debug!(peer = %visitor.peer, visitor = %visitor.visitor, %host, %path, "http no route");
        write_not_found(&mut visitor.stream).await;
        return Ok(());
    };

    let Some(control) = route.control.upgrade() else {
        write_not_found(&mut visitor.stream).await;
        return Err(anyhow!("http proxy client gone: {}", route.proxy_name));
    };

    if !acquire_conn(&route.active_conns, route.max_connections) {
        tracing::warn!(
            proxy = %route.proxy_name,
            max_connections = route.max_connections,
            peer = %visitor.peer,
            "connection limit reached, dropping"
        );
        write_service_unavailable(&mut visitor.stream).await;
        return Ok(());
    }
    let _limit_guard = ConnGuard(Arc::clone(&route.active_conns));

    rewrite_request_head(
        &mut head,
        &Rewrite {
            host: if route.host_header_rewrite.is_empty() {
                None
            } else {
                Some(route.host_header_rewrite.as_str())
            },
            ..Default::default()
        },
    )?;

    orbien_core::net::apply_x_forwarded_for(&mut head, &visitor.visitor.ip().to_string(), "http")?;

    let work = match control.get_work_conn().await {
        Ok(w) => w,
        Err(e) => {
            write_bad_gateway(&mut visitor.stream).await;
            return Err(e);
        }
    };
    let work = control
        .start_work_conn(
            work,
            &route.proxy_name,
            visitor.visitor.ip().to_string(),
            visitor.visitor.port(),
            visitor
                .local
                .map(|a| a.ip().to_string())
                .unwrap_or_default(),
            visitor.local.map(|a| a.port()).unwrap_or(0),
        )
        .await?;

    let mut work = maybe_limit(work, route.limiter.clone());
    let head_len = head.len() as u64;
    work.write_all(&head).await?;
    tracing::debug!(
        proxy = %route.proxy_name,
        %host,
        %path,
        peer = %visitor.peer,
        visitor = %visitor.visitor,
        "http joining visitor <-> work"
    );
    let _guard = control.metrics.track_connection(&route.proxy_name, "http");
    let (to_work, from_work, err) = orbien_core::io::join_counted(visitor.stream, work).await;
    control
        .metrics
        .add_traffic_in(&route.proxy_name, "http", to_work.saturating_add(head_len));
    control
        .metrics
        .add_traffic_out(&route.proxy_name, "http", from_work);
    if let Some(e) = err {
        tracing::debug!(proxy = %route.proxy_name, error = %e, "http join ended");
    }
    Ok(())
}

async fn read_http_request_head<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(Vec<u8>, String, String)> {
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
            Status::Complete(_) => {
                let host = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("host"))
                    .map(|h| String::from_utf8_lossy(h.value).into_owned())
                    .ok_or_else(|| anyhow!("missing Host header"))?;
                let path = req.path.unwrap_or("/").to_string();
                return Ok((buf, normalize_host(&host), path));
            }
            Status::Partial => continue,
        }
    }
}

pub async fn write_not_found<W: AsyncWrite + Unpin>(stream: &mut W) {
    let body = "Not Found\n";
    let resp = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}

async fn write_service_unavailable<W: AsyncWrite + Unpin>(stream: &mut W) {
    let body = "Service Unavailable\n";
    let resp = format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}

async fn write_bad_gateway<W: AsyncWrite + Unpin>(stream: &mut W) {
    let body = "Bad Gateway\n";
    let resp = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}
