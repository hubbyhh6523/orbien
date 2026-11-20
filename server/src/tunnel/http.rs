use super::gw::{
    build_domains, expand_locations, normalize_host, route_basic_auth_ok, route_user_from_headers,
    HttpGw, HttpRoute,
};
use crate::access::{prepare_ingress, AccessPolicy};
use crate::control::Control;
use crate::metrics::ServerMetrics;
use anyhow::{anyhow, bail, Result};
use httparse::Status;
use orbien_core::limit::{maybe_limit, BandwidthLimiter};
use orbien_core::msg::NewTunnel;
use orbien_core::net::http_forward::{
    forward_one, validate_single_request, ForwardLimits,
};
use orbien_core::net::http_head::{rewrite_request_head, Rewrite};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, RwLock};

pub struct HttpTunnel {
    pub name: String,
    pub domains: Vec<String>,
    gw: Arc<HttpGw>,
    closed: AtomicBool,
}

impl HttpTunnel {
    pub async fn register(
        np: &NewTunnel,
        control: Arc<Control>,
        gw: Arc<HttpGw>,
        sub_domain_host: &str,
        limiter: Option<Arc<BandwidthLimiter>>,
    ) -> Result<Self> {
        let domains = build_domains(&np.domains, sub_domain_host)?;
        let name = np.tunnel_name.clone();
        let locations = expand_locations(&np.locations);
        let rewrite = np.host_header_rewrite.clone();
        let basic_auth_user = np.basic_auth_user.clone();
        let basic_auth_password = np.basic_auth_password.clone();
        let route_by_http_user = np.route_by_http_user.clone();

        gw.unregister_tunnel(&name).await;

        for domain in &domains {
            for location in &locations {
                gw.register(
                    domain,
                    HttpRoute {
                        tunnel_name: name.clone(),
                        control: Arc::downgrade(&control),
                        location: location.clone(),
                        host_header_rewrite: rewrite.clone(),
                        basic_auth_user: basic_auth_user.clone(),
                        basic_auth_password: basic_auth_password.clone(),
                        route_by_http_user: route_by_http_user.clone(),
                        limiter: limiter.clone(),
                    },
                )
                .await?;
            }
        }

        tracing::info!(
            tunnel = %name,
            domains = ?domains,
            locations = ?locations,
            route_by_http_user = %route_by_http_user,
            basic_auth = !basic_auth_user.is_empty() || !basic_auth_password.is_empty(),
            "http tunnel registered"
        );

        Ok(Self {
            name,
            domains,
            gw,
            closed: AtomicBool::new(false),
        })
    }

    pub async fn close(&self) {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.gw.unregister_tunnel(&self.name).await;
        }
    }
}

pub async fn run_http_gw_listener(
    bind_addr: String,
    port: u16,
    gw: Arc<HttpGw>,
    access: Arc<RwLock<Arc<AccessPolicy>>>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let addr = format!("{bind_addr}:{port}");
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "http gateway listener ready");

    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        orbien_core::net::enable_nodelay(&stream);
                        let gw = Arc::clone(&gw);
                        // Snapshot current policy; hot-reload swaps this on the next connection.
                        let access = Arc::clone(&*access.read().await);
                        tokio::spawn(async move {
                            if let Err(e) = handle_http_ingress(gw, stream, peer, access).await {
                                tracing::debug!(%peer, error = %e, "http ingress ended");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "http gateway accept failed");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

struct ParsedHttpHead {
    raw: Vec<u8>,
    host: String,
    path: String,
    is_proxy_request: bool,
    authorization: Option<String>,
    proxy_authorization: Option<String>,
}

async fn handle_http_ingress(
    gw: Arc<HttpGw>,
    stream: TcpStream,
    peer: std::net::SocketAddr,
    access: Arc<AccessPolicy>,
) -> Result<()> {
    let mut ingress = prepare_ingress(stream, peer, &access).await?;
    let head = read_http_request_head(&mut ingress.stream).await?;

    let route_user = route_user_from_headers(
        head.is_proxy_request,
        head.authorization.as_deref(),
        head.proxy_authorization.as_deref(),
    );

    let Some(route) = gw.lookup(&head.host, &head.path, &route_user).await else {
        tracing::debug!(
            peer = %ingress.peer,
            source = %ingress.source,
            host = %head.host,
            path = %head.path,
            %route_user,
            "http no route"
        );
        write_not_found(&mut ingress.stream).await;
        return Ok(());
    };

    if !route_basic_auth_ok(
        &route,
        head.is_proxy_request,
        head.authorization.as_deref(),
        head.proxy_authorization.as_deref(),
    ) {
        tracing::debug!(
            tunnel = %route.tunnel_name,
            peer = %ingress.peer,
            proxy_mode = head.is_proxy_request,
            "http basic auth failed"
        );
        if head.is_proxy_request {
            write_proxy_unauthorized(&mut ingress.stream).await;
        } else {
            write_unauthorized(&mut ingress.stream).await;
        }
        return Ok(());
    }

    let Some(control) = route.control.upgrade() else {
        write_not_found(&mut ingress.stream).await;
        return Err(anyhow!("http tunnel client gone: {}", route.tunnel_name));
    };

    let mut raw = head.raw;
    rewrite_request_head(
        &mut raw,
        &Rewrite {
            host: if route.host_header_rewrite.is_empty() {
                None
            } else {
                Some(route.host_header_rewrite.as_str())
            },
            ..Default::default()
        },
    )?;

    orbien_core::net::apply_x_forwarded_for(
        &mut raw,
        &ingress.source.ip().to_string(),
        "http",
    )?;
    validate_single_request(&raw)?;

    let data = match control.get_data_conn().await {
        Ok(w) => w,
        Err(e) => {
            write_bad_gateway(&mut ingress.stream).await;
            return Err(e);
        }
    };

    let data = control
        .start_data_conn(
            data,
            &route.tunnel_name,
            ingress.source.ip().to_string(),
            ingress.source.port(),
            ingress
                .local
                .map(|a| a.ip().to_string())
                .unwrap_or_default(),
            ingress.local.map(|a| a.port()).unwrap_or(0),
        )
        .await?;

    let data = maybe_limit(data, route.limiter.clone());
    let _guard = control.metrics.track_connection(&route.tunnel_name, "http");

    let stats = forward_one(
        ingress.stream,
        data,
        raw,
        ForwardLimits::default(),
    )
    .await?;

    control.metrics.add_traffic_in(
        &route.tunnel_name,
        "http",
        stats.to_upstream,
    );
    control.metrics.add_traffic_out(
        &route.tunnel_name,
        "http",
        stats.to_visitor,
    );
    Ok(())
}

async fn read_http_request_head<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<ParsedHttpHead> {
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
                let method = req.method.unwrap_or("").to_string();
                let target = req.path.unwrap_or("/").to_string();
                let (is_proxy_request, path) =
                    classify_request_target(&method, &target);

                let host = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("host"))
                    .map(|h| String::from_utf8_lossy(h.value).into_owned())
                    .or_else(|| host_from_absolute_target(&target))
                    .ok_or_else(|| anyhow!("missing Host header"))?;

                let authorization = header_value(&req, "authorization");
                let proxy_authorization =
                    header_value(&req, "proxy-authorization");

                return Ok(ParsedHttpHead {
                    raw: buf,
                    host: normalize_host(&host),
                    path,
                    is_proxy_request,
                    authorization,
                    proxy_authorization,
                });
            }
            Status::Partial => continue,
        }
    }
}

fn header_value(req: &httparse::Request<'_, '_>, name: &str) -> Option<String> {
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| String::from_utf8_lossy(h.value).into_owned())
}

fn classify_request_target(method: &str, target: &str) -> (bool, String) {
    if method.eq_ignore_ascii_case("CONNECT") {
        return (true, "/".into());
    }
    if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .or_else(|| target.strip_prefix("HTTP://"))
        .or_else(|| target.strip_prefix("HTTPS://"))
    {
        let path = match rest.find('/') {
            Some(i) => rest[i..].to_string(),
            None => "/".into(),
        };
        return (true, path);
    }
    (false, target.to_string())
}

fn host_from_absolute_target(target: &str) -> Option<String> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
        .or_else(|| target.strip_prefix("HTTP://"))
        .or_else(|| target.strip_prefix("HTTPS://"))?;
    let hostport = rest.split('/').next().unwrap_or(rest);
    if hostport.is_empty() {
        None
    } else {
        Some(hostport.to_string())
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

async fn write_unauthorized<W: AsyncWrite + Unpin>(stream: &mut W) {
    let body = "Unauthorized\n";
    let resp = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"Restricted\"\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}

async fn write_proxy_unauthorized<W: AsyncWrite + Unpin>(stream: &mut W) {
    let body = "Proxy Authentication Required\n";
    let resp = format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Restricted\"\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
