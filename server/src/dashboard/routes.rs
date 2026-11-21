use super::auth_routes;
use super::model::{
    ApiResponse, ClientInfo, ConfigReloadResp, Page, SystemConfig, SystemInfo, SystemStats,
    SystemStatus, TunnelInfo, TunnelTrafficPoint, TunnelTrafficResp,
};
use super::DashState;
use crate::metrics::{TrafficWindow, TunnelTrafficHistory};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use orbien_core::VERSION;
use rust_embed::Embed;
use serde::Deserialize;
use std::path::{Component, Path as FsPath, PathBuf};
use std::sync::Arc;

#[derive(Embed)]
#[folder = "assets/"]
struct Assets;

pub fn router(state: Arc<DashState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/", get(index_html))
        .route("/favicon.ico", get(favicon))
        .route("/static", get(|| async { Redirect::permanent("/") }))
        .route("/static/", get(|| async { Redirect::permanent("/") }))
        .route("/static/{*path}", get(redirect_legacy_static))
        // ── auth endpoints ──────────────────────────────────────────────────────────────────────
        .route("/api/v1/auth/status", get(auth_routes::auth_status))
        .route("/api/v1/auth/login", post(auth_routes::login))
        .route("/api/v1/auth/logout", post(auth_routes::logout))
        .route(
            "/api/v1/auth/webauthn/register/begin",
            post(auth_routes::webauthn_register_begin),
        )
        .route(
            "/api/v1/auth/webauthn/register/finish",
            post(auth_routes::webauthn_register_finish),
        )
        .route(
            "/api/v1/auth/webauthn/login/begin",
            post(auth_routes::webauthn_login_begin),
        )
        .route(
            "/api/v1/auth/webauthn/login/finish",
            post(auth_routes::webauthn_login_finish),
        )
        // ── dashboard API ───────────────────────────────────────────────────────────────────────
        .route("/api/v1/system/info", get(system_info))
        .route("/api/v1/system/health", get(system_health))
        .route("/api/v1/system/stats", get(system_stats))
        .route("/api/v1/system/traffic", get(system_traffic))
        .route("/api/v1/system/tokens", get(system_token_metrics))
        .route("/api/v1/config/reload", post(config_reload))
        .route("/metrics", get(prometheus_metrics))
        .route("/api/v1/clients", get(list_clients))
        .route("/api/v1/clients/{session_id}", get(get_client).delete(delete_client))
        .route("/api/v1/clients/{session_id}/kick", post(kick_client))
        .route("/api/v1/tunnels", get(list_tunnels))
        .route("/api/v1/tunnels/{name}", get(get_tunnel))
        .route("/api/v1/tunnels/{name}/traffic", get(tunnel_traffic))
        .route("/api/v1/proxies", get(list_tunnels))
        .route("/api/v1/proxies/{name}", delete(kick_proxy))
        .route("/api/v1/proxies/{name}/traffic", get(tunnel_traffic))
        .route("/{*path}", get(static_file))
        .with_state(state)
}

async fn redirect_legacy_static(Path(path): Path<String>) -> Redirect {
    let rel = path.trim_start_matches('/');
    if rel.is_empty() {
        Redirect::permanent("/")
    } else {
        Redirect::permanent(&format!("/{rel}"))
    }
}

#[allow(dead_code)]
#[allow(clippy::result_large_err)]
pub async fn basic_auth(
    state: axum::extract::State<Arc<DashState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    super::auth::auth_middleware(state, req, next).await
}

async fn index_html(State(state): State<Arc<DashState>>) -> Response {
    if let Some(bytes) = load_override(&state.cfg.static_dir, "index.html") {
        return bytes_response("text/html; charset=utf-8", bytes);
    }
    serve_asset("index.html")
}

async fn favicon(State(state): State<Arc<DashState>>) -> Response {
    if let Some(bytes) = load_override(&state.cfg.static_dir, "favicon.ico") {
        return bytes_response("image/x-icon", bytes);
    }
    if let Some(res) = try_embedded("favicon.ico") {
        return res;
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn static_file(State(state): State<Arc<DashState>>, Path(path): Path<String>) -> Response {
    let rel = path.trim_start_matches('/');
    if let Some(bytes) = load_override(&state.cfg.static_dir, rel) {
        return bytes_response(content_type(rel), bytes);
    }
    if let Some(res) = try_embedded(rel) {
        return res;
    }
    serve_asset("index.html")
}

fn serve_asset(path: &str) -> Response {
    if let Some(res) = try_embedded(path) {
        return res;
    }
    (
        StatusCode::NOT_FOUND,
        "dashboard assets missing — run `make web` then rebuild orbien-server",
    )
        .into_response()
}

fn try_embedded(path: &str) -> Option<Response> {
    let file = Assets::get(path)?;
    Some(bytes_response(content_type(path), file.data.into_owned()))
}

#[derive(Deserialize)]
struct PageQuery {
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_page_size", rename = "pageSize")]
    page_size: usize,
}

fn default_page() -> usize { 1 }
fn default_page_size() -> usize { 50 }

#[derive(Deserialize)]
struct TrafficQuery {
    #[serde(default)]
    range: String,
}

#[derive(serde::Serialize)]
struct TokenMetricsItem {
    /// First 16 chars of the token id (#11). The raw token is never
    /// returned by this endpoint.
    token: String,
    #[serde(rename = "activeConns")]
    active_conns: usize,
    #[serde(rename = "allowedTunnels")]
    allowed_tunnels: Vec<String>,
    #[serde(rename = "allowedProtocols")]
    allowed_protocols: Vec<String>,
    #[serde(rename = "allowedRemotePorts")]
    allowed_remote_ports: Vec<u16>,
    #[serde(rename = "allowedDomains")]
    allowed_domains: Vec<String>,
}

#[derive(serde::Serialize)]
struct TokenMetricsResp {
    tokens: Vec<TokenMetricsItem>,
}

fn traffic_window(q: &TrafficQuery) -> TrafficWindow {
    TrafficWindow::parse(&q.range)
}

fn traffic_resp(hist: TunnelTrafficHistory) -> TunnelTrafficResp {
    TunnelTrafficResp {
        name: hist.name,
        unit: hist.unit,
        granularity: hist.granularity,
        history: hist.history.into_iter().map(|p| TunnelTrafficPoint {
            date: p.date,
            traffic_in: p.traffic_in,
            traffic_out: p.traffic_out,
        }).collect(),
    }
}

// ── /healthz ──────────────────────────────────────────────────────────────────

async fn healthz() -> &'static str {
    "ok"
}

// ── /api/v1/system/health ─────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct HealthResp {
    status: &'static str,
    #[serde(rename = "uptimeSecs")]
    uptime_secs: u64,
    version: &'static str,
    #[serde(rename = "onlineClients")]
    online_clients: usize,
    #[serde(rename = "activeConnections")]
    active_connections: usize,
}

async fn system_health(State(state): State<Arc<DashState>>) -> Json<ApiResponse<HealthResp>> {
    let snap = state.svc.dashboard_snapshot().await;
    let online = snap
        .clients
        .iter()
        .filter(|c| c.status.is_empty() || c.status == "online")
        .count();
    Json(ApiResponse::ok(HealthResp {
        status: "ok",
        uptime_secs: 0,
        version: VERSION,
        online_clients: online,
        active_connections: snap.active_connections,
    }))
}

// ── /api/v1/config/reload ─────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct ReloadBody {
    #[serde(rename = "configPath", default)]
    config_path: String,
}

async fn config_reload(
    State(state): State<Arc<DashState>>,
    body: Option<Json<ReloadBody>>,
) -> Json<ApiResponse<ConfigReloadResp>> {
    let body = body.map(|b| b.0).unwrap_or_default();

    let path = if !body.config_path.is_empty() {
        body.config_path.clone()
    } else {
        state.cfg.config_file.clone().unwrap_or_default()
    };

    if path.is_empty() {
        return Json(ApiResponse {
            code: 400,
            msg: "configPath not specified and no config file path recorded at startup".into(),
            data: ConfigReloadResp { changed: vec![] },
        });
    }

    match state.svc.reload_config_file(&path).await {
        Ok(changed) => {
            tracing::info!(path = %path, ?changed, "config reloaded via dashboard");
            Json(ApiResponse::ok(ConfigReloadResp { changed }))
        }
        Err(e) => Json(ApiResponse {
            code: 422,
            msg: format!("reload failed: {e:#}"),
            data: ConfigReloadResp { changed: vec![] },
        }),
    }
}

async fn system_info(State(state): State<Arc<DashState>>) -> Json<ApiResponse<SystemInfo>> {
    let snap = state.svc.dashboard_snapshot().await;
    Json(ApiResponse::ok(SystemInfo {
        version: VERSION.to_string(),
        config: SystemConfig {
            listen: state.svc.cfg().listen.clone(),
            quic_port: state.svc.cfg().quic_port,
            kcp_port: state.svc.cfg().kcp_port,
            http_gw_port: state.svc.cfg().http_gw_port,
            https_gw_port: state.svc.cfg().https_gw_port,
            root_domain: state.svc.cfg().root_domain.clone(),
            tcp_mux: state.svc.cfg().transport.tcp_mux,
            tls_force: state.svc.cfg().transport.tls.force,
            max_conn_pool: state.svc.cfg().transport.max_conn_pool,
            heartbeat_timeout: state.svc.cfg().transport.heartbeat_timeout,
        },
        status: SystemStatus {
            client_counts: snap.clients.iter().filter(|c| c.status.is_empty() || c.status == "online").count(),
            total_client_counts: snap.total_client_counts,
            tunnel_type_count: snap.tunnel_type_count,
            active_connections: snap.active_connections,
            total_traffic_in: snap.total_traffic_in,
            total_traffic_out: snap.total_traffic_out,
        },
    }))
}

async fn system_stats(State(state): State<Arc<DashState>>) -> Json<ApiResponse<SystemStats>> {
    let snap = state.svc.dashboard_snapshot().await;
    Json(ApiResponse::ok(SystemStats {
        clients_online: snap.clients.iter().filter(|c| c.status.is_empty() || c.status == "online").count(),
        clients_total: snap.total_client_counts,
        tunnels_total: snap.tunnels.len(),
        active_connections: snap.active_connections,
        total_traffic_in: snap.total_traffic_in,
        total_traffic_out: snap.total_traffic_out,
    }))
}

async fn system_traffic(
    State(state): State<Arc<DashState>>,
    Query(q): Query<TrafficQuery>,
) -> Json<ApiResponse<TunnelTrafficResp>> {
    let hist = state.svc.metrics().server_traffic(traffic_window(&q));
    Json(ApiResponse::ok(traffic_resp(hist)))
}

async fn system_token_metrics(
    State(state): State<Arc<DashState>>,
) -> Json<ApiResponse<TokenMetricsResp>> {
    // #11: keyed by token id; displayed by the first 16 chars of the id
    // (short_token_id of the raw token). The raw token never leaves the
    // server on this endpoint.
    let policy_map = state
        .svc
        .cfg()
        .auth
        .token_policies
        .iter()
        .filter(|p| !p.token.trim().is_empty())
        .map(|p| {
            let raw = p.token.trim();
            (
                orbien_core::auth::token_id(raw),
                (
                    orbien_core::auth::short_token_id(raw),
                    p.allowed_tunnels.clone(),
                    p.allowed_protocols.clone(),
                    p.allowed_remote_ports.clone(),
                    p.allowed_domains.clone(),
                ),
            )
        })
        .collect::<std::collections::HashMap<_, _>>();

    let mut tokens = state
        .svc
        .metrics()
        .token_conn_snapshot()
        .into_iter()
        .map(|item| {
            let id = orbien_core::auth::token_id(&item.token);
            let (
                display,
                allowed_tunnels,
                allowed_protocols,
                allowed_remote_ports,
                allowed_domains,
            ) = policy_map.get(&id).cloned().unwrap_or_else(|| {
                (
                    orbien_core::auth::short_token_id(&item.token),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
            });
            TokenMetricsItem {
                token: display,
                active_conns: item.active_conns,
                allowed_tunnels,
                allowed_protocols,
                allowed_remote_ports,
                allowed_domains,
            }
        })
        .collect::<Vec<_>>();

    for (_id, (display, allowed_tunnels, allowed_protocols, allowed_remote_ports, allowed_domains)) in
        policy_map
    {
        if tokens.iter().any(|item| item.token == display) {
            continue;
        }
        tokens.push(TokenMetricsItem {
            token: display,
            active_conns: 0,
            allowed_tunnels,
            allowed_protocols,
            allowed_remote_ports,
            allowed_domains,
        });
    }

    tokens.sort_by(|a, b| a.token.cmp(&b.token));
    Json(ApiResponse::ok(TokenMetricsResp { tokens }))
}

async fn list_clients(
    State(state): State<Arc<DashState>>,
    Query(q): Query<PageQuery>,
) -> Json<ApiResponse<Page<ClientInfo>>> {
    let page = q.page.max(1);
    let page_size = q.page_size.clamp(1, 200);
    let snap = state.svc.dashboard_snapshot().await;
    let total = snap.clients.len();
    let start = (page - 1).saturating_mul(page_size);
    Json(ApiResponse::ok(Page {
        total,
        page,
        page_size,
        items: snap.clients.into_iter().skip(start).take(page_size).collect(),
    }))
}

async fn get_client(
    State(state): State<Arc<DashState>>,
    Path(session_id): Path<String>,
) -> Result<Json<ApiResponse<ClientInfo>>, StatusCode> {
    let session_id = urlencoding_decode(&session_id);
    let snap = state.svc.dashboard_snapshot().await;
    match snap.clients.into_iter().find(|c| c.session_id == session_id) {
        Some(c) => Ok(Json(ApiResponse::ok(c))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn kick_client(
    State(state): State<Arc<DashState>>,
    Path(session_id): Path<String>,
) -> Json<ApiResponse<()>> {
    let session_id = urlencoding_decode(&session_id);
    match state.svc.kick_client(&session_id).await {
        Ok(()) => Json(ApiResponse::ok(())),
        Err(e) => Json(ApiResponse { code: 404, msg: e.to_string(), data: () }),
    }
}

async fn delete_client(
    State(state): State<Arc<DashState>>,
    Path(session_id): Path<String>,
) -> Json<ApiResponse<()>> {
    let session_id = urlencoding_decode(&session_id);
    match state.svc.kick_client(&session_id).await {
        Ok(()) => Json(ApiResponse::ok(())),
        Err(e) => Json(ApiResponse { code: 404, msg: e.to_string(), data: () }),
    }
}

#[derive(Deserialize)]
struct TunnelListQuery {
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_page_size", rename = "pageSize")]
    page_size: usize,
    #[serde(default, rename = "sessionId")]
    session_id: String,
    #[serde(default)]
    q: String,
}

async fn list_tunnels(
    State(state): State<Arc<DashState>>,
    Query(q): Query<TunnelListQuery>,
) -> Json<ApiResponse<Page<TunnelInfo>>> {
    let page = q.page.max(1);
    let page_size = q.page_size.clamp(1, 200);
    let snap = state.svc.dashboard_snapshot().await;
    let session_id = q.session_id.trim();
    let needle = q.q.trim().to_ascii_lowercase();
    let filtered: Vec<TunnelInfo> = snap.tunnels.into_iter()
        .filter(|p| session_id.is_empty() || p.session_id == session_id)
        .filter(|p| needle.is_empty() || p.name.to_ascii_lowercase().contains(&needle))
        .collect();
    let total = filtered.len();
    let start = (page - 1).saturating_mul(page_size);
    Json(ApiResponse::ok(Page {
        total,
        page,
        page_size,
        items: filtered.into_iter().skip(start).take(page_size).collect(),
    }))
}

async fn get_tunnel(
    State(state): State<Arc<DashState>>,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<TunnelInfo>>, StatusCode> {
    let name = urlencoding_decode(&name);
    let snap = state.svc.dashboard_snapshot().await;
    match snap.tunnels.into_iter().find(|p| p.name == name) {
        Some(t) => Ok(Json(ApiResponse::ok(t))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn kick_proxy(
    State(state): State<Arc<DashState>>,
    Path(name): Path<String>,
) -> Json<ApiResponse<()>> {
    let name = urlencoding_decode(&name);
    match state.svc.kick_proxy(&name).await {
        Ok(()) => Json(ApiResponse::ok(())),
        Err(e) => Json(ApiResponse { code: 404, msg: e.to_string(), data: () }),
    }
}

async fn tunnel_traffic(
    State(state): State<Arc<DashState>>,
    Path(name): Path<String>,
    Query(q): Query<TrafficQuery>,
) -> Result<Json<ApiResponse<TunnelTrafficResp>>, StatusCode> {
    let name = urlencoding_decode(&name);
    match state.svc.metrics().tunnel_traffic(&name, traffic_window(&q)) {
        Some(hist) => Ok(Json(ApiResponse::ok(traffic_resp(hist)))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

fn urlencoding_decode(raw: &str) -> String {
    percent_decode(raw).unwrap_or_else(|| raw.to_string())
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let h = from_hex(bytes[i + 1])?;
                let l = from_hex(bytes[i + 2])?;
                out.push((h << 4) | l);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn load_override(static_dir: &str, rel: &str) -> Option<Vec<u8>> {
    if static_dir.trim().is_empty() { return None; }
    let path = safe_join(FsPath::new(static_dir), rel)?;
    std::fs::read(path).ok()
}

fn safe_join(base: &FsPath, rel: &str) -> Option<PathBuf> {
    let mut out = base.to_path_buf();
    for c in FsPath::new(rel).components() {
        match c {
            Component::Normal(x) => out.push(x),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

fn content_type(path: &str) -> &'static str {
    if path.ends_with(".js") || path.ends_with(".mjs") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".woff2") {
        "font/woff2"
    } else if path.ends_with(".map") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

fn bytes_response(content_type: &'static str, body: Vec<u8>) -> Response {
    (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response()
}

async fn prometheus_metrics(State(state): State<Arc<DashState>>) -> Response {
    let snap = state.svc.dashboard_snapshot().await;
    let mut out = String::new();
    out.push_str("# HELP orbien_clients_online Current number of online clients.\n");
    out.push_str("# TYPE orbien_clients_online gauge\n");
    out.push_str(&format!("orbien_clients_online {}\n", snap.clients.len()));
    out.push_str("# HELP orbien_clients_total Total clients seen.\n");
    out.push_str("# TYPE orbien_clients_total gauge\n");
    out.push_str(&format!("orbien_clients_total {}\n", snap.total_client_counts));
    out.push_str("# HELP orbien_connections_current Current active connections.\n");
    out.push_str("# TYPE orbien_connections_current gauge\n");
    out.push_str(&format!("orbien_connections_current {}\n", snap.active_connections));
    out.push_str("# HELP orbien_traffic_in_bytes_total Total bytes received.\n");
    out.push_str("# TYPE orbien_traffic_in_bytes_total counter\n");
    out.push_str(&format!("orbien_traffic_in_bytes_total {}\n", snap.total_traffic_in));
    out.push_str("# HELP orbien_traffic_out_bytes_total Total bytes sent.\n");
    out.push_str("# TYPE orbien_traffic_out_bytes_total counter\n");
    out.push_str(&format!("orbien_traffic_out_bytes_total {}\n", snap.total_traffic_out));
    out.push_str("# HELP orbien_proxy_connections_current Current connections per proxy.\n");
    out.push_str("# TYPE orbien_proxy_connections_current gauge\n");
    for p in &snap.tunnels {
        let name = prom_escape(&p.name);
        out.push_str(&format!("orbien_proxy_connections_current{{proxy=\"{name}\",type=\"{}\"}} {}\n", prom_escape(&p.tunnel_type), p.active_connections));
    }
    out.push_str("# HELP orbien_proxy_traffic_in_bytes_total Total bytes received per proxy.\n");
    out.push_str("# TYPE orbien_proxy_traffic_in_bytes_total counter\n");
    out.push_str("# HELP orbien_proxy_traffic_out_bytes_total Total bytes sent per proxy.\n");
    out.push_str("# TYPE orbien_proxy_traffic_out_bytes_total counter\n");
    for p in &snap.tunnels {
        let name = prom_escape(&p.name);
        out.push_str(&format!("orbien_proxy_traffic_in_bytes_total{{proxy=\"{name}\"}} {}\n", p.today_traffic_in));
        out.push_str(&format!("orbien_proxy_traffic_out_bytes_total{{proxy=\"{name}\"}} {}\n", p.today_traffic_out));
    }
    bytes_response("text/plain; version=0.0.4; charset=utf-8", out.into_bytes())
}

fn prom_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}
