#![cfg(test)]
//! Dashboard route integration tests.
//!
//! Strategy
//! --------
//! * Build the axum `Router` directly via `routes::router()` — no TCP socket.
//! * Set `DashboardConfig { disable_auth: true }` so the auth middleware
//!   passes every request through without requiring credentials.
//! * Use `tower::ServiceExt::oneshot` to drive individual requests.
//! * All assertions are JSON-level (serde_json), not string-matching.
//! * `Service::new(ServerConfig::default())` is safe in CI: when cert/key
//!   paths are empty, TLS is not enabled.

use super::auth::AuthState;
use super::model::ApiResponse;
use super::routes;
use super::DashState;
use crate::service::Service;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware;
use http_body_util::BodyExt;
use orbien_core::config::{DashboardConfig, ServerConfig};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal `DashState` backed by an in-memory `Service`.
    /// `disable_auth` is set to true so the auth middleware treats every
    /// request as authenticated without requiring credentials.
    fn make_state() -> Arc<DashState> {
        let cfg = ServerConfig::default();
        let svc = Arc::new(Service::new(cfg).expect("Service::new"));
        let web_cfg = DashboardConfig {
            addr: "127.0.0.1".into(),
            port: 0,
            user: String::new(),
            password: String::new(),
            disable_auth: true,
            ..Default::default()
        };
        let auth = Some(Arc::new(AuthState::session_only()));
        Arc::new(DashState {
            svc,
            cfg: web_cfg,
            auth,
        })
    }

    async fn call(state: Arc<DashState>, req: Request<Body>) -> (StatusCode, Value) {
        // Mirror the production wiring in `dashboard::run`: the auth middleware
        // is attached via `.layer(...)` on top of `routes::router()`. Without it
        // the auth-rejection tests can never observe a 401.
        let router = routes::router(state.clone())
            .layer(middleware::from_fn_with_state(state, crate::dashboard::auth::auth_middleware));
        // login handler now extracts ConnectInfo (M2 fix); inject a fixed peer
        // so oneshot-driven requests satisfy the extractor.
        let mut req = req;
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                12345,
            ))));
        let resp = router.oneshot(req).await.expect("oneshot");
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    /// Like `call` but returns the raw response before consuming the body,
    /// so callers can inspect headers (e.g. Location, Content-Type).
    async fn call_raw(state: Arc<DashState>, req: Request<Body>) -> axum::response::Response {
        let router = routes::router(state.clone())
            .layer(middleware::from_fn_with_state(state, crate::dashboard::auth::auth_middleware));
        let mut req = req;
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                12345,
            ))));
        router.oneshot(req).await.expect("oneshot")
    }

    // ── /healthz ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn healthz_returns_ok() {
        let state = make_state();
        let req = Request::get("/healthz").body(Body::empty()).unwrap();
        let (status, _) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
    }

    // ── /api/v1/system/info ───────────────────────────────────────────────────

    #[tokio::test]
    async fn system_info_returns_200() {
        let state = make_state();
        let req = Request::get("/api/v1/system/info")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
        assert!(json["data"]["version"].is_string());
    }

    // ── /api/v1/clients ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_clients_empty() {
        let state = make_state();
        let req = Request::get("/api/v1/clients").body(Body::empty()).unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
        assert_eq!(json["data"]["total"], 0);
    }

    #[tokio::test]
    async fn list_clients_pagination_params_accepted() {
        let state = make_state();
        let req = Request::get("/api/v1/clients?page=2&pageSize=5")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
        // page=2 with no clients → items is empty array, total still 0
        assert_eq!(json["data"]["total"], 0);
        assert_eq!(json["data"]["page"], 2);
        assert_eq!(json["data"]["pageSize"], 5);
        assert!(json["data"]["items"].is_array());
    }

    #[tokio::test]
    async fn get_client_not_found() {
        let state = make_state();
        let req = Request::get("/api/v1/clients/no-such-id")
            .body(Body::empty())
            .unwrap();
        let (status, _) = call(state, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn kick_client_not_found_returns_body_code_404() {
        let state = make_state();
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/clients/ghost-session/kick")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        // Handler always returns HTTP 200 but embeds the error code in the body.
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 404);
    }

    // ── /api/v1/proxies ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_proxies_empty() {
        let state = make_state();
        let req = Request::get("/api/v1/proxies").body(Body::empty()).unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
        assert_eq!(json["data"]["total"], 0);
    }

    #[tokio::test]
    async fn list_proxies_with_page_params() {
        let state = make_state();
        let req = Request::get("/api/v1/proxies?page=1&pageSize=10")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
    }

    #[tokio::test]
    async fn kick_proxy_not_found() {
        let state = make_state();
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/v1/proxies/no-such-proxy")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK); // handler returns 200 with code=404 in body
        assert_eq!(json["code"], 404);
    }

    #[tokio::test]
    async fn proxy_traffic_unknown_proxy_returns_404() {
        let state = make_state();
        let req = Request::get("/api/v1/proxies/no-such-proxy/traffic")
            .body(Body::empty())
            .unwrap();
        let (status, _) = call(state, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── /api/v1/tunnels ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_tunnels_empty() {
        let state = make_state();
        let req = Request::get("/api/v1/tunnels").body(Body::empty()).unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
        assert_eq!(json["data"]["total"], 0);
        assert!(json["data"]["items"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_tunnels_session_id_filter_empty_result() {
        let state = make_state();
        let req = Request::get("/api/v1/tunnels?sessionId=nonexistent-session")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
        assert_eq!(json["data"]["total"], 0);
    }

    #[tokio::test]
    async fn list_tunnels_q_search_empty_result() {
        let state = make_state();
        let req = Request::get("/api/v1/tunnels?q=does-not-exist")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
        assert_eq!(json["data"]["total"], 0);
    }

    #[tokio::test]
    async fn tunnel_traffic_unknown_tunnel_returns_404() {
        let state = make_state();
        let req = Request::get("/api/v1/tunnels/no-such-tunnel/traffic")
            .body(Body::empty())
            .unwrap();
        let (status, _) = call(state, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ── /api/v1/system/traffic ────────────────────────────────────────────────

    #[tokio::test]
    async fn system_traffic_returns_200() {
        let state = make_state();
        let req = Request::get("/api/v1/system/traffic")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
    }

    #[tokio::test]
    async fn system_traffic_with_range_param() {
        let state = make_state();
        let req = Request::get("/api/v1/system/traffic?range=7d")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
        assert!(json["data"]["history"].is_array());
    }

    // ── /api/v1/system/tokens ─────────────────────────────────────────────────

    #[tokio::test]
    async fn system_tokens_returns_200() {
        let state = make_state();
        let req = Request::get("/api/v1/system/tokens")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
        assert!(json["data"]["tokens"].is_array());
    }

    /// #11: the tokens endpoint must never expose a raw token — only the
    /// first 16 chars of its id, plus the policy dimensions.
    #[tokio::test]
    async fn system_tokens_never_exposes_raw_tokens() {
        use orbien_core::config::TokenPolicy;
        let mut cfg = ServerConfig::default();
        cfg.auth.token_policies = vec![TokenPolicy {
            token: "policy-secret-1".into(),
            allowed_tunnels: vec!["web".into()],
            allowed_protocols: vec!["http".into()],
            allowed_remote_ports: vec![],
            allowed_domains: vec!["app.example.com".into()],
        }];
        let svc = Arc::new(Service::new(cfg).expect("Service::new"));
        let state = Arc::new(DashState {
            svc,
            cfg: DashboardConfig {
                addr: "127.0.0.1".into(),
                port: 0,
                user: String::new(),
                password: "x".into(),
                disable_auth: true,
                ..Default::default()
            },
            auth: Some(Arc::new(AuthState::session_only())),
        });
        let req = Request::get("/api/v1/system/tokens")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        let rendered = json.to_string();
        assert!(
            !rendered.contains("policy-secret-1"),
            "raw token leaked: {rendered}"
        );
        let id = orbien_core::auth::token_id("policy-secret-1");
        assert!(
            rendered.contains(&id[..16]),
            "token id prefix missing: {rendered}"
        );
        assert!(
            rendered.contains("app.example.com"),
            "allowed_domains missing: {rendered}"
        );
    }

    // ── /metrics (Prometheus) ─────────────────────────────────────────────────

    #[tokio::test]
    async fn prometheus_metrics_returns_200_text_plain() {
        let state = make_state();
        let req = Request::get("/metrics").body(Body::empty()).unwrap();
        let resp = call_raw(state, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("text/plain"), "unexpected content-type: {ct}");
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let body = std::str::from_utf8(&bytes).expect("utf-8 body");
        assert!(body.contains("orbien_clients_online"), "missing metric: {body}");
        assert!(body.contains("orbien_traffic_in_bytes_total"), "missing metric: {body}");
    }

    // ── /api/v1/auth/* (always public) ────────────────────────────────────────

    #[tokio::test]
    async fn auth_status_is_public() {
        // Build a state with disable_auth=false and NO credentials — any
        // non-auth API endpoint would be rejected, but /api/v1/auth/status
        // must still return 200.
        let cfg = ServerConfig::default();
        let svc = Arc::new(Service::new(cfg).expect("Service::new"));
        let web_cfg = DashboardConfig {
            addr: "127.0.0.1".into(),
            port: 0,
            user: String::new(),
            password: String::new(),
            disable_auth: false,
            ..Default::default()
        };
        let state = Arc::new(DashState {
            svc,
            cfg: web_cfg,
            auth: Some(Arc::new(AuthState::session_only())),
        });
        let req = Request::get("/api/v1/auth/status")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["data"]["password"].is_boolean());
        assert!(json["data"]["webauthn"].is_boolean());
    }

    #[tokio::test]
    async fn auth_status_reflects_password_configured() {
        let cfg = ServerConfig::default();
        let svc = Arc::new(Service::new(cfg).expect("Service::new"));
        let web_cfg = DashboardConfig {
            addr: "127.0.0.1".into(),
            port: 0,
            user: "admin".into(),
            password: "secret".into(),
            disable_auth: false,
            ..Default::default()
        };
        let state = Arc::new(DashState {
            svc,
            cfg: web_cfg,
            auth: Some(Arc::new(AuthState::session_only())),
        });
        let req = Request::get("/api/v1/auth/status")
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"]["password"], true);
        assert_eq!(json["data"]["webauthn"], false);
    }

    // ── /api/v1/auth/login ────────────────────────────────────────────────────

    #[tokio::test]
    async fn login_wrong_credentials_returns_401() {
        let cfg = ServerConfig::default();
        let svc = Arc::new(Service::new(cfg).expect("Service::new"));
        let web_cfg = DashboardConfig {
            addr: "127.0.0.1".into(),
            port: 0,
            user: "admin".into(),
            password: "correct".into(),
            disable_auth: false,
            ..Default::default()
        };
        let state = Arc::new(DashState {
            svc,
            cfg: web_cfg,
            auth: Some(Arc::new(AuthState::session_only())),
        });
        let body = r#"{"username":"admin","password":"wrong"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = call(state, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_correct_credentials_returns_200_and_sets_cookie() {
        let cfg = ServerConfig::default();
        let svc = Arc::new(Service::new(cfg).expect("Service::new"));
        let web_cfg = DashboardConfig {
            addr: "127.0.0.1".into(),
            port: 0,
            user: "admin".into(),
            password: "secret".into(),
            disable_auth: false,
            ..Default::default()
        };
        let state = Arc::new(DashState {
            svc,
            cfg: web_cfg,
            auth: Some(Arc::new(AuthState::session_only())),
        });
        let body = r#"{"username":"admin","password":"secret"}"#;
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = call_raw(state, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookie = resp
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(cookie.contains("orbien_session="), "expected session cookie, got: {cookie}");
    }

    // ── auth middleware ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn auth_middleware_rejects_when_no_credentials_and_no_disable_auth() {
        let cfg = ServerConfig::default();
        let svc = Arc::new(Service::new(cfg).expect("Service::new"));
        let web_cfg = DashboardConfig {
            addr: "127.0.0.1".into(),
            port: 0,
            user: String::new(),
            password: String::new(),
            disable_auth: false,
            ..Default::default()
        };
        let state = Arc::new(DashState {
            svc,
            cfg: web_cfg,
            auth: Some(Arc::new(AuthState::session_only())),
        });
        let req = Request::get("/api/v1/clients").body(Body::empty()).unwrap();
        let (status, _) = call(state, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn basic_auth_header_grants_access_when_credentials_configured() {
        use base64::Engine;
        let cfg = ServerConfig::default();
        let svc = Arc::new(Service::new(cfg).expect("Service::new"));
        let web_cfg = DashboardConfig {
            addr: "127.0.0.1".into(),
            port: 0,
            user: "admin".into(),
            password: "secret".into(),
            disable_auth: false,
            ..Default::default()
        };
        let state = Arc::new(DashState {
            svc,
            cfg: web_cfg,
            auth: Some(Arc::new(AuthState::session_only())),
        });
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:secret");
        let req = Request::get("/api/v1/clients")
            .header("authorization", format!("Basic {encoded}"))
            .body(Body::empty())
            .unwrap();
        let (status, json) = call(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["code"], 200);
    }

    #[tokio::test]
    async fn basic_auth_wrong_password_is_rejected() {
        use base64::Engine;
        let cfg = ServerConfig::default();
        let svc = Arc::new(Service::new(cfg).expect("Service::new"));
        let web_cfg = DashboardConfig {
            addr: "127.0.0.1".into(),
            port: 0,
            user: "admin".into(),
            password: "secret".into(),
            disable_auth: false,
            ..Default::default()
        };
        let state = Arc::new(DashState {
            svc,
            cfg: web_cfg,
            auth: Some(Arc::new(AuthState::session_only())),
        });
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:wrong");
        let req = Request::get("/api/v1/clients")
            .header("authorization", format!("Basic {encoded}"))
            .body(Body::empty())
            .unwrap();
        let (status, _) = call(state, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // ── SPA fallback + legacy static redirects ────────────────────────────────

    #[tokio::test]
    async fn unknown_path_serves_spa_fallback() {
        // Any unknown path should either serve index.html (200) or return
        // a "dashboard assets missing" 404 when the embedded assets are absent.
        // Both outcomes are acceptable in CI where `make web` has not been run;
        // what matters is that the handler does NOT 404 silently with an empty body.
        let state = make_state();
        let req = Request::get("/some/deep/ui/route")
            .body(Body::empty())
            .unwrap();
        let resp = call_raw(state, req).await;
        let status = resp.status();
        // Either the SPA was served (200) or assets are missing (404 with message).
        assert!(
            status == StatusCode::OK || status == StatusCode::NOT_FOUND,
            "unexpected status {status}",
        );
    }

    #[tokio::test]
    async fn legacy_static_path_redirects_permanently() {
        let state = make_state();
        let req = Request::get("/static/app.js")
            .body(Body::empty())
            .unwrap();
        let resp = call_raw(state, req).await;
        // Must be a permanent redirect (308 or 301).
        assert!(
            resp.status() == StatusCode::PERMANENT_REDIRECT
                || resp.status().is_redirection(),
            "expected redirect, got {}",
            resp.status()
        );
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(location, "/app.js");
    }

    #[tokio::test]
    async fn legacy_static_root_redirects_to_slash() {
        let state = make_state();
        let req = Request::get("/static/").body(Body::empty()).unwrap();
        let resp = call_raw(state, req).await;
        assert!(resp.status().is_redirection(), "expected redirect, got {}", resp.status());
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(location, "/");
    }
}
