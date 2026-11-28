use super::{auth, routes, DashState};
use crate::service::Service;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware;
use http_body_util::BodyExt;
use orbien_core::auth::token_id;
use orbien_core::config::{DashboardConfig, ServerConfig};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

struct ConfigFile(std::path::PathBuf);

impl ConfigFile {
    fn new(text: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = loop {
            let dir = std::env::temp_dir().join(format!(
                "orbien-step3-{}-{}",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("create test directory: {e}"),
            }
        };
        let path = dir.join("config.toml");
        std::fs::write(&path, text).unwrap();
        Self(path)
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.parent().unwrap());
    }
}

const INITIAL: &str = r#"
[[auth.token_policies]]
token = 'stable-token'
allowed_tunnels = ['db']
allowed_protocols = ['tcp']
allowed_remote_ports = [3306]
"#;

/// #3: the state records the temp file as its startup config, so reloads
/// re-read it. The `ConfigFile` must be kept alive by the caller — dropping
/// it deletes the directory.
fn state() -> (Arc<DashState>, ConfigFile) {
    let initial = ConfigFile::new(INITIAL);
    let cfg = ServerConfig::load(&initial.0).unwrap();
    let mut dash_cfg = DashboardConfig {
        disable_auth: true,
        ..Default::default()
    };
    dash_cfg.config_file = Some(initial.0.to_str().unwrap().to_owned());
    let state = Arc::new(DashState {
        svc: Arc::new(Service::new(cfg).unwrap()),
        cfg: dash_cfg,
        auth: Some(Arc::new(auth::AuthState::session_only())),
        trusted_proxies: vec![],
    });
    (state, initial)
}

/// #3: reload takes no path — it re-reads the file recorded at startup.
/// Returns the HTTP status alongside the JSON body (errors answer 422).
async fn reload(state: Arc<DashState>) -> (StatusCode, Value) {
    let router = routes::router(Arc::clone(&state))
        .layer(middleware::from_fn_with_state(state, auth::auth_middleware));
    let response = router
        .oneshot(
            Request::post("/api/v1/config/reload")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// Write `text` into the recorded startup file, reload, and assert the
/// reload failed with `reason` in the message while the live policy and
/// the running config stayed untouched.
async fn assert_unchanged(state: &Arc<DashState>, text: &str, reason: &str) {
    let before = state.svc.access_policy().await;
    let config_before = serde_json::to_value(state.svc.cfg()).unwrap();
    let path = state.cfg.config_file.clone().expect("config_file recorded");
    std::fs::write(&path, text).unwrap();
    let (status, result) = reload(Arc::clone(state)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{result}");
    assert_eq!(result["code"], 422, "{result}");
    assert_eq!(result["data"]["changed"], json!([]));
    assert!(result["msg"].as_str().unwrap().contains(reason), "{result}");
    let after = state.svc.access_policy().await;
    assert!(Arc::ptr_eq(&before, &after));
    assert_eq!(config_before, serde_json::to_value(state.svc.cfg()).unwrap());
    assert!(after.authorize_proxy(&token_id("stable-token"), "db", "tcp", Some(3306)).is_ok());
    assert!(after.authorize_proxy(&token_id("replacement-token"), "db", "tcp", Some(5432)).is_err());
}

#[tokio::test]
async fn reload_api_unknown_keys_reject_entire_candidate_atomically() {
    let (state, _file) = state();
    for (text, reason) in [
        ("denySrcCidr = ['127.0.0.1/32']", "denySrcCidr"),
        ("[transport.tls]\ntrusted_ca = 'ignored.pem'", "trusted_ca"),
        ("denySrcCidrs = ['127.0.0.1/32']\n[[auth.token_policies]]\ntoken = 'replacement-token'\nallowed_remote_port = [5432]", "allowed_remote_port"),
    ] {
        assert_unchanged(&state, text, reason).await;
    }
}

#[tokio::test]
async fn reload_api_semantic_policy_and_tls_errors_are_atomic() {
    let (state, _file) = state();
    for (text, reason) in [
        ("httpGwPort = 9527", "must not share a TCP listen"),
        ("[dashboard]\nport = 8020", "dashboard.user and dashboard.password"),
        ("denySrcCidrs = ['10.0.0.0/99']", "access policy preflight"),
        ("[transport.tls]\ncertFile = 'missing-cert.pem'\nkeyFile = 'missing-key.pem'", "transport.tls preflight"),
        ("[[auth.token_policies]]\ntoken = 'x'\nallowed_domains = ['bad_*.com']", "invalid allowed_domains pattern"),
        ("[[auth.token_policies]]\ntoken = 'dup'\n[[auth.token_policies]]\ntoken = 'dup'", "duplicate token in token_policies"),
    ] {
        assert_unchanged(&state, text, reason).await;
    }
}

#[tokio::test]
async fn reload_api_missing_file_and_missing_env_are_atomic() {
    let (state, file) = state();
    let before = state.svc.access_policy().await;
    std::fs::remove_file(&file.0).unwrap();
    let (status, result) = reload(Arc::clone(&state)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{result}");
    assert_eq!(result["code"], 422);
    assert!(result["msg"].as_str().unwrap().contains("failed to read config file"));
    assert!(Arc::ptr_eq(&before, &state.svc.access_policy().await));
    let key = format!("ORBIEN_ISSUE20_UNSET_{}_7C01", std::process::id());
    assert!(std::env::var_os(&key).is_none());
    assert_unchanged(&state, &format!("rootDomain = '{{{{env.{key}}}}}'"), "is not set").await;
}

#[tokio::test]
async fn reload_api_success_uses_env_completion_relative_tls_paths_and_recorded_path() {
    use base64::Engine;
    let (state, file) = state();
    let dir = file.0.parent().unwrap().to_path_buf();
    std::fs::write(
        &file.0,
        r#"
listen = '{{env.ORBIEN_ISSUE20_DEFAULT_LISTEN_7C01:127.0.0.1:9527}}'
[transport.tls]
trustedCaFile = 'fixture.crt'
certFile = 'fixture.crt'
keyFile = 'fixture.key'
[[auth.token_policies]]
token = 'next-token'
allowed_tunnels = ['db']
allowed_protocols = ['tcp']
allowed_remote_ports = [5432]
"#,
    )
    .unwrap();
    let certificate = orbien_core::transport::generate_self_signed_cert("localhost").unwrap();
    let encoder = base64::engine::general_purpose::STANDARD;
    std::fs::write(dir.join("fixture.crt"), format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        encoder.encode(certificate.certs[0].as_ref())
    )).unwrap();
    std::fs::write(dir.join("fixture.key"), format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        encoder.encode(certificate.key.secret_pkcs8_der())
    )).unwrap();
    let loaded = ServerConfig::load(&file.0).unwrap();
    assert!(loaded.transport.tls.force);
    assert!(std::path::Path::new(&loaded.transport.tls.cert_file).is_absolute());
    let (status, result) = reload(Arc::clone(&state)).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["code"], 200, "{result}");
    let policy = state.svc.access_policy().await;
    assert!(policy.authorize_proxy(&token_id("next-token"), "db", "tcp", Some(5432)).is_ok());
    assert!(policy.authorize_proxy(&token_id("stable-token"), "db", "tcp", Some(3306)).is_err());
}

#[tokio::test]
async fn direct_reload_cannot_bypass_the_shared_preflight() {
    let (state, _file) = state();
    let before = state.svc.access_policy().await;
    let mut candidate = ServerConfig::from_defaults();
    candidate.dashboard.port = 8020;
    assert!(state.svc.reload_access_policy(&candidate).await.is_err());
    assert!(Arc::ptr_eq(&before, &state.svc.access_policy().await));
}

#[tokio::test]
async fn reload_api_allowed_domains_accepted() {
    let (state, file) = state();
    std::fs::write(
        &file.0,
        "[[auth.token_policies]]\ntoken = 'dom-token'\n\
         allowed_domains = ['app.example.com', '*.example.org']\n",
    )
    .unwrap();
    let (status, result) = reload(Arc::clone(&state)).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["code"], 200, "{result}");
    let policy = state.svc.access_policy().await;
    assert!(policy
        .authorize_domains(&token_id("dom-token"), &["app.example.com".to_string()], "other.test")
        .is_ok());
    assert!(policy
        .authorize_domains(&token_id("dom-token"), &["a.example.org".to_string()], "other.test")
        .is_ok());
    assert!(policy
        .authorize_domains(&token_id("dom-token"), &["evil.com".to_string()], "other.test")
        .is_err());
}

/// #15: a reload that changes only `denySrcCidrs` swaps the live policy,
/// so a previously allowed address is denied for new connections.
#[tokio::test]
async fn reload_api_deny_src_cidrs_swap_applies() {
    let (state, file) = state();
    let before = state.svc.access_policy().await;
    assert!(!before.is_denied("127.0.0.1".parse().unwrap()));
    std::fs::write(&file.0, "denySrcCidrs = ['127.0.0.1/32']\n").unwrap();
    let (status, result) = reload(Arc::clone(&state)).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["code"], 200, "{result}");
    let after = state.svc.access_policy().await;
    assert!(!Arc::ptr_eq(&before, &after));
    assert!(after.is_denied("127.0.0.1".parse().unwrap()));
    assert!(!after.is_denied("127.0.0.2".parse().unwrap()));
}

/// #3: the request body is ignored — a `configPath` pointing at a file
/// with different content must not change what is reloaded.
#[tokio::test]
async fn reload_ignores_config_path_body() {
    let (state, _file) = state();
    let decoy = ConfigFile::new("denySrcCidrs = ['127.0.0.1/32']\n");
    let router = routes::router(Arc::clone(&state)).layer(middleware::from_fn_with_state(
        Arc::clone(&state),
        auth::auth_middleware,
    ));
    let payload = json!({"configPath": decoy.0.to_str().unwrap()});
    let response = router
        .oneshot(
            Request::post("/api/v1/config/reload")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["code"], 200, "{result}");
    // The startup file was re-read (no changes); the decoy was ignored.
    assert_eq!(result["data"]["changed"], json!([]));
    let policy = state.svc.access_policy().await;
    assert!(!policy.is_denied("127.0.0.1".parse().unwrap()));
}

// ── #3, slice 2: API keys through reload ─────────────────────────────────────

const READ_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const WRITE_KEY: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const EXTRA_KEY: &str = "4444444444444444444444444444444444444444444444444444444444444444";

/// Render a full server config with the given dashboard API keys
/// (`(name, key, scope)` triples).
fn keys_toml(keys: &[(&str, &str, &str)]) -> String {
    let mut s = String::from("[dashboard]\nport = 8020\nuser = 'admin'\npassword = 'secret'\n");
    for (name, key, scope) in keys {
        s.push_str(&format!(
            "[[dashboard.apiKeys]]\nname = '{name}'\nkey = '{key}'\nscope = '{scope}'\n"
        ));
    }
    s.push_str(
        "[[auth.token_policies]]\ntoken = 'stable-token'\nallowed_tunnels = ['db']\nallowed_protocols = ['tcp']\nallowed_remote_ports = [3306]\n",
    );
    s
}

/// Like `state()`, but with auth on and two API keys in the startup file,
/// so Bearer calls exercise the middleware.
fn key_state() -> (Arc<DashState>, ConfigFile) {
    let initial = ConfigFile::new(&keys_toml(&[
        ("ro", READ_KEY, "read"),
        ("rw", WRITE_KEY, "read-write"),
    ]));
    let cfg = ServerConfig::load(&initial.0).unwrap();
    let dash_cfg = DashboardConfig {
        addr: "127.0.0.1".into(),
        port: 8020,
        user: "admin".into(),
        password: "secret".into(),
        disable_auth: false,
        config_file: Some(initial.0.to_str().unwrap().to_owned()),
        ..Default::default()
    };
    let state = Arc::new(DashState {
        svc: Arc::new(Service::new(cfg).unwrap()),
        cfg: dash_cfg,
        auth: Some(Arc::new(auth::AuthState::session_only())),
        trusted_proxies: vec![],
    });
    (state, initial)
}

/// Drive one request through the router + auth middleware with a Bearer
/// key, injecting a fixed peer like `routes_test::call`.
async fn call_bearer(state: Arc<DashState>, req: Request<Body>) -> (StatusCode, Value) {
    let router = routes::router(Arc::clone(&state))
        .layer(middleware::from_fn_with_state(state, auth::auth_middleware));
    let mut req = req;
    req.extensions_mut().insert(ConnectInfo(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        12345,
    ))));
    let response = router.oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn get_as(state: Arc<DashState>, uri: &str, key: &str) -> StatusCode {
    call_bearer(
        state,
        Request::get(uri)
            .header("authorization", format!("Bearer {key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .0
}

async fn reload_as(state: Arc<DashState>, key: &str) -> (StatusCode, Value) {
    call_bearer(
        state,
        Request::post("/api/v1/config/reload")
            .header("authorization", format!("Bearer {key}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn reload_api_keys_add_and_remove() {
    let (state, file) = key_state();
    assert_eq!(
        get_as(state.clone(), "/api/v1/system/info", READ_KEY).await,
        StatusCode::OK
    );
    // Add a third key: reload reports `apiKeys` as changed and the new
    // key works immediately.
    std::fs::write(
        &file.0,
        keys_toml(&[
            ("ro", READ_KEY, "read"),
            ("rw", WRITE_KEY, "read-write"),
            ("extra", EXTRA_KEY, "read"),
        ]),
    )
    .unwrap();
    let (status, result) = reload_as(state.clone(), WRITE_KEY).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(
        result["data"]["changed"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "apiKeys"),
        "{result}"
    );
    assert_eq!(
        get_as(state.clone(), "/api/v1/system/info", EXTRA_KEY).await,
        StatusCode::OK
    );
    // Remove the read key: it is rejected right after the reload, the
    // others keep working.
    std::fs::write(
        &file.0,
        keys_toml(&[("rw", WRITE_KEY, "read-write"), ("extra", EXTRA_KEY, "read")]),
    )
    .unwrap();
    let (status, result) = reload_as(state.clone(), WRITE_KEY).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(
        get_as(state.clone(), "/api/v1/system/info", READ_KEY).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get_as(state.clone(), "/api/v1/system/info", EXTRA_KEY).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn reload_api_keys_bad_key_is_atomic() {
    let (state, file) = key_state();
    // A too-short key fails the whole reload; the old keys keep working.
    std::fs::write(
        &file.0,
        keys_toml(&[("ro", "short", "read"), ("rw", WRITE_KEY, "read-write")]),
    )
    .unwrap();
    let (status, result) = reload_as(state.clone(), WRITE_KEY).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{result}");
    assert!(result["msg"].as_str().unwrap().contains("too short"), "{result}");
    assert_eq!(result["data"]["changed"], json!([]));
    assert_eq!(
        get_as(state.clone(), "/api/v1/system/info", READ_KEY).await,
        StatusCode::OK
    );
    // A duplicate name fails the same way.
    std::fs::write(
        &file.0,
        keys_toml(&[("rw", READ_KEY, "read"), ("rw", WRITE_KEY, "read-write")]),
    )
    .unwrap();
    let (status, result) = reload_as(state.clone(), WRITE_KEY).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{result}");
    assert_eq!(
        get_as(state.clone(), "/api/v1/system/info", WRITE_KEY).await,
        StatusCode::OK
    );
}
