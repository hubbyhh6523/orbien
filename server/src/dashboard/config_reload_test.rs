use super::{auth, routes, DashState};
use crate::service::Service;
use axum::body::Body;
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

fn state() -> Arc<DashState> {
    let initial = ConfigFile::new(INITIAL);
    let cfg = ServerConfig::load(&initial.0).unwrap();
    Arc::new(DashState {
        svc: Arc::new(Service::new(cfg).unwrap()),
        cfg: DashboardConfig { disable_auth: true, ..Default::default() },
        auth: Some(Arc::new(auth::AuthState::session_only())),
    })
}

async fn reload(state: Arc<DashState>, path: Option<&std::path::Path>) -> Value {
    let router = routes::router(Arc::clone(&state))
        .layer(middleware::from_fn_with_state(state, auth::auth_middleware));
    let payload = path.map(|p| json!({"configPath": p.to_str().unwrap()})).unwrap_or(json!({}));
    let response = router.oneshot(Request::post("/api/v1/config/reload")
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string())).unwrap()).await.unwrap();
    // Preserve the existing API contract: errors are carried in JSON.code.
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn assert_unchanged(state: &Arc<DashState>, text: &str, reason: &str) {
    let before = state.svc.access_policy().await;
    let config_before = serde_json::to_value(state.svc.cfg()).unwrap();
    let file = ConfigFile::new(text);
    let result = reload(Arc::clone(state), Some(&file.0)).await;
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
    let state = state();
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
    let state = state();
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
    let state = state();
    let before = state.svc.access_policy().await;
    let file = ConfigFile::new("");
    std::fs::remove_file(&file.0).unwrap();
    let result = reload(Arc::clone(&state), Some(&file.0)).await;
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
    let mut state = state();
    let file = ConfigFile::new(r#"
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
"#);
    let certificate = orbien_core::transport::generate_self_signed_cert("localhost").unwrap();
    let encoder = base64::engine::general_purpose::STANDARD;
    std::fs::write(file.0.parent().unwrap().join("fixture.crt"), format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        encoder.encode(certificate.certs[0].as_ref())
    )).unwrap();
    std::fs::write(file.0.parent().unwrap().join("fixture.key"), format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        encoder.encode(certificate.key.secret_pkcs8_der())
    )).unwrap();
    let loaded = ServerConfig::load(&file.0).unwrap();
    assert!(loaded.transport.tls.force);
    assert!(std::path::Path::new(&loaded.transport.tls.cert_file).is_absolute());
    Arc::get_mut(&mut state).unwrap().cfg.config_file = Some(file.0.to_str().unwrap().to_owned());
    let result = reload(Arc::clone(&state), None).await;
    assert_eq!(result["code"], 200, "{result}");
    let policy = state.svc.access_policy().await;
    assert!(policy.authorize_proxy(&token_id("next-token"), "db", "tcp", Some(5432)).is_ok());
    assert!(policy.authorize_proxy(&token_id("stable-token"), "db", "tcp", Some(3306)).is_err());
}

#[tokio::test]
async fn direct_reload_cannot_bypass_the_shared_preflight() {
    let state = state();
    let before = state.svc.access_policy().await;
    let mut candidate = ServerConfig::from_defaults();
    candidate.dashboard.port = 8020;
    assert!(state.svc.reload_access_policy(&candidate).await.is_err());
    assert!(Arc::ptr_eq(&before, &state.svc.access_policy().await));
}

#[tokio::test]
async fn reload_api_allowed_domains_accepted() {
    let state = state();
    let file = ConfigFile::new(
        "[[auth.token_policies]]\ntoken = 'dom-token'\n\
         allowed_domains = ['app.example.com', '*.example.org']\n",
    );
    let result = reload(Arc::clone(&state), Some(&file.0)).await;
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
    let state = state();
    let before = state.svc.access_policy().await;
    assert!(!before.is_denied("127.0.0.1".parse().unwrap()));
    let file = ConfigFile::new("denySrcCidrs = ['127.0.0.1/32']\n");
    let result = reload(Arc::clone(&state), Some(&file.0)).await;
    assert_eq!(result["code"], 200, "{result}");
    let after = state.svc.access_policy().await;
    assert!(!Arc::ptr_eq(&before, &after));
    assert!(after.is_denied("127.0.0.1".parse().unwrap()));
    assert!(!after.is_denied("127.0.0.2".parse().unwrap()));
}
