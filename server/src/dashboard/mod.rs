pub(crate) mod auth;
pub(crate) mod auth_routes;
pub(crate) mod model;
mod routes;
mod security;
#[cfg(test)]
mod routes_test;
#[cfg(test)]
mod config_reload_test;

use crate::service::Service;
use anyhow::Result;
use axum::middleware;
use orbien_core::config::DashboardConfig;
use std::sync::Arc;
use tokio::net::TcpListener;

pub async fn run(svc: Arc<Service>, cfg: DashboardConfig) -> Result<()> {
    let addr = format!("{}:{}", cfg.addr, cfg.port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, user = %cfg.user, "dashboard listening");

    // Build AuthState when both WebAuthn fields are populated.
    // `cfg.webauthn_enabled()` returns true only when rp_id AND origin are
    // non-empty, so a partial config is treated as "disabled".
    let auth_state: Option<Arc<auth::AuthState>> = Some(Arc::new(if cfg.webauthn_enabled() {
        let store_path = cfg.passkey_store_path.clone();
        match auth::AuthState::new(&cfg.webauthn_rp_id, &cfg.webauthn_origin) {
            Ok(a) => {
                tracing::info!(
                    rp_id = %cfg.webauthn_rp_id,
                    origin = %cfg.webauthn_origin,
                    "WebAuthn enabled"
                );
                // M3: opt-in passkey persistence via [dashboard] passkeyStorePath.
                if store_path.is_empty() {
                    a
                } else {
                    a.with_passkey_store(store_path)
                }
            }
            Err(e) => {
                tracing::warn!("WebAuthn init failed, using password sessions only: {e}");
                auth::AuthState::session_only()
            }
        }
    } else {
        tracing::info!("WebAuthn not configured, using password sessions + Basic Auth");
        auth::AuthState::session_only()
    }));

    // #3: parse once at startup (`validate()` already rejected bad entries)
    // so the middleware never parses per request.
    let trusted_proxies = parse_trusted_proxies(&cfg.trusted_proxies);

    let state = Arc::new(DashState {
        svc,
        cfg,
        auth: auth_state,
        trusted_proxies,
    });

    let app = routes::router(state.clone())
        .layer(middleware::from_fn_with_state(state, auth::auth_middleware))
        .layer(middleware::from_fn(security::security_headers))
        .into_make_service_with_connect_info::<std::net::SocketAddr>();

    axum::serve(listener, app).await?;
    Ok(())
}

#[derive(Clone)]
pub struct DashState {
    pub svc: Arc<Service>,
    pub cfg: DashboardConfig,
    /// Present when WebAuthn is configured; `None` → Basic Auth only.
    pub auth: Option<Arc<auth::AuthState>>,
    /// #3: parsed `dashboard.trustedProxies` (IPs/CIDRs). Empty means direct
    /// mode — forwarding headers are never trusted.
    pub trusted_proxies: Vec<orbien_core::net::Cidr>,
}

/// #3: parse the configured trusted proxies. Unparsable entries are skipped
/// with a warning — `validate()` already refuses them at startup, so this
/// only fires for states built without validation (tests).
fn parse_trusted_proxies(entries: &[String]) -> Vec<orbien_core::net::Cidr> {
    entries
        .iter()
        .filter_map(|e| match orbien_core::net::Cidr::parse(e) {
            Ok(c) => Some(c),
            Err(err) => {
                tracing::warn!(entry = %e, "ignoring unparsable dashboard.trustedProxies entry: {err}");
                None
            }
        })
        .collect()
}
