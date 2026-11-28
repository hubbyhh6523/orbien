//! Session-cookie + WebAuthn + password-login authentication layer.
//!
//! ## Session flow
//! 1. Client POSTs `/api/v1/auth/login` (password) **or** completes a
//!    WebAuthn ceremony via `/api/v1/auth/webauthn/login/finish`.
//! 2. Server mints a random 32-byte session token, stores it in `AuthState`,
//!    and sets `Set-Cookie: orbien_session=<token>; HttpOnly; Path=/; SameSite=Strict`.
//! 3. Every subsequent API request carries that cookie.
//!
//! ## Backward compatibility
//! If no session cookie is present the middleware falls back to HTTP Basic Auth
//! so existing integrations keep working without changes.
//!
//! ## API keys (#3, slice 2)
//! `Authorization: Bearer <key>` authenticates against the hash-only store
//! owned by `Service` (config `[[dashboard.apiKeys]]`). A `read` key may
//! only call `GET`/`HEAD`; a `read-write` key may also write. Bearer is
//! checked after the session cookie and before Basic Auth.

use crate::dashboard::DashState;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderValue, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use orbien_core::auth::constant_time_eq;
use orbien_core::config::ApiKeyScope;
use orbien_core::net::Cidr;
use rand::RngExt;
use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use webauthn_rs::{
    prelude::{PasskeyAuthentication, PasskeyRegistration, Url},
    Webauthn, WebauthnBuilder,
};

// ── session record ────────────────────────────────────────────────────────────

#[derive(Clone)]
struct Session {
    username: String,
    created: Instant,
}

const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
const COOKIE_NAME: &str = "orbien_session";
const LOGIN_WINDOW: Duration = Duration::from_secs(60);
const LOGIN_MAX_ATTEMPTS: u32 = 8;
/// #3, slice 2: per-key write rate limit — 60 writes per minute per API
/// key id. Generous for automation, still bounds a stolen key. Only
/// writes that pass the scope check count.
const API_KEY_WRITE_WINDOW: Duration = Duration::from_secs(60);
const API_KEY_WRITE_MAX: u32 = 60;
/// #3: pending WebAuthn states expire with the 120 s state cookie, and are
/// capped so repeated `begin` calls cannot grow memory until restart.
const WA_STATE_TTL: Duration = Duration::from_secs(120);
const MAX_PENDING_WA_STATES: usize = 64;

use webauthn_rs::prelude::Passkey;

/// Who authenticated this request, carried in the request extensions so
/// handlers — and slice 3's audit log — can attribute an action without
/// re-parsing credentials. `scope` is `Some` only for API keys; session
/// and Basic Auth callers are unrestricted.
///
/// Not read yet: no handler consumes it in slice 2. Slice 3 (audit log)
/// reads it; the allow stays until then.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AuthInfo {
    pub kind: AuthKind,
    /// Username for session/Basic Auth, short key id for API keys.
    pub id: String,
    pub scope: Option<ApiKeyScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    Session,
    Basic,
    ApiKey,
}

// ── public AuthState shared via DashState ────────────────────────────────────

pub struct AuthState {
    sessions: DashMap<String, Session>,
    passkeys: DashMap<String, Vec<Passkey>>,
    /// Pending states carry their creation time (#3: they expire with the
    /// 120 s state cookie instead of living until restart).
    reg_states: DashMap<String, (PasskeyRegistration, Instant)>,
    auth_states: DashMap<String, (PasskeyAuthentication, Instant)>,
    login_attempts: DashMap<String, (u32, Instant)>,
    /// #3, slice 2: write counts per API key id (short hash prefix).
    api_key_writes: DashMap<String, (u32, Instant)>,
    pub webauthn: Option<Webauthn>,
    /// M3: when set, passkeys are persisted to this JSON file (0600) on every
    /// mutation and reloaded on startup, so registrations survive restarts.
    passkey_store: Option<PathBuf>,
}

impl AuthState {
    pub fn session_only() -> Self {
        Self {
            sessions: DashMap::new(),
            passkeys: DashMap::new(),
            reg_states: DashMap::new(),
            auth_states: DashMap::new(),
            login_attempts: DashMap::new(),
            api_key_writes: DashMap::new(),
            webauthn: None,
            passkey_store: None,
        }
    }

    pub fn new(rp_id: &str, rp_origin: &str) -> anyhow::Result<Self> {
        let origin = Url::parse(rp_origin)
            .map_err(|e| anyhow::anyhow!("invalid rp_origin {rp_origin}: {e}"))?;
        let webauthn = WebauthnBuilder::new(rp_id, &origin)?.build()?;
        let mut this = Self::session_only();
        this.webauthn = Some(webauthn);
        Ok(this)
    }

    /// M3: attach a passkey persistence file and load any existing entries.
    /// Must be called before the state is shared; failures are logged and
    /// non-fatal (dashboard keeps working with in-memory passkeys only).
    pub fn with_passkey_store(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        match std::fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<HashMap<String, Vec<Passkey>>>(&bytes) {
                Ok(map) => {
                    let count: usize = map.values().map(|v| v.len()).sum();
                    for (user, keys) in map {
                        self.passkeys.insert(user, keys);
                    }
                    tracing::info!(path = %path.display(), passkeys = count, "passkey store loaded");
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), "passkey store parse failed, starting empty: {e}")
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(path = %path.display(), "passkey store does not exist yet, starting empty");
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), "passkey store unreadable, starting empty: {e}")
            }
        }
        self.passkey_store = Some(path);
        self
    }

    /// Serialize passkeys to the store file (0600). Called after every
    /// mutation; write failures are logged, never fatal.
    fn persist_passkeys(&self) {
        let Some(path) = &self.passkey_store else {
            return;
        };
        // Clone out of the DashMap so we don't return references into it.
        let map: HashMap<String, Vec<Passkey>> = self
            .passkeys
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        match serde_json::to_vec_pretty(&map) {
            Ok(bytes) => {
                // Write to a temp file then rename for atomicity. #3: the
                // temp file is created 0600 from the start — the old code
                // wrote it with default permissions and chmodded only after
                // the rename, leaving a window where other users could read it.
                let tmp = path.with_extension("json.tmp");
                if let Err(e) =
                    write_private(&tmp, &bytes).and_then(|_| std::fs::rename(&tmp, path))
                {
                    tracing::warn!(path = %path.display(), "passkey store write failed: {e}");
                }
                #[cfg(unix)]
                if let Err(e) = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600)) {
                    tracing::warn!(path = %path.display(), "passkey store chmod failed: {e}");
                }
            }
            Err(e) => tracing::warn!("passkey store serialize failed: {e}"),
        }
    }

    pub fn webauthn_enabled(&self) -> bool {
        self.webauthn.is_some()
    }

    // ── session helpers ───────────────────────────────────────────────────────

    pub fn create_session(&self, username: &str) -> String {
        let token = random_token();
        self.sessions.insert(
            token.clone(),
            Session {
                username: username.to_string(),
                created: Instant::now(),
            },
        );
        self.evict_expired();
        token
    }

    pub fn validate_session(&self, token: &str) -> Option<String> {
        let entry = self.sessions.get(token)?;
        if entry.created.elapsed() > SESSION_TTL {
            drop(entry);
            self.sessions.remove(token);
            return None;
        }
        Some(entry.username.clone())
    }

    pub fn remove_session(&self, token: &str) {
        self.sessions.remove(token);
    }

    fn evict_expired(&self) {
        self.sessions
            .retain(|_, v| v.created.elapsed() <= SESSION_TTL);
    }

    // ── passkey helpers ───────────────────────────────────────────────────────

    pub fn store_passkey(&self, username: &str, passkey: Passkey) {
        self.passkeys
            .entry(username.to_string())
            .or_default()
            .push(passkey);
        self.persist_passkeys();
    }

    pub fn passkeys_for(&self, username: &str) -> Vec<Passkey> {
        self.passkeys
            .get(username)
            .map(|v| v.value().clone())
            .unwrap_or_default()
    }

    pub fn all_passkeys(&self) -> Vec<Passkey> {
        self.passkeys
            .iter()
            .flat_map(|e| e.value().to_vec())
            .collect()
    }

    #[allow(dead_code)]
    pub fn update_passkey(&self, username: &str, updated: &Passkey) {
        let mut changed = false;
        if let Some(mut entry) = self.passkeys.get_mut(username) {
            for pk in entry.iter_mut() {
                if pk.cred_id() == updated.cred_id() {
                    *pk = updated.clone();
                    changed = true;
                }
            }
        }
        if changed {
            self.persist_passkeys();
        }
    }

    pub fn apply_auth_result(
        &self,
        auth_result: &webauthn_rs::prelude::AuthenticationResult,
    ) -> Option<String> {
        // M3 note: persist AFTER the iter_mut guard is dropped — DashMap shard
        // locks are not reentrant, so calling persist_passkeys() (which takes a
        // read lock) inside the loop would self-deadlock the auth thread.
        let mut persisted_user = None;
        for mut entry in self.passkeys.iter_mut() {
            for pk in entry.value_mut().iter_mut() {
                if auth_result.cred_id() == pk.cred_id() {
                    pk.update_credential(auth_result);
                    persisted_user = Some(entry.key().clone());
                    break;
                }
            }
        }
        if persisted_user.is_some() {
            self.persist_passkeys();
        }
        persisted_user
    }

    // ── pending state helpers ─────────────────────────────────────────────────

    /// #3: pending states expire after `WA_STATE_TTL` and are capped, so a
    /// flood of `begin` calls stays bounded. Returns `false` when the cap is
    /// hit (caller answers 429); expired entries are swept first.
    pub fn save_reg_state(&self, username: &str, state: PasskeyRegistration) -> bool {
        self.evict_expired_wa_states();
        if self.reg_states.len() >= MAX_PENDING_WA_STATES {
            return false;
        }
        self.reg_states
            .insert(username.to_string(), (state, Instant::now()));
        true
    }

    pub fn take_reg_state(&self, username: &str) -> Option<PasskeyRegistration> {
        let (_, (state, created)) = self.reg_states.remove(username)?;
        if wa_state_expired(created) {
            return None;
        }
        Some(state)
    }

    pub fn save_auth_state(&self, key: &str, state: PasskeyAuthentication) -> bool {
        self.evict_expired_wa_states();
        if self.auth_states.len() >= MAX_PENDING_WA_STATES {
            return false;
        }
        self.auth_states
            .insert(key.to_string(), (state, Instant::now()));
        true
    }

    pub fn take_auth_state(&self, key: &str) -> Option<PasskeyAuthentication> {
        let (_, (state, created)) = self.auth_states.remove(key)?;
        if wa_state_expired(created) {
            return None;
        }
        Some(state)
    }

    fn evict_expired_wa_states(&self) {
        self.reg_states
            .retain(|_, (_, created)| !wa_state_expired(*created));
        self.auth_states
            .retain(|_, (_, created)| !wa_state_expired(*created));
    }

    pub fn login_allowed(&self, key: &str) -> bool {
        match self.login_attempts.get(key) {
            Some(entry) => {
                let (count, started) = *entry;
                started.elapsed() > LOGIN_WINDOW || count < LOGIN_MAX_ATTEMPTS
            }
            None => true,
        }
    }

    pub fn record_login_failure(&self, key: &str) {
        self.login_attempts
            .entry(key.to_string())
            .and_modify(|(count, started)| {
                if started.elapsed() > LOGIN_WINDOW {
                    *count = 1;
                    *started = Instant::now();
                } else {
                    *count = count.saturating_add(1);
                }
            })
            .or_insert((1, Instant::now()));
        self.login_attempts
            .retain(|_, (_, started)| started.elapsed() <= LOGIN_WINDOW * 2);
    }

    pub fn clear_login_failures(&self, key: &str) {
        self.login_attempts.remove(key);
    }

    // ── per-key write limiter (#3, slice 2) ──────────────────────────────────

    pub fn api_key_write_allowed(&self, key_id: &str) -> bool {
        match self.api_key_writes.get(key_id) {
            Some(entry) => {
                let (count, started) = *entry;
                started.elapsed() > API_KEY_WRITE_WINDOW || count < API_KEY_WRITE_MAX
            }
            None => true,
        }
    }

    pub fn record_api_key_write(&self, key_id: &str) {
        self.api_key_writes
            .entry(key_id.to_string())
            .and_modify(|(count, started)| {
                if started.elapsed() > API_KEY_WRITE_WINDOW {
                    *count = 1;
                    *started = Instant::now();
                } else {
                    *count = count.saturating_add(1);
                }
            })
            .or_insert((1, Instant::now()));
        self.api_key_writes
            .retain(|_, (_, started)| started.elapsed() <= API_KEY_WRITE_WINDOW * 2);
    }
}

/// Write `bytes` to `path`, creating it with mode 0600 on unix so no other
/// user can read it even briefly (#3).
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

/// #3: a pending WebAuthn state is usable only within the state-cookie
/// lifetime. Kept as a pure predicate so the rule is unit-testable without
/// fabricating a `PasskeyAuthentication` value.
fn wa_state_expired(created: Instant) -> bool {
    created.elapsed() > WA_STATE_TTL
}

fn random_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ── Axum middleware ───────────────────────────────────────────────────────────

#[allow(clippy::result_large_err)]
pub async fn auth_middleware(
    State(state): State<Arc<DashState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let path = req.uri().path();

    // Liveness probe: public by design.
    if path == "/healthz" {
        return Ok(next.run(req).await);
    }

    // #3: `/metrics` is protected like `/api/` — it used to be public
    // because the middleware only checked `/api/` paths. Everything else
    // (the SPA, static assets) stays public.
    let protected = path.starts_with("/api/") || path == "/metrics";
    if !protected {
        return Ok(next.run(req).await);
    }

    // #3: cross-site guard for unsafe methods. `SameSite` cookies do not
    // protect the Basic Auth path, and a forged POST from another origin
    // must not reach a handler. Missing headers (curl, API clients) pass.
    if matches!(
        *req.method(),
        axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::DELETE
    ) && is_cross_site(&req)
    {
        return Err((StatusCode::FORBIDDEN, "cross-site request forbidden").into_response());
    }

    // Auth endpoints are public by design (login, status, WebAuthn).
    if path.starts_with("/api/v1/auth/") {
        return Ok(next.run(req).await);
    }

    if state.cfg.disable_auth {
        return Ok(next.run(req).await);
    }

    // Peer for rate limiting: injected by
    // `into_make_service_with_connect_info` (oneshot tests insert it too).
    let peer = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());
    let key = client_key(req.headers(), peer, &state.trusted_proxies);

    if let Some(auth) = &state.auth {
        if let Some(token) = extract_cookie(req.headers(), COOKIE_NAME) {
            if let Some(user) = auth.validate_session(&token) {
                req.extensions_mut().insert(AuthInfo {
                    kind: AuthKind::Session,
                    id: user,
                    scope: None,
                });
                return Ok(next.run(req).await);
            }
        }
    }

    // #3, slice 2: `Authorization: Bearer <key>` — checked after the
    // session cookie and before Basic Auth. A presented Bearer is
    // authoritative when present: an unknown key is a 401 (and counts
    // against the per-address limiter, like a Basic Auth failure), it
    // does not fall through to Basic Auth.
    if let Some(presented) = extract_bearer(req.headers()) {
        if let Some(auth) = &state.auth {
            if !auth.login_allowed(&key) {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many authentication attempts",
                )
                    .into_response());
            }
        }
        let store = state.svc.api_key_store().await;
        match store.lookup(&presented) {
            Some(entry) => {
                if let Some(auth) = &state.auth {
                    auth.clear_login_failures(&key);
                }
                let is_write = !matches!(
                    *req.method(),
                    axum::http::Method::GET | axum::http::Method::HEAD
                );
                if is_write && !entry.scope.allows_write() {
                    tracing::debug!(
                        key_id = %entry.id,
                        method = %req.method(),
                        path = %path,
                        "read-scoped API key denied write"
                    );
                    return Err((
                        StatusCode::FORBIDDEN,
                        "read-scoped API key cannot perform writes",
                    )
                        .into_response());
                }
                if is_write {
                    if let Some(auth) = &state.auth {
                        if !auth.api_key_write_allowed(&entry.id) {
                            return Err((
                                StatusCode::TOO_MANY_REQUESTS,
                                "too many write requests for this API key",
                            )
                                .into_response());
                        }
                        auth.record_api_key_write(&entry.id);
                    }
                }
                let info = AuthInfo {
                    kind: AuthKind::ApiKey,
                    id: entry.id.clone(),
                    scope: Some(entry.scope),
                };
                req.extensions_mut().insert(info);
                return Ok(next.run(req).await);
            }
            None => {
                if let Some(auth) = &state.auth {
                    auth.record_login_failure(&key);
                }
                return Err(unauthorized_response());
            }
        }
    }

    if needs_basic_auth(&state) {
        if let Some(auth) = &state.auth {
            // #3: Basic Auth failures count against the same limiter as
            // logins — once limited, even correct credentials are rejected
            // until the window passes.
            if !auth.login_allowed(&key) {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many authentication attempts",
                )
                    .into_response());
            }
        }
        if basic_auth_ok(&state, req.headers()) {
            if let Some(auth) = &state.auth {
                auth.clear_login_failures(&key);
            }
            let user = state.cfg.user.clone();
            req.extensions_mut().insert(AuthInfo {
                kind: AuthKind::Basic,
                id: user,
                scope: None,
            });
            return Ok(next.run(req).await);
        }
        if let Some(auth) = &state.auth {
            auth.record_login_failure(&key);
        }
    }

    Err(unauthorized_response())
}

/// Shared 401 with the `Basic` challenge (also used for unknown Bearer
/// keys — the challenge names the fallback scheme, not the one tried).
fn unauthorized_response() -> Response {
    let mut res = (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    res.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"Restricted\""),
    );
    res
}

/// #3, slice 2: `Authorization: Bearer <token>` (scheme case-insensitive,
/// like the Basic parser below). Returns the raw token, trimmed.
fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    let h = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let token = h
        .strip_prefix("Bearer ")
        .or_else(|| h.strip_prefix("bearer "))?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

/// #3: `true` when the request is cross-site — `Sec-Fetch-Site: cross-site`,
/// or an `Origin` whose host differs from the request `Host`. Missing
/// headers mean "not a browser" and are allowed.
fn is_cross_site(req: &Request<Body>) -> bool {
    let headers = req.headers();
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
    {
        if site.eq_ignore_ascii_case("cross-site") {
            return true;
        }
    }
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(origin_host) = origin
        .parse::<axum::http::Uri>()
        .ok()
        .and_then(|u| u.host().map(str::to_string))
    else {
        return true; // malformed Origin — fail closed
    };
    !origin_host.eq_ignore_ascii_case(host_without_port(host))
}

fn host_without_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    host.split(':').next().unwrap_or(host)
}

// ── cookie helpers ────────────────────────────────────────────────────────────

pub fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let cookie_str = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())?;
    for pair in cookie_str.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix(&format!("{name}=")) {
            return Some(val.to_string());
        }
    }
    None
}

/// #3: the `Secure` cookie flag. `X-Forwarded-Proto` is read only when a
/// trusted proxy is configured (a non-empty trusted list); in direct mode
/// the header is attacker-controlled and ignored, and the configured
/// origin decides.
pub fn cookie_secure(
    headers: &axum::http::HeaderMap,
    origin: &str,
    trusted_proxies: &[Cidr],
) -> bool {
    if !trusted_proxies.is_empty() {
        if let Some(proto) = headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
        {
            return proto
                .split(',')
                .next_back()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("https");
        }
    }
    origin.trim().to_ascii_lowercase().starts_with("https://")
}

pub fn session_cookie(token: &str, clear: bool, secure: bool) -> HeaderValue {
    let secure_flag = if secure { "; Secure" } else { "" };
    if clear {
        HeaderValue::from_str(&format!(
            "{COOKIE_NAME}=; HttpOnly{secure_flag}; Path=/; SameSite=Strict; Max-Age=0"
        ))
        .unwrap()
    } else {
        HeaderValue::from_str(&format!(
            "{COOKIE_NAME}={token}; HttpOnly{secure_flag}; Path=/; SameSite=Strict; Max-Age={}",
            SESSION_TTL.as_secs()
        ))
        .unwrap()
    }
}

pub fn wa_state_cookie(state_key: &str, secure: bool) -> HeaderValue {
    let secure_flag = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "orbien_wa_state={state_key}; HttpOnly{secure_flag}; Path=/api/v1/auth; SameSite=Strict; Max-Age=120"
    ))
    .unwrap()
}

pub fn clear_wa_state_cookie(secure: bool) -> HeaderValue {
    let secure_flag = if secure { "; Secure" } else { "" };
    HeaderValue::from_str(&format!(
        "orbien_wa_state=; HttpOnly{secure_flag}; Path=/api/v1/auth; Max-Age=0"
    ))
    .unwrap()
}

// ── basic-auth helpers (kept for backward compat) ─────────────────────────────

fn needs_basic_auth(state: &DashState) -> bool {
    !state.cfg.user.is_empty() || !state.cfg.password.is_empty()
}

pub fn credentials_match(expected_user: &str, expected_pass: &str, user: &str, pass: &str) -> bool {
    // #3: an empty configured credential never matches — even an empty
    // submitted one. Startup validation already refuses empty credentials;
    // this is defense in depth.
    if expected_user.is_empty() || expected_pass.is_empty() {
        return false;
    }
    constant_time_eq(user.as_bytes(), expected_user.as_bytes())
        && constant_time_eq(pass.as_bytes(), expected_pass.as_bytes())
}

fn basic_auth_ok(state: &DashState, headers: &axum::http::HeaderMap) -> bool {
    use base64::Engine;
    let Some(h) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(b64) = h
        .strip_prefix("Basic ")
        .or_else(|| h.strip_prefix("basic "))
    else {
        return false;
    };
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let Ok(s) = String::from_utf8(raw) else {
        return false;
    };
    let Some((u, p)) = s.split_once(':') else {
        return false;
    };
    credentials_match(&state.cfg.user, &state.cfg.password, u, p)
}

/// #3: rate-limit key for one peer. `X-Forwarded-For` is trusted only when
/// the direct peer is itself a configured trusted proxy; otherwise the
/// (unforgeable) peer address is used. IPv6 collapses to its /64 prefix so
/// rotating addresses inside one /64 shares a bucket; IPv4-mapped IPv6
/// normalizes to IPv4 first (same rule as #15's deny check).
pub fn client_key(
    headers: &axum::http::HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxies: &[Cidr],
) -> String {
    if !trusted_proxies.is_empty() {
        if let Some(peer) = peer_ip {
            let peer = normalize_ip(peer);
            if trusted_proxies.iter().any(|c| c.contains(peer)) {
                if let Some(forwarded) = headers
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.split(',').next_back())
                    .map(str::trim)
                    .filter(|v| v.parse::<IpAddr>().is_ok())
                {
                    let fwd: IpAddr = forwarded.parse().unwrap();
                    return format!("proxy:{}", limiter_ip_key(fwd));
                }
            }
        }
    }
    match peer_ip {
        Some(ip) => format!("direct:{}", limiter_ip_key(ip)),
        None => "direct:unknown".to_string(),
    }
}

/// #3: one address folded into its limiter bucket — IPv4 as-is, IPv6 as its
/// /64 prefix.
fn limiter_ip_key(ip: IpAddr) -> String {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            format!("{}/64", std::net::Ipv6Addr::from(octets))
        }
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use std::net::IpAddr;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    // 直连模式（trusted_proxies 为空）：转发头一律不采信
    #[test]
    fn client_key_no_header() {
        let headers = HeaderMap::new();
        assert_eq!(client_key(&headers, ip("10.0.0.9"), &[]), "direct:10.0.0.9");
    }

    #[test]
    fn client_key_direct_mode_ignores_forwarded_for() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "192.168.1.1".parse().unwrap());
        // 伪造的转发头必须被忽略——限速键只由真实对端 IP 决定
        assert_eq!(client_key(&h, ip("203.0.113.7"), &[]), "direct:203.0.113.7");
    }

    #[test]
    fn client_key_direct_mode_attacker_cannot_bypass_rate_limit() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "10.0.0.1, 203.0.113.5".parse().unwrap());
        assert_eq!(client_key(&h, ip("198.51.100.9"), &[]), "direct:198.51.100.9");
        h.insert("x-forwarded-for", "10.0.0.2, 203.0.113.5".parse().unwrap());
        // 攻击者换任何伪造头，真实对端 IP 不变 → 限速键稳定
        assert_eq!(client_key(&h, ip("198.51.100.9"), &[]), "direct:198.51.100.9");
    }

    #[test]
    fn client_key_direct_mode_no_peer_falls_back() {
        let headers = HeaderMap::new();
        assert_eq!(client_key(&headers, None, &[]), "direct:unknown");
    }

    #[test]
    fn client_key_direct_mode_invalid_header_still_ignored() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "garbage".parse().unwrap());
        assert_eq!(client_key(&h, ip("192.0.2.1"), &[]), "direct:192.0.2.1");
    }

    #[test]
    fn client_key_direct_mode_trims_spaces_in_header_ignored() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "1.2.3.4 ,  203.0.113.5  ".parse().unwrap());
        // 即便格式合法，直连模式也不采信
        assert_eq!(client_key(&h, ip("198.51.100.9"), &[]), "direct:198.51.100.9");
    }

    // #3: IPv6 限速键按 /64 折叠，同一 /64 内的地址共享桶
    #[test]
    fn client_key_ipv6_shares_bucket_within_slash64() {
        let headers = HeaderMap::new();
        let a = client_key(&headers, ip("2001:db8::1"), &[]);
        let b = client_key(&headers, ip("2001:db8::2"), &[]);
        let c = client_key(&headers, ip("2001:db9::1"), &[]);
        assert_eq!(a, "direct:2001:db8::/64");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn client_key_ipv4_mapped_normalizes_to_ipv4() {
        let headers = HeaderMap::new();
        assert_eq!(
            client_key(&headers, ip("::ffff:10.0.0.9"), &[]),
            "direct:10.0.0.9"
        );
    }

    // #3: 只有直连对端本身在可信列表里时才采信 X-Forwarded-For
    #[test]
    fn client_key_trusted_proxy_uses_forwarded_for() {
        let trusted = vec![Cidr::parse("10.0.0.5").unwrap()];
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        assert_eq!(
            client_key(&h, ip("10.0.0.5"), &trusted),
            "proxy:203.0.113.7"
        );
    }

    #[test]
    fn client_key_untrusted_peer_ignores_forwarded_for() {
        let trusted = vec![Cidr::parse("10.0.0.5").unwrap()];
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        assert_eq!(
            client_key(&h, ip("198.51.100.9"), &trusted),
            "direct:198.51.100.9"
        );
    }

    #[test]
    fn cookie_secure_no_header_http() {
        let h = HeaderMap::new();
        assert!(!cookie_secure(&h, "http://example.com", &[]));
    }

    #[test]
    fn cookie_secure_no_header_https() {
        let h = HeaderMap::new();
        assert!(cookie_secure(&h, "https://example.com", &[]));
    }

    // 直连模式：伪造/合法的 x-forwarded-proto 都不影响 Secure 判定
    #[test]
    fn cookie_secure_direct_mode_ignores_forwarded_proto() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "http, https".parse().unwrap());
        assert!(!cookie_secure(&h, "http://example.com", &[]));
    }

    #[test]
    fn cookie_secure_direct_mode_attacker_cannot_upgrade() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(!cookie_secure(&h, "http://example.com", &[]));
    }

    // #3: 配置了可信代理时 X-Forwarded-Proto 决定 Secure 标记
    #[test]
    fn cookie_secure_trusted_proxy_reads_forwarded_proto() {
        let trusted = vec![Cidr::parse("10.0.0.5").unwrap()];
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(cookie_secure(&h, "http://example.com", &trusted));
        h.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!cookie_secure(&h, "https://example.com", &trusted));
    }

    // #3: 待处理 WebAuthn 态 120 秒后过期
    #[test]
    fn wa_state_expiry_predicate() {
        assert!(!wa_state_expired(Instant::now()));
        let old = Instant::now()
            .checked_sub(Duration::from_secs(121))
            .unwrap();
        assert!(wa_state_expired(old));
    }

    // #3: 空的配置凭据永远不匹配，哪怕提交的也是空的
    #[test]
    fn credentials_match_rejects_empty_expected() {
        assert!(!credentials_match("", "", "", ""));
        assert!(!credentials_match("admin", "", "admin", ""));
        assert!(credentials_match("admin", "secret", "admin", "secret"));
        assert!(!credentials_match("admin", "secret", "admin", "wrong"));
    }

    // #3, slice 2: Bearer extraction
    #[test]
    fn extract_bearer_cases() {
        let mut h = HeaderMap::new();
        assert_eq!(extract_bearer(&h), None);
        h.insert(
            header::AUTHORIZATION,
            "Bearer abc123".parse().unwrap(),
        );
        assert_eq!(extract_bearer(&h).as_deref(), Some("abc123"));
        h.insert(
            header::AUTHORIZATION,
            "bearer   spaced-key  ".parse().unwrap(),
        );
        assert_eq!(extract_bearer(&h).as_deref(), Some("spaced-key"));
        h.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(extract_bearer(&h), None);
        h.insert(header::AUTHORIZATION, "Basic YWRtaW46eA==".parse().unwrap());
        assert_eq!(extract_bearer(&h), None);
    }

    // #3, slice 2: per-key write limiter — 60 writes per 60 s window.
    #[test]
    fn api_key_write_limiter_allows_then_blocks() {
        let auth = AuthState::session_only();
        for _ in 0..API_KEY_WRITE_MAX {
            assert!(auth.api_key_write_allowed("deadbeefdeadbeef"));
            auth.record_api_key_write("deadbeefdeadbeef");
        }
        assert!(!auth.api_key_write_allowed("deadbeefdeadbeef"));
        // A different key id has its own bucket.
        assert!(auth.api_key_write_allowed("0123456789abcdef"));
    }
}
