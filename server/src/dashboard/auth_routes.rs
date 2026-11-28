//! `/api/v1/auth/*` route handlers.

use super::{
    auth::{
        clear_wa_state_cookie, client_key, cookie_secure, credentials_match, session_cookie,
        wa_state_cookie, AuthState,
    },
    DashState,
};
use axum::{
    extract::ConnectInfo,
    extract::{Json, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

// ── shared response wrapper ───────────────────────────────────────────────────

#[derive(Serialize)]
struct Resp<T: Serialize> {
    code: u16,
    msg: String,
    data: T,
}

fn ok<T: Serialize>(data: T) -> Json<Resp<T>> {
    Json(Resp {
        code: 200,
        msg: String::new(),
        data,
    })
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, msg.to_string()).into_response()
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Get WebAuthn-enabled AuthState, or return a boxed error response.
/// Box<Response> keeps the Result variants balanced in size (clippy::result_large_err suppressed).
#[allow(clippy::result_large_err)]
fn get_auth(state: &DashState) -> Result<&AuthState, Box<Response>> {
    let auth = state
        .auth
        .as_deref()
        .ok_or_else(|| Box::new(err(StatusCode::NOT_IMPLEMENTED, "auth not configured")))?;
    if auth.webauthn.is_none() {
        return Err(Box::new(err(
            StatusCode::NOT_IMPLEMENTED,
            "webauthn not configured",
        )));
    }
    Ok(auth)
}

#[allow(clippy::result_large_err)]
fn get_sessions(state: &DashState) -> Result<&AuthState, Box<Response>> {
    state.auth.as_deref().ok_or_else(|| {
        Box::new(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "auth not configured",
        ))
    })
}

fn cookie_is_secure(state: &DashState, headers: &axum::http::HeaderMap) -> bool {
    cookie_secure(headers, &state.cfg.webauthn_origin, &state.trusted_proxies)
}

// ── auth status (public) ───────────────────────────────────────────────────

pub async fn auth_status(State(state): State<Arc<DashState>>) -> Response {
    let webauthn_available = state
        .auth
        .as_ref()
        .map(|a| a.webauthn_enabled())
        .unwrap_or(false);
    let password_available = !state.cfg.user.is_empty();
    ok(serde_json::json!({
        "webauthn": webauthn_available,
        "password": password_available,
    }))
    .into_response()
}

// ── password login ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

pub async fn login(
    State(state): State<Arc<DashState>>,
    headers: axum::http::HeaderMap,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<LoginReq>,
) -> Response {
    // 真实对端 IP 是限速键的不可伪造分量（M2 修复）
    let key = client_key(&headers, Some(peer.ip()), &state.trusted_proxies);
    if let Some(auth) = &state.auth {
        if !auth.login_allowed(&key) {
            return err(StatusCode::TOO_MANY_REQUESTS, "too many login attempts");
        }
    }

    let ok_creds = credentials_match(
        &state.cfg.user,
        &state.cfg.password,
        &body.username,
        &body.password,
    );
    if !ok_creds {
        if let Some(auth) = &state.auth {
            auth.record_login_failure(&key);
        }
        return err(StatusCode::UNAUTHORIZED, "invalid credentials");
    }
    if let Some(auth) = &state.auth {
        auth.clear_login_failures(&key);
    }

    let mut res = ok(serde_json::json!({ "username": body.username })).into_response();
    let auth = match get_sessions(&state) {
        Ok(a) => a,
        Err(e) => return *e,
    };
    let token = auth.create_session(&body.username);
    let cookie = session_cookie(&token, false, cookie_is_secure(&state, &headers));
    res.headers_mut().insert(header::SET_COOKIE, cookie);
    res
}

// ── logout ────────────────────────────────────────────────────────────────────

pub async fn logout(
    State(state): State<Arc<DashState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if let Some(auth) = &state.auth {
        if let Some(token) = super::auth::extract_cookie(&headers, "orbien_session") {
            auth.remove_session(&token);
        }
    }
    let clear = session_cookie("", true, cookie_is_secure(&state, &headers));
    let mut res = ok(()).into_response();
    res.headers_mut().insert(header::SET_COOKIE, clear);
    res
}

// ── WebAuthn registration begin ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegBeginReq {
    username: String,
}

pub async fn webauthn_register_begin(
    State(state): State<Arc<DashState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RegBeginReq>,
) -> Response {
    if !registration_authorized(&state, &headers) {
        return err(
            StatusCode::UNAUTHORIZED,
            "login required to register a passkey",
        );
    }
    let auth = match get_auth(&state) {
        Ok(a) => a,
        Err(e) => return *e,
    };

    // clippy::map_clone: CredentialID is Clone; use .cloned() on the iterator
    let existing: Vec<_> = auth
        .passkeys_for(&body.username)
        .iter()
        .map(|pk| pk.cred_id().clone())
        .collect();

    let session_user = current_username(&state, &headers);
    if let Some(user) = &session_user {
        if user != &body.username {
            return err(
                StatusCode::FORBIDDEN,
                "cannot register a passkey for another user",
            );
        }
    } else if body.username != state.cfg.user {
        // #3: with Basic Auth there is no session user, so the "another
        // user" check above never fires — require the configured user here.
        return err(
            StatusCode::FORBIDDEN,
            "cannot register a passkey for another user",
        );
    }

    let user_id = uuid_for_name(&body.username);
    let webauthn = match auth.webauthn.as_ref() {
        Some(w) => w,
        None => return err(StatusCode::NOT_IMPLEMENTED, "webauthn not configured"),
    };
    let (challenge, reg_state) = match webauthn.start_passkey_registration(
        user_id,
        &body.username,
        &body.username,
        Some(existing),
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("webauthn reg begin error: {e}");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "registration init failed",
            );
        }
    };

    // #3: the pending-state store is capped; refuse rather than grow memory.
    if !auth.save_reg_state(&body.username, reg_state) {
        return err(
            StatusCode::TOO_MANY_REQUESTS,
            "too many pending registrations",
        );
    }
    ok(challenge).into_response()
}

// ── WebAuthn registration finish ───────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegFinishReq {
    username: String,
    credential: RegisterPublicKeyCredential,
}

pub async fn webauthn_register_finish(
    State(state): State<Arc<DashState>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RegFinishReq>,
) -> Response {
    if !registration_authorized(&state, &headers) {
        return err(
            StatusCode::UNAUTHORIZED,
            "login required to register a passkey",
        );
    }
    let auth = match get_auth(&state) {
        Ok(a) => a,
        Err(e) => return *e,
    };

    let reg_state = match auth.take_reg_state(&body.username) {
        Some(s) => s,
        None => return err(StatusCode::BAD_REQUEST, "no pending registration"),
    };

    if let Some(user) = current_username(&state, &headers) {
        if user != body.username {
            return err(
                StatusCode::FORBIDDEN,
                "cannot register a passkey for another user",
            );
        }
    } else if body.username != state.cfg.user {
        // #3: see register_begin — Basic Auth has no session user.
        return err(
            StatusCode::FORBIDDEN,
            "cannot register a passkey for another user",
        );
    }

    let webauthn = match auth.webauthn.as_ref() {
        Some(w) => w,
        None => return err(StatusCode::NOT_IMPLEMENTED, "webauthn not configured"),
    };
    match webauthn.finish_passkey_registration(&body.credential, &reg_state) {
        Ok(passkey) => {
            auth.store_passkey(&body.username, passkey);
            ok(()).into_response()
        }
        Err(e) => {
            tracing::warn!("webauthn reg finish error: {e}");
            err(StatusCode::BAD_REQUEST, "registration verification failed")
        }
    }
}

// ── WebAuthn login begin ────────────────────────────────────────────────────────

pub async fn webauthn_login_begin(
    State(state): State<Arc<DashState>>,
    headers: axum::http::HeaderMap,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
) -> Response {
    let auth = match get_auth(&state) {
        Ok(a) => a,
        Err(e) => return *e,
    };

    // #3: rate-limit the begin call per client address — each call stores a
    // pending state, so an unbounded caller grows memory until restart.
    // Reuses the login limiter under a separate key namespace.
    let key = format!(
        "wa-begin:{}",
        client_key(&headers, Some(peer.ip()), &state.trusted_proxies)
    );
    if !auth.login_allowed(&key) {
        return err(StatusCode::TOO_MANY_REQUESTS, "too many login attempts");
    }
    auth.record_login_failure(&key);

    let all_keys = auth.all_passkeys();
    if all_keys.is_empty() {
        return err(StatusCode::BAD_REQUEST, "no registered passkeys");
    }

    let webauthn = match auth.webauthn.as_ref() {
        Some(w) => w,
        None => return err(StatusCode::NOT_IMPLEMENTED, "webauthn not configured"),
    };
    let (challenge, auth_state) = match webauthn.start_passkey_authentication(&all_keys) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("webauthn login begin error: {e}");
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "authentication init failed",
            );
        }
    };

    let state_key = uuid::Uuid::new_v4().to_string();
    // #3: the pending-state store is capped; refuse rather than grow memory.
    if !auth.save_auth_state(&state_key, auth_state) {
        return err(StatusCode::TOO_MANY_REQUESTS, "too many pending logins");
    }

    let mut res = ok(challenge).into_response();
    let secure = cookie_is_secure(&state, &headers);
    res.headers_mut()
        .insert(header::SET_COOKIE, wa_state_cookie(&state_key, secure));
    res
}

// ── WebAuthn login finish ───────────────────────────────────────────────────────

pub async fn webauthn_login_finish(
    State(state): State<Arc<DashState>>,
    req_headers: axum::http::HeaderMap,
    Json(credential): Json<PublicKeyCredential>,
) -> Response {
    let auth = match get_auth(&state) {
        Ok(a) => a,
        Err(e) => return *e,
    };

    let state_key = match super::auth::extract_cookie(&req_headers, "orbien_wa_state") {
        Some(k) => k,
        None => return err(StatusCode::BAD_REQUEST, "missing auth state"),
    };

    let auth_state = match auth.take_auth_state(&state_key) {
        Some(s) => s,
        None => return err(StatusCode::BAD_REQUEST, "expired or unknown auth state"),
    };

    let webauthn = match auth.webauthn.as_ref() {
        Some(w) => w,
        None => return err(StatusCode::NOT_IMPLEMENTED, "webauthn not configured"),
    };
    match webauthn.finish_passkey_authentication(&credential, &auth_state) {
        Ok(auth_result) => {
            // #3: no `admin` fallback — if the credential no longer maps to
            // a user (deleted between begin and finish), fail the login.
            let Some(username) = auth.apply_auth_result(&auth_result) else {
                return err(StatusCode::UNAUTHORIZED, "authentication failed");
            };

            let token = auth.create_session(&username);
            let secure = cookie_is_secure(&state, &req_headers);
            let cookie = session_cookie(&token, false, secure);
            let clear_wa = clear_wa_state_cookie(secure);

            let mut res = ok(serde_json::json!({ "username": username })).into_response();
            res.headers_mut().insert(header::SET_COOKIE, cookie);
            res.headers_mut().append(header::SET_COOKIE, clear_wa);
            res
        }
        Err(e) => {
            tracing::warn!("webauthn login finish error: {e}");
            err(StatusCode::UNAUTHORIZED, "authentication failed")
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn uuid_for_name(name: &str) -> uuid::Uuid {
    const OFFSET: u128 = 0x6c62272e07bb014262b821756295c58d;
    const PRIME: u128 = 0x0000000001000000000000000000013B;
    let mut hash = OFFSET;
    for &b in name.as_bytes() {
        hash ^= u128::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    uuid::Uuid::from_u128(hash)
}

fn current_username(state: &DashState, headers: &axum::http::HeaderMap) -> Option<String> {
    let auth = state.auth.as_ref()?;
    let token = super::auth::extract_cookie(headers, "orbien_session")?;
    auth.validate_session(&token)
}

fn registration_authorized(state: &DashState, headers: &axum::http::HeaderMap) -> bool {
    if let Some(auth) = &state.auth {
        if let Some(token) = super::auth::extract_cookie(headers, "orbien_session") {
            if auth.validate_session(&token).is_some() {
                return true;
            }
        }
    }
    basic_headers_ok(state, headers)
}

fn basic_headers_ok(state: &DashState, headers: &axum::http::HeaderMap) -> bool {
    use base64::Engine;
    let Some(h) = headers
        .get(axum::http::header::AUTHORIZATION)
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
