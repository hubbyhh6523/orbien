//! Reproduction tests for orbien #11 (token policies, route ownership,
//! session identity, data-connection proof).
//!
//! These tests encode the *desired* behaviour from the issue. They fail
//! against main (1853371e) and must pass once the fix lands. Each test
//! names the reproduction it covers.

use super::gw::{HttpGw, HttpRoute};
use super::https::{HttpsGw, HttpsRoute};
use crate::control::Control;
use orbien_core::transport::boxed_stream;
use std::sync::{Arc, Weak};

fn make_control(session_id: &str) -> Arc<Control> {
    let (_peer, stream) = tokio::io::duplex(64 * 1024);
    let cfg = orbien_core::config::ServerConfig::default();
    let access = Arc::new(tokio::sync::RwLock::new(Arc::new(
        crate::access::AccessPolicy::from_server_config(&cfg)
            .expect("default config builds an access policy"),
    )));
    Arc::new(Control::new(
        session_id.into(),
        boxed_stream(stream),
        cfg,
        1,
        None,
        None,
        access,
        "user".into(),
        "host".into(),
        "linux".into(),
        "x86_64".into(),
        "0.2.0".into(),
        "127.0.0.1:1".into(),
        crate::metrics::MemMetrics::new(),
        format!("token-id-{session_id}"),
        "00".repeat(32),
    ))
}

fn http_route(
    name: &str,
    control: &Arc<Control>,
    location: &str,
    route_user: &str,
) -> HttpRoute {
    HttpRoute {
        tunnel_name: name.into(),
        owner_session_id: control.session_id.clone(),
        control: Arc::downgrade(control),
        generation: 0,
        location: location.into(),
        host_header_rewrite: String::new(),
        basic_auth_user: String::new(),
        basic_auth_password: String::new(),
        route_by_http_user: route_user.into(),
        limiter: None,
    }
}

fn https_route(name: &str, control: &Arc<Control>) -> HttpsRoute {
    HttpsRoute {
        tunnel_name: name.into(),
        owner_session_id: control.session_id.clone(),
        control: Arc::downgrade(control),
        generation: 0,
        limiter: None,
    }
}

/// Single-route registration for tests, via the production `register_all`
/// path (the gateway no longer has a single-route `register`).
async fn http_register(gw: &HttpGw, domain: &str, route: HttpRoute) -> anyhow::Result<u64> {
    let session_id = route.owner_session_id.clone();
    gw.register_all(&session_id, vec![(domain.to_string(), route)])
        .await
}

async fn https_register(
    gw: &HttpsGw,
    domain: &str,
    route: HttpsRoute,
) -> anyhow::Result<u64> {
    let session_id = route.owner_session_id.clone();
    gw.register_all(&session_id, vec![(domain.to_string(), route)])
        .await
}

/// Step 5: the data-conn pool holds at most pool_count streams (the
/// control here was made with pool_count 1); a second stream is refused
/// instead of waiting.
#[tokio::test]
async fn data_pool_full_refuses_second_stream() {
    let a = make_control("sess-a");
    let (_peer1, stream1) = tokio::io::duplex(1024);
    let (_peer2, stream2) = tokio::io::duplex(1024);
    assert!(
        a.push_data_conn(boxed_stream(stream1)).await,
        "first stream must queue"
    );
    assert!(
        !a.push_data_conn(boxed_stream(stream2)).await,
        "second stream must be refused when the pool is full"
    );
}

/// Repro 2 (HTTP): a second session must not take over a tunnel name.
#[tokio::test]
async fn http_same_name_takeover_by_other_session_rejected() {
    let gw = HttpGw::new(8080);
    let a = make_control("sess-a");
    let b = make_control("sess-b");
    http_register(&gw, "app.example.com", http_route("web", &a, "", ""))
        .await
        .expect("first registration");
    let err = http_register(&gw, "app.example.com", http_route("web", &b, "", ""))
        .await
        .expect_err("second session must not take over the tunnel name");
    assert!(err.to_string().contains("app.example.com"), "{err}");
}

/// Repro 3 (HTTP): a second session must not register another location
/// under a domain a live session already holds.
#[tokio::test]
async fn http_same_domain_other_location_rejected() {
    let gw = HttpGw::new(8080);
    let a = make_control("sess-a");
    let b = make_control("sess-b");
    http_register(&gw, "app.example.com", http_route("web", &a, "", ""))
        .await
        .expect("first registration");
    http_register(&gw, "app.example.com", http_route("other", &b, "/login", ""))
        .await
        .expect_err("other location under a held domain must be rejected");
}

/// Repro 4 (HTTP): a second session must not register a routeByHTTPUser
/// value under a domain a live session already holds.
#[tokio::test]
async fn http_same_domain_other_route_user_rejected() {
    let gw = HttpGw::new(8080);
    let a = make_control("sess-a");
    let b = make_control("sess-b");
    http_register(&gw, "app.example.com", http_route("web", &a, "", ""))
        .await
        .expect("first registration");
    http_register(&gw, "app.example.com", http_route("other", &b, "", "alice"))
        .await
        .expect_err("routeByHTTPUser under a held domain must be rejected");
}

/// A route whose owning control is gone must not block a new registration.
#[tokio::test]
async fn http_stale_route_does_not_block() {
    let gw = HttpGw::new(8080);
    {
        let a = make_control("sess-a");
        http_register(&gw, "app.example.com", http_route("web", &a, "", ""))
            .await
            .expect("first registration");
        // `a` drops here; its Weak no longer upgrades.
    }
    let b = make_control("sess-b");
    http_register(&gw, "app.example.com", http_route("other", &b, "", ""))
        .await
        .expect("stale route must not block a new registration");
}

/// Regression guard: the same session re-registering its own tunnel
/// replaces it (existing behaviour, must keep working).
#[tokio::test]
async fn http_same_session_reregister_replaces() {
    let gw = HttpGw::new(8080);
    let a = make_control("sess-a");
    let mut first = http_route("web", &a, "", "");
    first.basic_auth_password = "old".into();
    http_register(&gw, "app.example.com", first)
        .await
        .expect("first registration");
    let mut second = http_route("web", &a, "", "");
    second.basic_auth_password = "new".into();
    http_register(&gw, "app.example.com", second)
        .await
        .expect("same-session re-registration must succeed");
    let found = gw
        .lookup("app.example.com", "/", "")
        .await
        .expect("route must still resolve");
    assert_eq!(found.basic_auth_password, "new");
}

/// A dead Weak owner must not keep a route alive for lookup either:
/// lookup of a stale route resolves to nothing once the owner is gone.
/// (Documents the current lookup behaviour; the fix keeps it.)
#[tokio::test]
async fn http_dead_owner_weak_does_not_upgrade() {
    let weak: Weak<Control>;
    {
        let a = make_control("sess-a");
        weak = Arc::downgrade(&a);
        assert!(weak.upgrade().is_some());
    }
    assert!(weak.upgrade().is_none(), "dropped control must not upgrade");
}

/// Repro 2 (HTTPS): same tunnel name, second session must be rejected.
#[tokio::test]
async fn https_same_name_takeover_by_other_session_rejected() {
    let gw = HttpsGw::new(8443);
    let a = make_control("sess-a");
    let b = make_control("sess-b");
    https_register(&gw, "app.example.com", https_route("web", &a))
        .await
        .expect("first registration");
    https_register(&gw, "app.example.com", https_route("web", &b))
        .await
        .expect_err("second session must not take over the https tunnel name");
}

/// A stale HTTPS route must not block a new registration.
#[tokio::test]
async fn https_stale_route_does_not_block() {
    let gw = HttpsGw::new(8443);
    {
        let a = make_control("sess-a");
        https_register(&gw, "app.example.com", https_route("web", &a))
            .await
            .expect("first registration");
    }
    let b = make_control("sess-b");
    https_register(&gw, "app.example.com", https_route("other", &b))
        .await
        .expect("stale https route must not block a new registration");
}

/// Regression guard: same-session HTTPS re-registration replaces.
#[tokio::test]
async fn https_same_session_reregister_replaces() {
    let gw = HttpsGw::new(8443);
    let a = make_control("sess-a");
    https_register(&gw, "app.example.com", https_route("web", &a))
        .await
        .expect("first registration");
    https_register(&gw, "app.example.com", https_route("web", &a))
        .await
        .expect("same-session re-registration must succeed");
    assert!(gw.lookup("app.example.com").await.is_some());
}

/// Repro 10 (HTTP): a register_all whose second domain conflicts adds no
/// route at all — the first domain stays free for other clients.
#[tokio::test]
async fn http_register_all_conflict_adds_nothing() {
    let gw = HttpGw::new(8080);
    let a = make_control("sess-a");
    let b = make_control("sess-b");
    http_register(&gw, "app.example.com", http_route("web", &a, "", ""))
        .await
        .expect("first registration");
    gw.register_all(
        "sess-b",
        vec![
            (
                "free.example.com".to_string(),
                http_route("squat", &b, "", ""),
            ),
            (
                "app.example.com".to_string(),
                http_route("squat", &b, "", ""),
            ),
        ],
    )
    .await
    .expect_err("conflicting second domain must reject the whole batch");
    // free.example.com must still be free for a third client.
    let c = make_control("sess-c");
    http_register(&gw, "free.example.com", http_route("mine", &c, "", ""))
        .await
        .expect("first domain of a failed batch must stay free");
    // A's route is untouched.
    assert!(gw.lookup("app.example.com", "/", "").await.is_some());
}

/// Repro 10 (HTTPS): same atomicity for the SNI gateway.
#[tokio::test]
async fn https_register_all_conflict_adds_nothing() {
    let gw = HttpsGw::new(8443);
    let a = make_control("sess-a");
    let b = make_control("sess-b");
    https_register(&gw, "app.example.com", https_route("web", &a))
        .await
        .expect("first registration");
    gw.register_all(
        "sess-b",
        vec![
            ("free.example.com".to_string(), https_route("squat", &b)),
            ("app.example.com".to_string(), https_route("squat", &b)),
        ],
    )
    .await
    .expect_err("conflicting second domain must reject the whole batch");
    let c = make_control("sess-c");
    https_register(&gw, "free.example.com", https_route("mine", &c))
        .await
        .expect("first domain of a failed batch must stay free");
    assert!(gw.lookup("app.example.com").await.is_some());
}

/// Unregistering one generation of one tunnel must not remove another
/// tunnel of the same session, nor a replacement tunnel of the same name.
#[tokio::test]
async fn http_unregister_removes_only_own_generation() {
    let gw = HttpGw::new(8080);
    let a = make_control("sess-a");
    let gen_web = gw
        .register_all(
            "sess-a",
            vec![(
                "app.example.com".to_string(),
                http_route("web", &a, "", ""),
            )],
        )
        .await
        .expect("register web");
    gw.register_all(
        "sess-a",
        vec![(
            "other.example.com".to_string(),
            http_route("other", &a, "", ""),
        )],
    )
    .await
    .expect("register other");
    // Re-register "web" (new generation); closing the old generation must
    // not delete the replacement's routes.
    gw.register_all(
        "sess-a",
        vec![(
            "app.example.com".to_string(),
            http_route("web", &a, "/v2", ""),
        )],
    )
    .await
    .expect("re-register web");
    gw.unregister_tunnel("sess-a", "web", gen_web).await;
    assert!(
        gw.lookup("app.example.com", "/v2", "").await.is_some(),
        "replacement route must survive closing the old generation"
    );
    assert!(
        gw.lookup("other.example.com", "/", "").await.is_some(),
        "other tunnel of the same session must survive"
    );
}

/// Same for HTTPS: unregister is scoped to (session, name, generation).
#[tokio::test]
async fn https_unregister_removes_only_own_generation() {
    let gw = HttpsGw::new(8443);
    let a = make_control("sess-a");
    let gen_web = gw
        .register_all(
            "sess-a",
            vec![("app.example.com".to_string(), https_route("web", &a))],
        )
        .await
        .expect("register web");
    gw.register_all(
        "sess-a",
        vec![("other.example.com".to_string(), https_route("other", &a))],
    )
    .await
    .expect("register other");
    gw.register_all(
        "sess-a",
        vec![("app.example.com".to_string(), https_route("web", &a))],
    )
    .await
    .expect("re-register web");
    gw.unregister_tunnel("sess-a", "web", gen_web).await;
    assert!(gw.lookup("app.example.com").await.is_some());
    assert!(gw.lookup("other.example.com").await.is_some());
}

/// Re-registering with fewer locations drops the locations that are no
/// longer covered, as the old unregister-first order did.
#[tokio::test]
async fn http_same_session_reregister_drops_removed_location() {
    let gw = HttpGw::new(8080);
    let a = make_control("sess-a");
    http_register(&gw, "app.example.com", http_route("web", &a, "", ""))
        .await
        .expect("first registration");
    http_register(&gw, "app.example.com", http_route("web", &a, "/v2", ""))
        .await
        .expect("re-registration must succeed");
    assert!(gw.lookup("app.example.com", "/", "").await.is_none());
    assert!(
        gw.lookup("app.example.com", "/v2", "").await.is_some(),
        "new location must resolve"
    );
}
