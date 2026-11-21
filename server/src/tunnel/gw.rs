use crate::control::Control;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Weak;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct HttpRoute {
    pub tunnel_name: String,
    /// Session that owns this route. A domain is owned by the first live
    /// session that registers under it; other sessions are refused for any
    /// location or routeByHTTPUser value under that domain (#11).
    pub owner_session_id: String,
    pub control: Weak<Control>,
    /// Registration generation, stamped by `HttpGw::register_all`. The
    /// owning tunnel removes only its own generation on close, so replacing
    /// a tunnel never deletes the replacement's routes (#11).
    pub generation: u64,
    pub location: String,
    pub host_header_rewrite: String,
    pub basic_auth_user: String,
    pub basic_auth_password: String,
    pub route_by_http_user: String,
    pub limiter: Option<std::sync::Arc<orbien_core::limit::BandwidthLimiter>>,
}

type DomainIndex = HashMap<String, HashMap<String, Vec<HttpRoute>>>;

pub struct HttpGw {
    routes: Mutex<DomainIndex>,
    next_generation: AtomicU64,
    pub listen_port: u16,
}

impl HttpGw {
    pub fn new(listen_port: u16) -> Self {
        Self {
            routes: Mutex::new(HashMap::new()),
            next_generation: AtomicU64::new(1),
            listen_port,
        }
    }

    /// Validate every (domain, route) pair first, then add all of them
    /// under one lock; any conflict adds nothing. Returns the generation
    /// stamped on the new routes. A domain is owned by the first live
    /// session that registers under it: a different session is refused
    /// for any location or routeByHTTPUser value under that domain, and a
    /// route whose owner is gone (its Weak no longer upgrades) is evicted
    /// and does not block (#11).
    pub async fn register_all(
        &self,
        session_id: &str,
        routes: Vec<(String, HttpRoute)>,
    ) -> anyhow::Result<u64> {
        let mut pending: Vec<(String, HttpRoute)> = Vec::with_capacity(routes.len());
        for (domain, route) in routes {
            let key = normalize_host(&domain);
            if key.is_empty() {
                return Err(anyhow::anyhow!("empty http domain"));
            }
            pending.push((key, route));
        }
        if pending.is_empty() {
            return Err(anyhow::anyhow!("no http routes to register"));
        }
        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        let mut map = self.routes.lock().await;
        // Evict dead routes under the touched domains first.
        for (key, _) in &pending {
            let mut empty = false;
            if let Some(by_user) = map.get_mut(key) {
                by_user.retain(|_, list| {
                    list.retain(|r| r.control.upgrade().is_some());
                    !list.is_empty()
                });
                empty = by_user.is_empty();
            }
            if empty {
                map.remove(key);
            }
        }
        // Pre-check everything before writing anything.
        let mut seen: HashMap<(String, String, String), String> = HashMap::new();
        for (key, route) in &pending {
            if let Some(by_user) = map.get(key) {
                for list in by_user.values() {
                    for existing in list {
                        if existing.owner_session_id != session_id {
                            return Err(anyhow::anyhow!(
                                "http domain {key} is owned by another session"
                            ));
                        }
                    }
                }
                if let Some(list) = by_user.get(&route.route_by_http_user) {
                    if let Some(existing) =
                        list.iter().find(|r| r.location == route.location)
                    {
                        if existing.tunnel_name != route.tunnel_name {
                            return Err(anyhow::anyhow!(
                                "router config conflict: domain={key} location={} routeByHTTPUser={}",
                                route.location,
                                route.route_by_http_user
                            ));
                        }
                    }
                }
            }
            let slot = (
                key.clone(),
                route.route_by_http_user.clone(),
                route.location.clone(),
            );
            if let Some(other) = seen.get(&slot) {
                if other != &route.tunnel_name {
                    return Err(anyhow::anyhow!(
                        "router config conflict: domain={key} location={} routeByHTTPUser={}",
                        route.location,
                        route.route_by_http_user
                    ));
                }
            }
            seen.insert(slot, route.tunnel_name.clone());
        }
        // All checks passed: replace this session's routes for the tunnel
        // under each touched domain (drops locations the new registration
        // no longer covers), then insert the new routes.
        for (key, mut route) in pending {
            if let Some(by_user) = map.get_mut(&key) {
                for list in by_user.values_mut() {
                    list.retain(|r| {
                        !(r.owner_session_id == session_id
                            && r.tunnel_name == route.tunnel_name)
                    });
                }
            }
            route.generation = generation;
            let by_user = map.entry(key.clone()).or_default();
            let list = by_user.entry(route.route_by_http_user.clone()).or_default();
            list.push(route);
            list.sort_by(|a, b| b.location.cmp(&a.location));
            tracing::info!(domain = %key, "http route registered");
        }
        Ok(generation)
    }

    /// Remove only the routes of one registration generation of one
    /// session's tunnel. Other tunnels of the same session, and a
    /// replacement tunnel with the same name, are left alone (#11).
    pub async fn unregister_tunnel(&self, session_id: &str, tunnel_name: &str, generation: u64) {
        let mut map = self.routes.lock().await;
        map.retain(|_, by_user| {
            by_user.retain(|_, list| {
                list.retain(|r| {
                    !(r.owner_session_id == session_id
                        && r.tunnel_name == tunnel_name
                        && r.generation == generation)
                });
                !list.is_empty()
            });
            !by_user.is_empty()
        });
    }

    pub async fn lookup(&self, host: &str, path: &str, route_user: &str) -> Option<HttpRoute> {
        let key = normalize_host(host);
        let map = self.routes.lock().await;
        lookup_exact_or_all_users(&map, &key, path, route_user).cloned()
    }
}

fn lookup_exact_or_all_users<'a>(
    map: &'a DomainIndex,
    host: &str,
    path: &str,
    route_user: &str,
) -> Option<&'a HttpRoute> {
    if let Some(r) = match_location(map, host, path, route_user) {
        return Some(r);
    }
    if !route_user.is_empty() {
        return match_location(map, host, path, "");
    }
    None
}

fn match_location<'a>(
    map: &'a DomainIndex,
    host: &str,
    path: &str,
    route_user: &str,
) -> Option<&'a HttpRoute> {
    let list = map.get(host)?.get(route_user)?;
    list.iter()
        .find(|route| path.starts_with(&route.location))
}

pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let without_port = if let Some(h) = host.strip_prefix('[') {
        if let Some(end) = h.find(']') {
            &h[..end]
        } else {
            host
        }
    } else {
        host.split(':').next().unwrap_or(host)
    };
    without_port
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

pub fn build_domains(domains: &[String], root_domain: &str) -> anyhow::Result<Vec<String>> {
    let root = normalize_host(root_domain);
    let entries: Vec<String> = domains
        .iter()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();

    if entries.is_empty() {
        return Err(anyhow::anyhow!(
            "http/https requires at least one domain (fullDomain or subdomain prefix)"
        ));
    }

    let mut out = Vec::new();
    for entry in &entries {
        out.push(expand_domain_entry(entry, &root)?);
    }

    let mut seen = std::collections::HashSet::new();
    out.retain(|d| seen.insert(d.clone()));
    Ok(out)
}

fn expand_domain_entry(entry: &str, root: &str) -> anyhow::Result<String> {
    let e = normalize_host(entry);
    if e.is_empty() {
        return Err(anyhow::anyhow!("empty domain entry"));
    }
    if e.starts_with('.') || e.ends_with('.') || e.contains("..") {
        return Err(anyhow::anyhow!("invalid domain entry: {entry:?}"));
    }

    if !e.contains('.') {
        if e.contains('*') {
            return Err(anyhow::anyhow!(
                "subdomain prefix must not contain '*': {entry:?}"
            ));
        }
        if e.len() > 63 {
            return Err(anyhow::anyhow!(
                "subdomain prefix too long (max 63): {entry:?}"
            ));
        }
        if root.is_empty() {
            return Err(anyhow::anyhow!(
                "domain prefix {entry:?} requires server rootDomain"
            ));
        }
        return Ok(normalize_host(&format!("{e}.{root}")));
    }

    if e.contains('*') {
        return Err(anyhow::anyhow!(
            "wildcard domains are not supported: {entry:?}"
        ));
    }

    if !root.is_empty() && is_host_under_root(&e, root) {
        return Ok(e);
    }

    Ok(e)
}

fn is_host_under_root(host: &str, root: &str) -> bool {
    host == root || host.ends_with(&format!(".{root}"))
}

pub fn expand_locations(locations: &[String]) -> Vec<String> {
    if locations.is_empty() {
        vec![String::new()]
    } else {
        locations.to_vec()
    }
}

pub fn parse_basic_auth(header_value: &str) -> Option<(String, String)> {
    const PREFIX: &str = "Basic ";
    let value = header_value.trim();
    if value.len() < PREFIX.len() || !value[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value[PREFIX.len()..].trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

pub fn route_user_from_headers(
    is_proxy_request: bool,
    authorization: Option<&str>,
    proxy_authorization: Option<&str>,
) -> String {
    if is_proxy_request {
        if let Some(proxy_auth) = proxy_authorization {
            return parse_basic_auth(proxy_auth)
                .map(|(u, _)| u)
                .unwrap_or_default();
        }
        return authorization
            .and_then(parse_basic_auth)
            .map(|(u, _)| u)
            .unwrap_or_default();
    }
    authorization
        .and_then(parse_basic_auth)
        .map(|(u, _)| u)
        .unwrap_or_default()
}

pub fn route_basic_auth_ok(
    route: &HttpRoute,
    is_proxy_request: bool,
    authorization: Option<&str>,
    proxy_authorization: Option<&str>,
) -> bool {
    if route.basic_auth_user.is_empty() && route.basic_auth_password.is_empty() {
        return true;
    }
    let creds = if is_proxy_request {
        let Some(h) = proxy_authorization else {
            return false;
        };
        parse_basic_auth(h)
    } else {
        let Some(h) = authorization else {
            return false;
        };
        parse_basic_auth(h)
    };
    match creds {
        Some((u, p)) => u == route.basic_auth_user && p == route.basic_auth_password,
        None => false,
    }
}
