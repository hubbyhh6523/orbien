use super::gw::{build_domains, normalize_host};
use crate::access::{prepare_ingress, AccessPolicy};
use crate::control::Control;
use crate::metrics;
use anyhow::{anyhow, Result};
use orbien_core::limit::{maybe_limit, BandwidthLimiter};
use orbien_core::msg::NewTunnel;
use orbien_core::tls::{peek_client_hello_sni, PrefixedStream};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, RwLock};

#[derive(Clone)]
pub struct HttpsRoute {
    pub tunnel_name: String,
    /// Session that owns this route; see `HttpRoute::owner_session_id` (#11).
    pub owner_session_id: String,
    pub control: Weak<Control>,
    /// Registration generation, stamped by `HttpsGw::register_all` (#11).
    pub generation: u64,
    pub limiter: Option<Arc<BandwidthLimiter>>,
}

pub struct HttpsGw {
    routes: Mutex<HashMap<String, HttpsRoute>>,
    next_generation: AtomicU64,
    pub listen_port: u16,
}

impl HttpsGw {
    pub fn new(listen_port: u16) -> Self {
        Self {
            routes: Mutex::new(HashMap::new()),
            next_generation: AtomicU64::new(1),
            listen_port,
        }
    }

    /// Validate every (domain, route) pair first, then add all of them
    /// under one lock; any conflict adds nothing. Returns the generation
    /// stamped on the new routes (#11). A domain is owned by the first
    /// live session that registers it; a route whose owner is gone is
    /// evicted and does not block.
    pub async fn register_all(
        &self,
        session_id: &str,
        routes: Vec<(String, HttpsRoute)>,
    ) -> Result<u64> {
        let mut pending: Vec<(String, HttpsRoute)> = Vec::with_capacity(routes.len());
        for (domain, route) in routes {
            let key = normalize_host(&domain);
            if key.is_empty() {
                return Err(anyhow!("empty https domain"));
            }
            pending.push((key, route));
        }
        if pending.is_empty() {
            return Err(anyhow!("no https routes to register"));
        }
        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        let mut map = self.routes.lock().await;
        for (key, route) in &pending {
            if let Some(existing) = map.get(key) {
                if existing.control.upgrade().is_none() {
                    continue;
                }
                if existing.owner_session_id != session_id {
                    return Err(anyhow!("https domain {key} is owned by another session"));
                }
                if existing.tunnel_name != route.tunnel_name {
                    return Err(anyhow!("router config conflict: domain={key} (https)"));
                }
            }
        }
        for (key, mut route) in pending {
            route.generation = generation;
            map.insert(key.clone(), route);
            tracing::info!(domain = %key, "https route registered");
        }
        Ok(generation)
    }

    /// Remove only the routes of one registration generation of one
    /// session's tunnel (#11).
    pub async fn unregister_tunnel(&self, session_id: &str, tunnel_name: &str, generation: u64) {
        let mut map = self.routes.lock().await;
        map.retain(|_, r| {
            !(r.owner_session_id == session_id
                && r.tunnel_name == tunnel_name
                && r.generation == generation)
        });
    }

    pub async fn lookup(&self, sni: &str) -> Option<HttpsRoute> {
        let key = normalize_host(sni);
        let map = self.routes.lock().await;
        map.get(&key).cloned()
    }
}

pub struct HttpsTunnel {
    pub name: String,
    pub domains: Vec<String>,
    session_id: String,
    generation: u64,
    gw: Arc<HttpsGw>,
    closed: AtomicBool,
}

impl HttpsTunnel {
    pub async fn register(
        np: &NewTunnel,
        control: Arc<Control>,
        gw: Arc<HttpsGw>,
        sub_domain_host: &str,
        limiter: Option<Arc<BandwidthLimiter>>,
    ) -> Result<Self> {
        let domains = build_domains(&np.domains, sub_domain_host)?;
        let name = np.tunnel_name.clone();
        // #11: enforce the session token's allowed_domains on the final
        // expanded names, before any route is created.
        control
            .access_policy()
            .await
            .authorize_domains(control.token_id(), &domains, sub_domain_host)?;

        // #11: register all routes atomically; a conflict adds nothing
        // and the previous tunnel of the same name stays in place.
        let generation = gw
            .register_all(
                &control.session_id,
                domains
                    .iter()
                    .map(|domain| {
                        (
                            domain.clone(),
                            HttpsRoute {
                                tunnel_name: name.clone(),
                                owner_session_id: control.session_id.clone(),
                                control: Arc::downgrade(&control),
                                generation: 0,
                                limiter: limiter.clone(),
                            },
                        )
                    })
                    .collect(),
            )
            .await?;

        tracing::info!(
            tunnel = %name,
            domains = ?domains,
            "https tunnel registered (SNI passthrough)"
        );

        Ok(Self {
            name,
            domains,
            session_id: control.session_id.clone(),
            generation,
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
            self.gw
                .unregister_tunnel(&self.session_id, &self.name, self.generation)
                .await;
        }
    }
}

pub async fn run_https_gw_listener(
    bind_addr: String,
    port: u16,
    gw: Arc<HttpsGw>,
    access: Arc<RwLock<Arc<AccessPolicy>>>,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let addr = format!("{bind_addr}:{port}");
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(%addr, "https gateway listener ready (SNI mux, no TLS terminate)");

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
                            if let Err(e) = handle_https_ingress(gw, stream, peer, access).await {
                                tracing::debug!(%peer, error = %e, "https ingress ended");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "https gateway accept failed");
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_https_ingress(
    gw: Arc<HttpsGw>,
    stream: TcpStream,
    peer: std::net::SocketAddr,
    access: Arc<AccessPolicy>,
) -> Result<()> {
    let mut ingress = prepare_ingress(stream, peer, &access).await?;
    let (sni, prefix) = peek_client_hello_sni(&mut ingress.stream).await?;
    let Some(route) = gw.lookup(&sni).await else {
        tracing::debug!(
            peer = %ingress.peer,
            source = %ingress.source,
            %sni,
            "https no route for SNI"
        );

        return Ok(());
    };

    let Some(control) = route.control.upgrade() else {
        return Err(anyhow!("https tunnel client gone: {}", route.tunnel_name));
    };

    let data = control.get_data_conn().await?;
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
    let user = PrefixedStream::new(prefix, ingress.stream);

    tracing::debug!(
        tunnel = %route.tunnel_name,
        %sni,
        peer = %ingress.peer,
        source = %ingress.source,
        "https joining ingress <-> data (passthrough)"
    );
    let _ =
        metrics::join_and_record(&control.metrics, &route.tunnel_name, "https", user, data).await;
    Ok(())
}
