use anyhow::{bail, Result};
use orbien_core::auth;
use orbien_core::net::{try_consume_proxy_protocol, PpConsume, PROXY_PROTOCOL_MAX_HEADER};
pub use orbien_core::net::Cidr;
use orbien_core::tls::PrefixedStream;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};

#[derive(Debug, Clone, Default)]
pub struct TokenAccessPolicy {
    pub allowed_tunnels: HashSet<String>,
    pub allowed_protocols: HashSet<String>,
    pub allowed_remote_ports: HashSet<u16>,
    /// Normalized `allowed_domains` patterns: exact lowercase domains and
    /// `*.suffix` wildcards. Empty = only names under `rootDomain`.
    pub allowed_domains: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct AccessPolicy {
    pub proxy_protocol: bool,
    pub trusted_proxy_cidrs: Vec<Cidr>,
    pub deny_src_cidrs: Vec<Cidr>,
    pub pp_header_timeout: Duration,
    pub token_policies: HashMap<String, TokenAccessPolicy>,
}

impl AccessPolicy {
    pub fn from_server_config(cfg: &orbien_core::config::ServerConfig) -> Result<Self> {
        let trusted = cfg
            .proxy_protocol_trusted_cidrs
            .iter()
            .map(|s| Cidr::parse(s))
            .collect::<Result<Vec<_>>>()?;
        let deny = cfg
            .deny_src_cidrs
            .iter()
            .map(|s| Cidr::parse(s))
            .collect::<Result<Vec<_>>>()?;
        if cfg.proxy_protocol && trusted.is_empty() {
            tracing::warn!(
                "proxyProtocol=true but proxyProtocolTrustedCidrs empty — \
                 PROXY protocol headers are ignored until trusted CIDRs are set"
            );
        }
        let mut token_policies = HashMap::new();
        for policy in &cfg.auth.token_policies {
            let token = policy.token.trim();
            if token.is_empty() {
                continue;
            }
            // #11: the map is keyed by token id (SHA-256 hex), never the
            // raw token. Two entries for the same token are a config error.
            let id = auth::token_id(token);
            if token_policies.contains_key(&id) {
                bail!("duplicate token in token_policies");
            }
            let tunnels = policy
                .allowed_tunnels
                .iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect::<HashSet<_>>();
            let protocols = policy
                .allowed_protocols
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect::<HashSet<_>>();
            let ports = policy
                .allowed_remote_ports
                .iter()
                .copied()
                .filter(|p| *p > 0)
                .collect::<HashSet<_>>();
            let domains = policy
                .allowed_domains
                .iter()
                .map(|s| normalize_domain_pattern(s))
                .collect::<Result<HashSet<_>>>()?;
            token_policies.insert(
                id,
                TokenAccessPolicy {
                    allowed_tunnels: tunnels,
                    allowed_protocols: protocols,
                    allowed_remote_ports: ports,
                    allowed_domains: domains,
                },
            );
        }

        Ok(Self {
            proxy_protocol: cfg.proxy_protocol,
            trusted_proxy_cidrs: trusted,
            deny_src_cidrs: deny,
            pp_header_timeout: Duration::from_secs(cfg.proxy_protocol_timeout_secs.max(1)),
            token_policies,
        })
    }

    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        !self.trusted_proxy_cidrs.is_empty()
            && self.trusted_proxy_cidrs.iter().any(|c| c.contains(ip))
    }

    pub fn is_denied(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        !self.deny_src_cidrs.is_empty() && self.deny_src_cidrs.iter().any(|c| c.contains(ip))
    }

    /// Check a tunnel registration against the token's policy (#11).
    /// `token` is the token id (SHA-256 hex), as stored on the session.
    pub fn authorize_proxy(
        &self,
        token: &str,
        tunnel: &str,
        proxy_type: &str,
        remote_port: Option<u16>,
    ) -> Result<()> {
        let Some(policy) = self.token_policies.get(token) else {
            // Fail-closed: if token policies are configured but this token
            // is not listed, deny access to prevent allowlist bypass.
            if !self.token_policies.is_empty() {
                bail!("token is not authorized for proxy registration");
            }
            // No policies configured at all — allow (backward compatibility).
            return Ok(());
        };

        if !policy.allowed_tunnels.is_empty() && !policy.allowed_tunnels.contains(tunnel) {
            bail!("token is not allowed to register tunnel: {tunnel}");
        }

        let proxy_type = proxy_type.trim().to_ascii_lowercase();
        if !policy.allowed_protocols.is_empty() && !policy.allowed_protocols.contains(&proxy_type) {
            bail!("token is not allowed to register proxy type: {proxy_type}");
        }

        if !policy.allowed_remote_ports.is_empty() {
            let Some(port) = remote_port else {
                bail!(
                    "token is not allowed to register proxy without remote port restriction match"
                );
            };
            if !policy.allowed_remote_ports.contains(&port) {
                bail!("token is not allowed to use remote port: {port}");
            }
        }

        Ok(())
    }

    /// Check every domain an http/https tunnel wants to register (#11).
    /// `token` is the token id (SHA-256 hex), as stored on the session.
    ///
    /// `domains` are the final names after `build_domains` expansion, so
    /// subdomain prefixes under `rootDomain` are covered too. Rules:
    /// - no policy for this token and policies configured at all: deny
    ///   (fail-closed, same as `authorize_proxy`);
    /// - no policies configured, or the policy has empty `allowed_domains`:
    ///   only names under `rootDomain`;
    /// - otherwise every domain must match an exact pattern or a
    ///   `*.suffix` pattern in the policy.
    pub fn authorize_domains(
        &self,
        token: &str,
        domains: &[String],
        root_domain: &str,
    ) -> Result<()> {
        let root = root_domain.trim().to_ascii_lowercase();
        let under_root = |d: &str| {
            !root.is_empty() && (d == root || d.ends_with(&format!(".{root}")))
        };
        let policy = self.token_policies.get(token);
        match policy {
            None => {
                if !self.token_policies.is_empty() {
                    bail!("token is not authorized for domain registration");
                }
                for d in domains {
                    let d = d.trim().to_ascii_lowercase();
                    if !under_root(&d) {
                        bail!("domain {d} is outside rootDomain");
                    }
                }
                Ok(())
            }
            Some(policy) => {
                if policy.allowed_domains.is_empty() {
                    for d in domains {
                        let d = d.trim().to_ascii_lowercase();
                        if !under_root(&d) {
                            bail!("domain {d} is outside rootDomain");
                        }
                    }
                    return Ok(());
                }
                for d in domains {
                    let d = d.trim().to_ascii_lowercase();
                    if !policy
                        .allowed_domains
                        .iter()
                        .any(|p| domain_matches_pattern(&d, p))
                    {
                        bail!("domain {d} is not allowed by this token's policy");
                    }
                }
                Ok(())
            }
        }
    }
}

/// `*.suffix` matches any name strictly below `suffix` (`a.example.com`,
/// `a.b.example.com`, but not `example.com` itself); anything else must
/// match exactly. Patterns are already normalized (see
/// `normalize_domain_pattern`).
fn domain_matches_pattern(domain: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        domain.len() > suffix.len() + 1 && domain.ends_with(&format!(".{suffix}"))
    } else {
        domain == pattern
    }
}

/// Normalize one `allowed_domains` entry to a lowercase exact domain or
/// `*.suffix` pattern. Anything else fails here so a typo is caught at
/// startup / `--check-config` instead of silently never matching.
fn normalize_domain_pattern(entry: &str) -> Result<String> {
    let e = entry.trim().to_ascii_lowercase();
    if e.is_empty() {
        bail!("invalid allowed_domains pattern {entry:?}: empty");
    }
    if !e
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '*')
    {
        bail!("invalid allowed_domains pattern {entry:?}: bad character");
    }
    if e.starts_with('.') || e.ends_with('.') || e.contains("..") {
        bail!("invalid allowed_domains pattern {entry:?}");
    }
    let suffix = e.strip_prefix("*.").unwrap_or(&e);
    if suffix.contains('*') {
        bail!("invalid allowed_domains pattern {entry:?}: '*' only allowed as leading '*.'");
    }
    if suffix.is_empty() {
        bail!("invalid allowed_domains pattern {entry:?}: empty suffix");
    }
    for label in suffix.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            bail!("invalid allowed_domains pattern {entry:?}: bad label");
        }
    }
    Ok(e)
}

/// Normalize an address for policy matching: an IPv4-mapped IPv6
/// address (`::ffff:a.b.c.d`) matches IPv4 rules (#15). `to_ipv4_mapped`
/// is `Ipv6Addr`-only on older toolchains, so match explicitly instead
/// of `IpAddr::to_ipv4_mapped` (CI pins Rust 1.92).
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

pub struct IngressConn {
    pub stream: PrefixedStream<TcpStream>,
    pub peer: SocketAddr,
    pub source: SocketAddr,
    pub local: Option<SocketAddr>,
}

/// #15: every gateway listener runs through here, so deny/PROXY handling
/// lives in `prepare_visitor` and this is a thin mapping (`source` is the
/// visitor the header names, or the peer when there is none). A bail here
/// closes the connection before any data connection is requested.
pub async fn prepare_ingress(
    stream: TcpStream,
    peer: SocketAddr,
    policy: &AccessPolicy,
) -> Result<IngressConn> {
    let v = prepare_visitor(stream, peer, policy).await?;
    Ok(IngressConn {
        stream: v.stream,
        peer: v.peer,
        source: v.visitor,
        local: v.local,
    })
}

pub struct VisitorConn {
    pub stream: PrefixedStream<TcpStream>,
    pub peer: SocketAddr,
    pub visitor: SocketAddr,
    pub local: Option<SocketAddr>,
}

pub async fn prepare_visitor(
    stream: TcpStream,
    peer: SocketAddr,
    policy: &AccessPolicy,
) -> Result<VisitorConn> {
    let local = stream.local_addr().ok();
    let (stream, mut visitor) = if policy.proxy_protocol && policy.is_trusted_proxy(peer.ip()) {
        read_optional_pp(stream, peer, policy.pp_header_timeout).await?
    } else {
        (PrefixedStream::new(Vec::new(), stream), peer)
    };

    if visitor.ip().is_unspecified() {
        visitor = peer;
    }

    if policy.is_denied(visitor.ip()) {
        tracing::info!(visitor = %visitor.ip(), peer = %peer, "denied by denySrcCidrs");
        anyhow::bail!("visitor {} denied by denySrcCidrs", visitor.ip());
    }

    Ok(VisitorConn {
        stream,
        peer,
        visitor,
        local,
    })
}

async fn read_optional_pp(
    mut stream: TcpStream,
    peer: SocketAddr,
    hdr_timeout: Duration,
) -> Result<(PrefixedStream<TcpStream>, SocketAddr)> {
    let mut buf = vec![0u8; PROXY_PROTOCOL_MAX_HEADER];
    let mut filled = 0usize;
    // #15: one total deadline from the first read, not a per-read
    // timeout — a peer dripping one byte at a time must not hold the
    // connection open indefinitely.
    let deadline = Instant::now() + hdr_timeout;

    loop {
        match try_consume_proxy_protocol(&buf[..filled])? {
            PpConsume::Done(parsed) => {
                let leftover = buf[parsed.header_len..filled].to_vec();
                tracing::debug!(
                    peer = %peer,
                    visitor = %parsed.src,
                    header_len = parsed.header_len,
                    "PROXY protocol accepted from trusted peer"
                );
                return Ok((PrefixedStream::new(leftover, stream), parsed.src));
            }
            PpConsume::NotProxy => {
                let leftover = buf[..filled].to_vec();
                return Ok((PrefixedStream::new(leftover, stream), peer));
            }
            PpConsume::Incomplete => {
                if filled >= buf.len() {
                    bail!("PROXY protocol header incomplete / too large");
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                let n = timeout(remaining, stream.read(&mut buf[filled..]))
                    .await
                    .map_err(|_| anyhow::anyhow!("timeout waiting for PROXY protocol header"))??;
                if n == 0 {
                    bail!("connection closed while reading PROXY protocol");
                }
                filled += n;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessPolicy, TokenAccessPolicy};
    use orbien_core::auth::token_id;
    use std::collections::{HashMap, HashSet};
    use std::time::Duration;

    fn hs_str(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn hs_u16(items: &[u16]) -> HashSet<u16> {
        items.iter().copied().collect()
    }

    fn base_policy() -> AccessPolicy {
        AccessPolicy {
            proxy_protocol: false,
            trusted_proxy_cidrs: vec![],
            deny_src_cidrs: vec![],
            pp_header_timeout: Duration::from_secs(1),
            token_policies: HashMap::new(),
        }
    }

    fn policy(token_policy: TokenAccessPolicy) -> AccessPolicy {
        let mut policy = base_policy();
        policy
            .token_policies
            .insert("tok-a".to_string(), token_policy);
        policy
    }

    #[test]
    fn authorize_proxy_allows_unknown_token_when_no_policies_configured() {
        // When no token policies are configured, allow all tokens (backward compatibility)
        let p = base_policy();
        assert!(p.authorize_proxy("tok-x", "db", "tcp", Some(3306)).is_ok());
    }

    #[test]
    fn authorize_proxy_denies_unknown_token_when_policies_exist() {
        // Fail-closed: when policies are configured, unknown tokens must be denied
        let p = policy(TokenAccessPolicy {
            allowed_tunnels: hs_str(&["db"]),
            ..Default::default()
        });
        assert!(p.authorize_proxy("tok-unknown", "db", "tcp", Some(3306)).is_err());
    }

    #[test]
    fn authorize_proxy_allows_matching_rules() {
        let p = policy(TokenAccessPolicy {
            allowed_tunnels: hs_str(&["db"]),
            allowed_protocols: hs_str(&["tcp"]),
            allowed_remote_ports: hs_u16(&[3306]),
            allowed_domains: hs_str(&[]),
        });
        assert!(p.authorize_proxy("tok-a", "db", "tcp", Some(3306)).is_ok());
    }

    #[test]
    fn authorize_proxy_rejects_tunnel() {
        let p = policy(TokenAccessPolicy {
            allowed_tunnels: hs_str(&["db"]),
            ..Default::default()
        });
        assert!(p
            .authorize_proxy("tok-a", "web", "tcp", Some(3306))
            .is_err());
    }

    #[test]
    fn authorize_proxy_rejects_protocol() {
        let p = policy(TokenAccessPolicy {
            allowed_protocols: hs_str(&["tcp", "udp"]),
            ..Default::default()
        });
        assert!(p.authorize_proxy("tok-a", "db", "http", None).is_err());
    }

    #[test]
    fn authorize_proxy_matches_protocol_case_insensitively() {
        let p = policy(TokenAccessPolicy {
            allowed_protocols: hs_str(&["tcp", "https"]),
            ..Default::default()
        });
        assert!(p.authorize_proxy("tok-a", "db", "TCP", Some(3306)).is_ok());
        assert!(p.authorize_proxy("tok-a", "site", "HTTPS", None).is_ok());
    }

    #[test]
    fn authorize_proxy_rejects_remote_port() {
        let p = policy(TokenAccessPolicy {
            allowed_remote_ports: hs_u16(&[3306]),
            ..Default::default()
        });
        assert!(p.authorize_proxy("tok-a", "db", "tcp", Some(5432)).is_err());
    }

    #[test]
    fn authorize_proxy_rejects_missing_remote_port_when_policy_requires_it() {
        let p = policy(TokenAccessPolicy {
            allowed_remote_ports: hs_u16(&[443]),
            ..Default::default()
        });
        assert!(p.authorize_proxy("tok-a", "site", "https", None).is_err());
    }

    #[test]
    fn authorize_proxy_allows_http_without_remote_port_when_no_port_policy() {
        let p = policy(TokenAccessPolicy {
            allowed_protocols: hs_str(&["http", "https"]),
            ..Default::default()
        });
        assert!(p.authorize_proxy("tok-a", "site", "http", None).is_ok());
        assert!(p
            .authorize_proxy("tok-a", "site-secure", "https", None)
            .is_ok());
    }

    #[test]
    fn authorize_proxy_ignores_unconfigured_dimensions() {
        let p = policy(TokenAccessPolicy {
            allowed_protocols: hs_str(&["http"]),
            ..Default::default()
        });
        assert!(p.authorize_proxy("tok-a", "any", "http", None).is_ok());
    }

    // ── #11: allowed_domains ─────────────────────────────────────────────

    fn domains(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn authorize_domains_allows_under_root_without_policies() {
        let p = base_policy();
        assert!(p
            .authorize_domains("any-token", &domains(&["app.example.com"]), "example.com")
            .is_ok());
        assert!(p
            .authorize_domains("any-token", &domains(&["example.com"]), "example.com")
            .is_ok());
    }

    #[test]
    fn authorize_domains_rejects_outside_root_without_policies() {
        let p = base_policy();
        assert!(p
            .authorize_domains("any-token", &domains(&["evil.com"]), "example.com")
            .is_err());
        // Empty rootDomain: nothing is under it.
        assert!(p
            .authorize_domains("any-token", &domains(&["app.example.com"]), "")
            .is_err());
    }

    #[test]
    fn authorize_domains_empty_policy_allows_only_root() {
        let p = policy(TokenAccessPolicy {
            allowed_domains: hs_str(&[]),
            ..Default::default()
        });
        assert!(p
            .authorize_domains("tok-a", &domains(&["app.example.com"]), "example.com")
            .is_ok());
        assert!(p
            .authorize_domains("tok-a", &domains(&["evil.com"]), "example.com")
            .is_err());
    }

    #[test]
    fn authorize_domains_matches_exact_and_wildcard() {
        let p = policy(TokenAccessPolicy {
            allowed_domains: hs_str(&["app.example.com", "*.example.org"]),
            ..Default::default()
        });
        assert!(p
            .authorize_domains("tok-a", &domains(&["app.example.com"]), "other.test")
            .is_ok());
        assert!(p
            .authorize_domains("tok-a", &domains(&["a.example.org"]), "other.test")
            .is_ok());
        assert!(p
            .authorize_domains("tok-a", &domains(&["a.b.example.org"]), "other.test")
            .is_ok());
        // The suffix itself is not covered by `*.suffix`.
        assert!(p
            .authorize_domains("tok-a", &domains(&["example.org"]), "other.test")
            .is_err());
        assert!(p
            .authorize_domains("tok-a", &domains(&["other.com"]), "other.test")
            .is_err());
        // Case-insensitive.
        assert!(p
            .authorize_domains("tok-a", &domains(&["APP.EXAMPLE.COM"]), "other.test")
            .is_ok());
    }

    #[test]
    fn authorize_domains_denies_unlisted_token_when_policies_exist() {
        let p = policy(TokenAccessPolicy {
            allowed_domains: hs_str(&["app.example.com"]),
            ..Default::default()
        });
        assert!(p
            .authorize_domains("tok-unknown", &domains(&["app.example.com"]), "example.com")
            .is_err());
    }

    #[test]
    fn normalize_domain_pattern_rejects_bad_patterns() {
        for bad in [
            "",
            "*",
            "*.",
            "bad_*.com",
            "*.bad_*.com",
            "foo.*.com",
            ".example.com",
            "example.com.",
            "foo..bar",
            "exa mple.com",
            "a_b.com",
            "-bad.com",
            "bad-.com",
        ] {
            assert!(
                super::normalize_domain_pattern(bad).is_err(),
                "pattern {bad:?} must be rejected"
            );
        }
        for good in ["example.com", "*.example.com", "a-b.example-2.com", "EXAMPLE.COM"] {
            let normalized = super::normalize_domain_pattern(good).unwrap();
            assert_eq!(normalized, good.to_ascii_lowercase());
        }
    }

    #[test]
    fn from_server_config_keys_policies_by_token_id() {
        use orbien_core::config::ServerConfig;
        let cfg: ServerConfig = toml::from_str(
            "[[auth.token_policies]]\ntoken = 'tok-a'\nallowed_tunnels = ['db']\n",
        )
        .unwrap();
        let p = AccessPolicy::from_server_config(&cfg).unwrap();
        // Looked up by id, never by raw token.
        assert!(p.authorize_proxy(&token_id("tok-a"), "db", "tcp", None).is_ok());
        assert!(p.authorize_proxy("tok-a", "db", "tcp", None).is_err());
    }

    #[test]
    fn from_server_config_rejects_duplicate_tokens_and_bad_patterns() {
        use orbien_core::config::ServerConfig;
        let dup: ServerConfig = toml::from_str(
            "[[auth.token_policies]]\ntoken = 'tok-a'\n\
             [[auth.token_policies]]\ntoken = 'tok-a'\n",
        )
        .unwrap();
        let err = AccessPolicy::from_server_config(&dup).unwrap_err();
        assert!(err.to_string().contains("duplicate token"), "{err}");
        let bad: ServerConfig = toml::from_str(
            "[[auth.token_policies]]\ntoken = 'tok-a'\n\
             allowed_domains = ['bad_*.com']\n",
        )
        .unwrap();
        let err = AccessPolicy::from_server_config(&bad).unwrap_err();
        assert!(
            err.to_string().contains("invalid allowed_domains pattern"),
            "{err}"
        );
    }

    // ── #15: deny / PROXY protocol ─────────────────────────────────────

    use super::{prepare_ingress, Cidr};
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;

    fn policy_15(deny: &[&str], pp: bool, trusted: &[&str], timeout: Duration) -> AccessPolicy {
        let mut p = base_policy();
        p.proxy_protocol = pp;
        p.trusted_proxy_cidrs = trusted.iter().map(|s| Cidr::parse(s).unwrap()).collect();
        p.deny_src_cidrs = deny.iter().map(|s| Cidr::parse(s).unwrap()).collect();
        p.pp_header_timeout = timeout;
        p
    }

    /// Connected loopback pair; returns (client, server) streams.
    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(
            tokio::net::TcpStream::connect(addr),
            listener.accept()
        );
        (client.unwrap(), server.unwrap().0)
    }

    #[test]
    fn deny_matches_ipv4_mapped_ipv6() {
        let p = policy_15(&["1.2.3.4/32"], false, &[], Duration::from_secs(1));
        assert!(p.is_denied("::ffff:1.2.3.4".parse().unwrap()));
        assert!(!p.is_denied("::ffff:1.2.3.5".parse().unwrap()));
        // A v6 rule never matches a v4 address and vice versa.
        let p6 = policy_15(&["::1/128"], false, &[], Duration::from_secs(1));
        assert!(!p6.is_denied("127.0.0.1".parse().unwrap()));
        assert!(p6.is_denied("::1".parse().unwrap()));
        // Trusted-proxy matching normalizes the same way.
        let t = policy_15(&[], true, &["10.0.0.0/8"], Duration::from_secs(1));
        assert!(t.is_trusted_proxy("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!t.is_trusted_proxy("::ffff:192.168.1.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn prepare_ingress_denied_peer_errors() {
        let (_client, server) = tcp_pair().await;
        let peer = server.peer_addr().unwrap();
        let p = policy_15(&["127.0.0.1/32"], false, &[], Duration::from_secs(1));
        let err = match prepare_ingress(server, peer, &p).await {
            Ok(_) => panic!("expected prepare_ingress to fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("denied by denySrcCidrs"), "{err}");
    }

    #[tokio::test]
    async fn prepare_ingress_trusted_pp_v1_sets_visitor() {
        let (mut client, server) = tcp_pair().await;
        let peer = server.peer_addr().unwrap();
        client
            .write_all(b"PROXY TCP4 203.0.113.7 127.0.0.1 1234 80\r\nGET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let p = policy_15(&[], true, &["127.0.0.1/32"], Duration::from_secs(1));
        let ingress = prepare_ingress(server, peer, &p).await.unwrap();
        assert_eq!(ingress.source.ip().to_string(), "203.0.113.7");
        assert_eq!(ingress.source.port(), 1234);
        assert_eq!(ingress.peer, peer);
    }

    #[tokio::test]
    async fn prepare_ingress_trusted_pp_v2_sets_visitor() {
        let (mut client, server) = tcp_pair().await;
        let peer = server.peer_addr().unwrap();
        let src: SocketAddr = "203.0.113.7:1234".parse().unwrap();
        let dst: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let hdr =
            orbien_core::net::build_proxy_protocol_header(src, dst, "v2").unwrap();
        client.write_all(&hdr).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let p = policy_15(&[], true, &["127.0.0.1/32"], Duration::from_secs(1));
        let ingress = prepare_ingress(server, peer, &p).await.unwrap();
        assert_eq!(ingress.source, src);
        assert_eq!(ingress.peer, peer);
    }

    #[tokio::test]
    async fn prepare_ingress_untrusted_pp_ignored() {
        let (mut client, server) = tcp_pair().await;
        let peer = server.peer_addr().unwrap();
        client
            .write_all(b"PROXY TCP4 203.0.113.7 127.0.0.1 1234 80\r\n")
            .await
            .unwrap();
        let p = policy_15(&[], true, &["10.0.0.0/8"], Duration::from_secs(1));
        let ingress = prepare_ingress(server, peer, &p).await.unwrap();
        assert_eq!(ingress.source, peer, "untrusted PP header must be ignored");
    }

    #[tokio::test]
    async fn prepare_ingress_pp_unknown_falls_back_to_peer() {
        let (mut client, server) = tcp_pair().await;
        let peer = server.peer_addr().unwrap();
        client.write_all(b"PROXY UNKNOWN\r\n").await.unwrap();
        let p = policy_15(&[], true, &["127.0.0.1/32"], Duration::from_secs(1));
        let ingress = prepare_ingress(server, peer, &p).await.unwrap();
        assert_eq!(ingress.source, peer);
    }

    #[tokio::test]
    async fn prepare_ingress_denied_visitor_in_header_errors() {
        let (mut client, server) = tcp_pair().await;
        let peer = server.peer_addr().unwrap();
        client
            .write_all(b"PROXY TCP4 203.0.113.7 127.0.0.1 1234 80\r\n")
            .await
            .unwrap();
        let p = policy_15(
            &["203.0.113.7/32"],
            true,
            &["127.0.0.1/32"],
            Duration::from_secs(1),
        );
        let err = match prepare_ingress(server, peer, &p).await {
            Ok(_) => panic!("expected prepare_ingress to fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("denied by denySrcCidrs"), "{err}");
    }

    #[tokio::test]
    async fn prepare_ingress_stalled_header_times_out() {
        let (mut client, server) = tcp_pair().await;
        let peer = server.peer_addr().unwrap();
        // Partial header, then stall: the client socket stays open, so
        // only the total deadline can end this.
        client.write_all(b"PROXY TCP4 203.0.113").await.unwrap();
        let p = policy_15(&[], true, &["127.0.0.1/32"], Duration::from_millis(100));
        let start = tokio::time::Instant::now();
        let err = match prepare_ingress(server, peer, &p).await {
            Ok(_) => panic!("expected prepare_ingress to fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("timeout"), "{err}");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "must fail on the deadline, not hang"
        );
    }

    #[tokio::test]
    async fn prepare_ingress_oversized_header_errors() {
        let (mut client, server) = tcp_pair().await;
        let peer = server.peer_addr().unwrap();
        // A v1 line with no CRLF past 108 bytes is rejected by the
        // parser; the 256-byte buffer bound is the backstop.
        client.write_all(b"PROXY ").await.unwrap();
        client.write_all(&[b'X'; 200]).await.unwrap();
        let p = policy_15(&[], true, &["127.0.0.1/32"], Duration::from_secs(1));
        let err = match prepare_ingress(server, peer, &p).await {
            Ok(_) => panic!("expected prepare_ingress to fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("no CRLF"), "{err}");
    }
}
