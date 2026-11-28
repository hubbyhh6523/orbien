use super::{ConnectionInfo, Plugin, PluginContext};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use fast_socks5::{
    server::{DnsResolveHelper, Socks5ServerProtocol, SocksServerError},
    util::target_addr::TargetAddr,
    ReplyError, Socks5Command,
};
use orbien_core::auth::constant_time_eq;
use orbien_core::config::PluginConfig;
use orbien_core::io::{join_counted, join_counted_idle};
use orbien_core::net::Cidr;
use orbien_core::ratelimit::LogThrottle;
use orbien_core::transport::DynStream;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

/// Connect timeout for the outbound dial (unchanged from before #17).
const RELAY_TIMEOUT_SECS: u64 = 30;
/// Simultaneous SOCKS5 sessions per tunnel when `maxConnections` is 0.
const DEFAULT_SESSION_CAP: usize = 64;
/// Sources tracked for auth failures; stale entries are swept lazily.
const MAX_TRACKED_SOURCES: usize = 1024;
/// Log at most one auth-failure line per interval (per plugin instance).
const FAIL_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// Key for failures whose source address is empty or unparseable.
const UNKNOWN_SOURCE: IpAddr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

pub struct Socks5Plugin {
    tunnel_name: String,
    allow_private_targets: bool,
    allowed_targets: Vec<Cidr>,
    server_addrs: Vec<IpAddr>,
    idle_timeout: Option<Duration>,
    /// Credential check + per-source failure tracking (#17).
    auth: Arc<AuthGate>,
    /// Concurrent relay cap (#17): `maxConnections` when > 0, else 64.
    sessions: Arc<Semaphore>,
}

/// Constant-time credential check with per-source failure counting and
/// lockout (#17). Runs synchronously: the fast-socks5 auth callback is
/// `FnMut`, so the gate is shared with the `serve` future through an
/// `Arc` instead of `&self`.
struct AuthGate {
    tunnel: String,
    expected_user: String,
    expected_pass: String,
    max_failures: u32,
    lockout: Duration,
    fail_log: LogThrottle,
    state: Mutex<HashMap<IpAddr, FailState>>,
}

struct FailState {
    failures: u32,
    last_failure: Instant,
    locked_until: Option<Instant>,
}

impl AuthGate {
    fn new(
        tunnel: String,
        expected_user: String,
        expected_pass: String,
        max_failures: u32,
        lockout: Duration,
    ) -> Self {
        Self {
            tunnel,
            expected_user,
            expected_pass,
            max_failures,
            lockout,
            fail_log: LogThrottle::new(FAIL_LOG_INTERVAL),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Source key: the #15 visitor address from `StartDataConn`; empty or
    /// unparseable sources share one bucket so guessing is still limited
    /// when the address is missing.
    fn source_key(src_addr: &str) -> IpAddr {
        src_addr.trim().parse().unwrap_or(UNKNOWN_SOURCE)
    }

    /// True when this source is locked out. Also sweeps stale entries so
    /// the map cannot grow without bound.
    fn is_locked(&self, src: IpAddr) -> bool {
        let mut state = self.state.lock().expect("auth gate lock");
        let now = Instant::now();
        let keep_for = self.lockout.max(Duration::from_secs(1));
        state.retain(|_, st| {
            st.locked_until.is_some_and(|until| until > now)
                || now.duration_since(st.last_failure) < keep_for
        });
        state
            .get(&src)
            .is_some_and(|st| st.locked_until.is_some_and(|until| until > now))
    }

    /// Constant-time credential check that records the outcome. A good
    /// login clears the source's failure state.
    fn check(&self, src: IpAddr, user: &str, pass: &str) -> bool {
        let user_ok = constant_time_eq(user.as_bytes(), self.expected_user.as_bytes());
        let pass_ok = constant_time_eq(pass.as_bytes(), self.expected_pass.as_bytes());
        if user_ok && pass_ok {
            self.state.lock().expect("auth gate lock").remove(&src);
            return true;
        }
        let failures = {
            let mut state = self.state.lock().expect("auth gate lock");
            if state.len() >= MAX_TRACKED_SOURCES && !state.contains_key(&src) {
                // Bound the map: drop an arbitrary entry rather than
                // tracking unboundedly. `is_locked` already swept stale.
                if let Some(k) = state.keys().next().copied() {
                    state.remove(&k);
                }
            }
            let st = state.entry(src).or_insert_with(|| FailState {
                failures: 0,
                last_failure: Instant::now(),
                locked_until: None,
            });
            st.failures += 1;
            st.last_failure = Instant::now();
            if self.max_failures > 0 && st.failures >= self.max_failures {
                st.locked_until = Some(Instant::now() + self.lockout);
            }
            st.failures
        };
        if self.fail_log.should_log() {
            tracing::warn!(
                tunnel = %self.tunnel,
                src = %src,
                failures,
                "socks5 login failed"
            );
        }
        false
    }
}

impl Socks5Plugin {
    pub fn new(ctx: PluginContext, cfg: &PluginConfig) -> Result<Self> {
        let (username, password) = required_credentials(cfg)?;
        // Config validation already parsed these; fail closed if it didn't.
        let allowed_targets = cfg
            .allowed_targets
            .iter()
            .map(|s| Cidr::parse(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("socks5 allowedTargets: {e}"))?;
        let cap = if ctx.max_connections > 0 {
            ctx.max_connections
        } else {
            DEFAULT_SESSION_CAP
        };
        tracing::info!(
            tunnel = %ctx.name,
            username = %username,
            sessions = cap,
            idle_timeout_secs = cfg.idle_timeout_secs,
            allow_private_targets = cfg.allow_private_targets,
            "plugin socks5 ready"
        );
        Ok(Self {
            tunnel_name: ctx.name.clone(),
            allow_private_targets: cfg.allow_private_targets,
            allowed_targets,
            server_addrs: ctx.server_addrs,
            idle_timeout: if cfg.idle_timeout_secs == 0 {
                None
            } else {
                Some(Duration::from_secs(cfg.idle_timeout_secs))
            },
            auth: Arc::new(AuthGate::new(
                ctx.name,
                username,
                password,
                cfg.auth_max_failures,
                Duration::from_secs(cfg.auth_lockout_secs),
            )),
            sessions: Arc::new(Semaphore::new(cap)),
        })
    }

    /// Destination policy (#17), applied to the resolved IP. The
    /// allow-list wins over every refusal; the client's own server
    /// address is always refused; non-public destinations (loopback,
    /// link-local, private, unspecified, multicast, broadcast,
    /// documentation, benchmarking, reserved, CGNAT) need the
    /// `allowPrivateTargets` opt-in.
    fn check_destination(&self, target: &TargetAddr) -> Result<(), String> {
        let TargetAddr::Ip(sock) = target else {
            return Err("target was not resolved to an IP".to_string());
        };
        let ip = normalize_ip(sock.ip());
        if self.allowed_targets.iter().any(|c| c.contains(ip)) {
            return Ok(());
        }
        if self
            .server_addrs
            .iter()
            .any(|a| normalize_ip(*a) == ip)
        {
            return Err(format!("target {ip} is the orbien server address"));
        }
        if !self.allow_private_targets && is_non_public(ip) {
            return Err(format!("target {ip} is not a public address"));
        }
        Ok(())
    }

    async fn serve(&self, conn: ConnectionInfo) -> Result<()> {
        let src = AuthGate::source_key(&conn.src_addr);
        // Refuse locked-out sources before reading credentials: no
        // credential oracle, and the attempt costs no auth round-trip.
        // (The lockout itself was already logged when it was triggered.)
        if self.auth.is_locked(src) {
            tracing::debug!(
                tunnel = %self.tunnel_name,
                src = %conn.src_addr,
                "socks5 source locked out; dropping connection"
            );
            return Err(anyhow!("socks5 source locked out"));
        }
        // Fail fast when the session cap is full instead of queueing: a
        // queued connection would hold a data conn while waiting.
        let _permit = match self.sessions.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!(
                    tunnel = %self.tunnel_name,
                    src = %conn.src_addr,
                    "socks5 session cap reached"
                );
                return Err(anyhow!("socks5 session cap reached"));
            }
        };

        let auth = Arc::clone(&self.auth);
        let (proto, cmd, target_addr) =
            Socks5ServerProtocol::accept_password_auth(conn.stream, move |user, pass| {
                auth.check(src, &user, &pass)
            })
            .await
            .map_err(map_server_err)?
            .0
            .read_command()
            .await
            .map_err(map_server_err)?
            .resolve_dns()
            .await
            .map_err(map_server_err)?;

        match cmd {
            Socks5Command::TCPConnect => {
                if let Err(reason) = self.check_destination(&target_addr) {
                    tracing::debug!(
                        tunnel = %self.tunnel_name,
                        src = %conn.src_addr,
                        target = %target_addr,
                        reason = %reason,
                        "socks5 destination refused"
                    );
                    let _ = proto.reply_error(&ReplyError::ConnectionNotAllowed).await;
                    return Err(anyhow!("socks5 destination refused: {reason}"));
                }
                tracing::debug!(
                    tunnel = %self.tunnel_name,
                    target = %target_addr,
                    "socks5 relay starting"
                );
                if let Err(e) = self.relay(proto, &target_addr).await {
                    tracing::debug!(
                        tunnel = %self.tunnel_name,
                        error = %e,
                        "socks5 relay ended"
                    );
                }
            }
            _ => {
                let _ = proto.reply_error(&ReplyError::CommandNotSupported).await;
                return Err(anyhow!("socks5 unsupported command {:?}", cmd));
            }
        }
        Ok(())
    }

    /// Same connect + success reply as `run_tcp_proxy`, but the copy uses
    /// `join_counted_idle` so a silent connection ends on the idle
    /// timeout instead of living forever.
    async fn relay(
        &self,
        proto: Socks5ServerProtocol<DynStream, fast_socks5::server::states::CommandRead>,
        target: &TargetAddr,
    ) -> Result<()> {
        let addr = target
            .to_socket_addrs()
            .map_err(|e| anyhow!("socks5 target address: {e}"))?
            .next()
            .ok_or_else(|| anyhow!("socks5 target has no socket address"))?;
        let outbound = match tokio::time::timeout(
            Duration::from_secs(RELAY_TIMEOUT_SECS),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                let code = match e.kind() {
                    ErrorKind::TimedOut => ReplyError::HostUnreachable,
                    ErrorKind::ConnectionRefused => ReplyError::ConnectionRefused,
                    _ => ReplyError::GeneralFailure,
                };
                let _ = proto.reply_error(&code).await;
                return Err(anyhow!("socks5 connect {addr}: {e}"));
            }
            Err(_) => {
                let _ = proto.reply_error(&ReplyError::HostUnreachable).await;
                return Err(anyhow!("socks5 connect {addr} timed out"));
            }
        };
        orbien_core::net::enable_nodelay(&outbound);
        let mut inner = proto
            .reply_success(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                0,
            ))
            .await
            .map_err(map_server_err)?;
        let (sent, received, err) = match self.idle_timeout {
            Some(idle) => join_counted_idle(&mut inner, outbound, idle).await,
            None => join_counted(&mut inner, outbound).await,
        };
        tracing::debug!(
            tunnel = %self.tunnel_name,
            sent,
            received,
            error = ?err,
            "socks5 relay ended"
        );
        Ok(())
    }
}

#[async_trait]
impl Plugin for Socks5Plugin {
    fn name(&self) -> &str {
        "socks5"
    }

    async fn handle(&self, conn: ConnectionInfo) -> Result<()> {
        self.serve(conn).await
    }
}

/// IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is the same host as the IPv4
/// address; normalize before any range check (#15 pattern).
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        ip => ip,
    }
}

/// True for addresses that are not globally routable unicast
/// destinations. `IpAddr` itself only exposes `is_unspecified` /
/// `is_loopback` / `is_multicast`, so match on the family (#17).
fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                // No stable std helpers for these three (still behind the
                // `ip` feature); check the prefixes directly.
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 benchmarking
                || (o[0] & 0xf0) == 0xf0 // 240.0.0.0/4 reserved
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // 100.64.0.0/10 shared (CGNAT)
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                // 2001:db8::/32 documentation range (no std helper).
                || (v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
        }
    }
}

fn required_credentials(cfg: &PluginConfig) -> Result<(String, String)> {
    let user = cfg.username.trim();
    let pass = cfg.password.trim();
    if user.is_empty() || pass.is_empty() {
        bail!("socks5 plugin requires username and password");
    }
    Ok((user.to_string(), pass.to_string()))
}

fn map_server_err(err: SocksServerError) -> anyhow::Error {
    anyhow::Error::new(err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orbien_core::transport::boxed_stream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn context() -> PluginContext {
        PluginContext {
            name: "socks5-test".to_owned(),
            cert_common_name: "localhost".to_owned(),
            server_addrs: vec!["10.9.8.7".parse().unwrap()],
            max_connections: 0,
        }
    }

    fn config() -> PluginConfig {
        PluginConfig {
            plugin_type: "socks5".to_owned(),
            username: "admin".to_owned(),
            password: "correct-horse-battery".to_owned(),
            ..Default::default()
        }
    }

    fn plugin_with(cfg: PluginConfig) -> Socks5Plugin {
        Socks5Plugin::new(context(), &cfg).unwrap()
    }

    fn dest(ip: &str) -> TargetAddr {
        TargetAddr::Ip(SocketAddr::new(ip.parse().unwrap(), 80))
    }

    #[test]
    fn private_targets_refused_by_default() {
        let p = plugin_with(config());
        for ip in [
            "127.0.0.1",
            "127.9.9.9",
            "10.0.0.5",
            "172.16.4.4",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "198.18.0.1",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
            "::ffff:10.0.0.5",
        ] {
            assert!(p.check_destination(&dest(ip)).is_err(), "{ip} must be refused");
        }
        assert!(p.check_destination(&dest("8.8.8.8")).is_ok());
        assert!(p.check_destination(&dest("2606:4700:4700::1111")).is_ok());
    }

    #[test]
    fn allow_list_wins_over_refusals() {
        let mut cfg = config();
        cfg.allowed_targets = vec!["10.0.0.0/8".to_string(), "192.168.1.100".to_string()];
        let p = plugin_with(cfg);
        assert!(p.check_destination(&dest("10.9.9.9")).is_ok());
        assert!(p.check_destination(&dest("192.168.1.100")).is_ok());
        assert!(p.check_destination(&dest("192.168.1.101")).is_err());
        // The server address is refused unless it is on the allow list.
        assert!(p.check_destination(&dest("10.9.8.7")).is_ok());
    }

    #[test]
    fn server_address_refused_even_with_private_opt_in() {
        let mut cfg = config();
        cfg.allow_private_targets = true;
        let p = plugin_with(cfg);
        assert!(p.check_destination(&dest("10.0.0.5")).is_ok());
        assert!(p.check_destination(&dest("10.9.8.7")).is_err());
    }

    #[test]
    fn credentials_compare_in_constant_time() {
        let p = plugin_with(config());
        let src = "203.0.113.7".parse().unwrap();
        assert!(p.auth.check(src, "admin", "correct-horse-battery"));
        assert!(!p.auth.check(src, "admin", "correct-horse-batterx"));
        assert!(!p.auth.check(src, "admix", "correct-horse-battery"));
        assert!(!p.auth.check(src, "admin", "short"));
    }

    #[test]
    fn failures_lock_out_and_success_resets() {
        let mut cfg = config();
        cfg.auth_max_failures = 3;
        cfg.auth_lockout_secs = 60;
        let p = plugin_with(cfg);
        let src: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(!p.auth.is_locked(src));
        assert!(!p.auth.check(src, "admin", "nope"));
        assert!(!p.auth.check(src, "admin", "nope"));
        assert!(!p.auth.is_locked(src));
        assert!(!p.auth.check(src, "admin", "nope"));
        assert!(p.auth.is_locked(src));
        // A second plugin with a 1 s lockout proves expiry and reset.
        let mut cfg2 = config();
        cfg2.auth_max_failures = 2;
        cfg2.auth_lockout_secs = 1;
        let p2 = plugin_with(cfg2);
        let src2: IpAddr = "203.0.113.8".parse().unwrap();
        assert!(!p2.auth.check(src2, "admin", "nope"));
        assert!(!p2.auth.check(src2, "admin", "nope"));
        assert!(p2.auth.is_locked(src2));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(!p2.auth.is_locked(src2));
        assert!(p2.auth.check(src2, "admin", "correct-horse-battery"));
        assert!(!p2.auth.is_locked(src2));
    }

    #[test]
    fn unknown_source_shares_one_bucket() {
        let mut cfg = config();
        cfg.auth_max_failures = 2;
        cfg.auth_lockout_secs = 60;
        let p = plugin_with(cfg);
        let unknown = AuthGate::source_key("");
        assert_eq!(unknown, UNKNOWN_SOURCE);
        assert!(!p.auth.check(unknown, "admin", "nope"));
        assert!(!p.auth.check(unknown, "admin", "nope"));
        assert!(p.auth.is_locked(unknown));
    }

    /// Drive `serve` over a duplex stream with a hand-rolled minimal
    /// SOCKS5 client: greeting, user/pass subnegotiation, CONNECT.
    struct Socks5Client {
        stream: tokio::io::DuplexStream,
    }

    impl Socks5Client {
        async fn greet(&mut self) {
            self.stream.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut buf = [0u8; 2];
            self.stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, [0x05, 0x02], "server must select password auth");
        }

        /// Returns the auth status byte (0 = ok).
        async fn login(&mut self, user: &str, pass: &str) -> u8 {
            let mut req = vec![0x01, user.len() as u8];
            req.extend_from_slice(user.as_bytes());
            req.push(pass.len() as u8);
            req.extend_from_slice(pass.as_bytes());
            self.stream.write_all(&req).await.unwrap();
            let mut buf = [0u8; 2];
            self.stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 0x01);
            buf[1]
        }

        async fn connect_to(&mut self, ip: [u8; 4], port: u16) {
            let mut req = vec![0x05, 0x01, 0x00, 0x01];
            req.extend_from_slice(&ip);
            req.extend_from_slice(&port.to_be_bytes());
            self.stream.write_all(&req).await.unwrap();
        }

        async fn read_reply(&mut self) -> Vec<u8> {
            let mut buf = vec![0u8; 10];
            self.stream.read_exact(&mut buf).await.unwrap();
            buf
        }
    }

    fn run_plugin(
        plugin: Arc<Socks5Plugin>,
        stream: tokio::io::DuplexStream,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let conn = ConnectionInfo {
                stream: boxed_stream(stream),
                src_addr: "203.0.113.7".to_string(),
                src_port: 50000,
                dst_addr: String::new(),
                dst_port: 0,
            };
            let _ = plugin.handle(conn).await;
        })
    }

    #[tokio::test]
    async fn serve_refuses_loopback_target() {
        let plugin = Arc::new(plugin_with(config()));
        let (a, b) = tokio::io::duplex(4096);
        let task = run_plugin(Arc::clone(&plugin), b);
        let mut client = Socks5Client { stream: a };
        client.greet().await;
        assert_eq!(client.login("admin", "correct-horse-battery").await, 0);
        client.connect_to([127, 0, 0, 1], 80).await;
        let reply = client.read_reply().await;
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x02, "loopback must be refused (not allowed)");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn serve_relay_to_allowed_target_and_idle_timeout() {
        // Allow-list the loopback range so a local listener is reachable.
        let mut cfg = config();
        cfg.allowed_targets = vec!["127.0.0.0/8".to_string()];
        cfg.idle_timeout_secs = 1;
        let plugin = Arc::new(plugin_with(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
            // Then stay silent: the plugin must end the relay on the idle
            // timeout instead of holding it forever.
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let (a, b) = tokio::io::duplex(65536);
        let task = run_plugin(Arc::clone(&plugin), b);
        let mut client = Socks5Client { stream: a };
        client.greet().await;
        assert_eq!(client.login("admin", "correct-horse-battery").await, 0);
        client.connect_to([127, 0, 0, 1], port).await;
        let reply = client.read_reply().await;
        assert_eq!(reply[1], 0x00, "allowed target must connect: {reply:?}");
        client.stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        // Silence from here: the idle timeout (1 s) must end the relay.
        let done = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert!(done.is_ok(), "relay must end on the idle timeout");
        echo.abort();
    }

    #[tokio::test]
    async fn serve_locks_out_after_failures() {
        let mut cfg = config();
        cfg.auth_max_failures = 2;
        cfg.auth_lockout_secs = 60;
        let plugin = Arc::new(plugin_with(cfg));
        for _ in 0..2 {
            let (a, b) = tokio::io::duplex(4096);
            let task = run_plugin(Arc::clone(&plugin), b);
            let mut client = Socks5Client { stream: a };
            client.greet().await;
            // Any non-zero status means failure (fast-socks5 sends 0xFF).
            assert_ne!(client.login("admin", "wrong").await, 0);
            task.await.unwrap();
        }
        // Third attempt from the same source is dropped before auth: the
        // server never answers the greeting.
        let (mut a, b) = tokio::io::duplex(4096);
        let task = run_plugin(Arc::clone(&plugin), b);
        a.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(2), a.read(&mut [0u8; 2])).await;
        assert!(
            matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
            "locked-out source must get no greeting reply, got {closed:?}"
        );
        task.await.unwrap();
    }
}
