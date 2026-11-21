use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,

    #[serde(default, rename = "quicPort", alias = "quic_port")]
    pub quic_port: u16,

    #[serde(default, rename = "kcpPort", alias = "kcp_port")]
    pub kcp_port: u16,

    #[serde(default, rename = "httpGwPort", alias = "http_gw_port")]
    pub http_gw_port: u16,

    #[serde(default, rename = "httpsGwPort", alias = "https_gw_port")]
    pub https_gw_port: u16,

    #[serde(default, rename = "rootDomain", alias = "root_domain")]
    pub root_domain: String,

    #[serde(default)]
    pub auth: AuthConfig,

    #[serde(
        default = "default_proxy_addr",
        rename = "proxyAddr",
        alias = "proxy_addr"
    )]
    pub proxy_addr: String,

    #[serde(default)]
    pub transport: ServerTransportConfig,

    #[serde(default)]
    pub dashboard: DashboardConfig,

    #[serde(
        default = "default_udp_packet_size",
        rename = "udpPacketSize",
        alias = "udp_packet_size"
    )]
    pub udp_packet_size: usize,

    #[serde(default, rename = "proxyProtocol", alias = "proxy_protocol")]
    pub proxy_protocol: bool,

    #[serde(
        default,
        rename = "proxyProtocolTrustedCidrs",
        alias = "proxy_protocol_trusted_cidrs"
    )]
    pub proxy_protocol_trusted_cidrs: Vec<String>,

    #[serde(default, rename = "denySrcCidrs", alias = "deny_src_cidrs")]
    pub deny_src_cidrs: Vec<String>,

    #[serde(
        default = "default_proxy_protocol_timeout",
        rename = "proxyProtocolTimeoutSecs",
        alias = "proxy_protocol_timeout_secs"
    )]
    pub proxy_protocol_timeout_secs: u64,

    #[serde(default, rename = "udpWorkReadSecs", alias = "udp_work_read_secs")]
    pub udp_work_read_secs: u64,

    #[serde(
        default,
        rename = "workConnTimeoutSecs",
        alias = "work_conn_timeout_secs"
    )]
    pub work_conn_timeout_secs: u64,

    #[serde(
        default,
        rename = "singleClientPerUser",
        alias = "single_client_per_user"
    )]
    pub single_client_per_user: bool,

    #[serde(
        default,
        rename = "ctrlHeartbeatIntervalSecs",
        alias = "ctrl_heartbeat_interval_secs"
    )]
    pub ctrl_heartbeat_interval_secs: u64,

    #[serde(
        default,
        rename = "ctrlHeartbeatTimeoutSecs",
        alias = "ctrl_heartbeat_timeout_secs"
    )]
    pub ctrl_heartbeat_timeout_secs: u64,
}

/// Per-token access policy entry.
///
/// `PartialEq` is derived so that `reload_access_policy` can compare
/// the old and new `token_policies` vecs with `!=` (E0369 fix).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TokenPolicy {
    pub token: String,
    #[serde(default, alias = "allowedTunnels")]
    pub allowed_tunnels: Vec<String>,
    #[serde(default, alias = "allowedProtocols")]
    pub allowed_protocols: Vec<String>,
    #[serde(default, alias = "allowedRemotePorts")]
    pub allowed_remote_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(default = "default_auth_type", rename = "type", alias = "auth_type")]
    pub auth_type: String,
    #[serde(default)]
    pub token: String,
    #[serde(default, alias = "tokenPolicies")]
    pub token_policies: Vec<TokenPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTransportConfig {
    #[serde(default = "default_tcp_mux", rename = "tcpMux", alias = "tcp_mux")]
    pub tcp_mux: bool,

    #[serde(
        default = "default_tcp_mux_keepalive",
        rename = "muxKeepaliveSecs",
        alias = "mux_keepalive_secs"
    )]
    pub mux_keepalive_secs: i64,

    #[serde(default, rename = "maxConnPool", alias = "max_conn_pool")]
    pub max_conn_pool: i64,

    #[serde(default, rename = "heartbeatTimeout", alias = "heartbeat_timeout")]
    pub heartbeat_timeout: i64,
    #[serde(default)]
    pub quic: QuicOptions,

    #[serde(default)]
    pub tls: ServerTlsConfig,
}

impl Default for ServerTransportConfig {
    fn default() -> Self {
        Self {
            tcp_mux: default_tcp_mux(),
            mux_keepalive_secs: default_tcp_mux_keepalive(),
            max_conn_pool: 0,
            heartbeat_timeout: 0,
            quic: QuicOptions::default(),
            tls: ServerTlsConfig::default(),
        }
    }
}

/// Dashboard web server configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DashboardConfig {
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub password: String,
    #[serde(default, rename = "webauthnRpId", alias = "webauthn_rp_id")]
    pub webauthn_rp_id: String,
    #[serde(default, rename = "webauthnOrigin", alias = "webauthn_origin")]
    pub webauthn_origin: String,
    #[serde(default, rename = "staticDir", alias = "static_dir")]
    pub static_dir: String,
    /// Path to the TOML config file that was used to start the server.
    /// Stored here so that `POST /api/v1/config/reload` can re-read it
    /// without the caller having to supply the path every time.
    ///
    /// This field is **not** deserialized from the config file itself
    /// (it would be a circular reference); it is injected at startup by
    /// `main.rs` after the config is loaded.
    #[serde(skip)]
    pub config_file: Option<String>,
    /// Explicitly disable authentication — for local dev / CI only.
    /// WARNING: Never set this in production.
    #[serde(default, rename = "disableAuth", alias = "disable_auth")]
    pub disable_auth: bool,
    /// Optional path for persisting WebAuthn passkeys (M3). When set, passkey
    /// registrations survive dashboard restarts; the file is JSON, written
    /// with 0600 permissions. Sessions themselves remain in-memory by design
    /// (short-lived, restart invalidation is acceptable and safer).
    #[serde(default, rename = "passkeyStorePath", alias = "passkey_store_path")]
    pub passkey_store_path: String,
}

impl DashboardConfig {
    pub fn complete(&mut self) {
        if self.addr.trim().is_empty() {
            self.addr = "127.0.0.1".into();
        }
    }
    pub fn enabled(&self) -> bool {
        self.port > 0
    }
    pub fn webauthn_enabled(&self) -> bool {
        !self.webauthn_rp_id.trim().is_empty() && !self.webauthn_origin.trim().is_empty()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        if self.disable_auth {
            return Ok(());
        }
        let user = self.user.trim();
        let pass = self.password.trim();
        if user.is_empty() || pass.is_empty() {
            anyhow::bail!(
                "dashboard.user and dashboard.password are required when dashboard.port > 0 \
                 (set dashboard.disableAuth = true to opt out for local dev/testing)"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerTlsConfig {
    #[serde(default)]
    pub force: bool,
    #[serde(default, rename = "certFile", alias = "cert_file")]
    pub cert_file: String,
    #[serde(default, rename = "keyFile", alias = "key_file")]
    pub key_file: String,
    #[serde(default, rename = "trustedCaFile", alias = "trusted_ca_file")]
    pub trusted_ca_file: String,
}

fn default_tcp_mux() -> bool {
    true
}
fn default_tcp_mux_keepalive() -> i64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuicOptions {
    #[serde(
        default = "default_quic_keepalive",
        rename = "keepalivePeriod",
        alias = "keepalive_period"
    )]
    pub keepalive_period: u64,
    #[serde(
        default = "default_quic_idle",
        rename = "maxIdleTimeout",
        alias = "max_idle_timeout"
    )]
    pub max_idle_timeout: u64,
    #[serde(
        default = "default_quic_streams",
        rename = "maxIncomingStreams",
        alias = "max_incoming_streams"
    )]
    pub max_incoming_streams: u32,
}

impl Default for QuicOptions {
    fn default() -> Self {
        Self {
            keepalive_period: default_quic_keepalive(),
            max_idle_timeout: default_quic_idle(),
            max_incoming_streams: default_quic_streams(),
        }
    }
}

impl QuicOptions {
    pub fn keepalive(&self) -> Duration {
        Duration::from_secs(self.keepalive_period.max(1))
    }
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.max_idle_timeout.max(1))
    }
}

fn default_listen() -> String {
    format!("{}:{}", default_listen_host(), default_listen_port())
}

fn default_listen_host() -> String {
    "0.0.0.0".into()
}
fn default_listen_port() -> u16 {
    9527
}

fn default_proxy_addr() -> String {
    default_listen_host()
}

fn default_auth_type() -> String {
    "token".into()
}
fn default_quic_keepalive() -> u64 {
    10
}
fn default_quic_idle() -> u64 {
    30
}
fn default_quic_streams() -> u32 {
    100_000
}
fn default_udp_packet_size() -> usize {
    1500
}
fn default_proxy_protocol_timeout() -> u64 {
    5
}

pub fn parse_host_port(raw: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok((default_listen_host(), default_port));
    }

    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid listen address '{raw}': missing ']'"))?;
        if host.is_empty() {
            return Err(anyhow!("invalid listen address '{raw}': empty IPv6 host"));
        }
        let host = format!("[{host}]");
        if after.is_empty() {
            return Ok((host, default_port));
        }
        let port_str = after
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("invalid listen address '{raw}': expected ':' after ']'"))?;
        if port_str.is_empty() {
            return Ok((host, default_port));
        }
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid listen port in '{raw}'"))?;
        if port == 0 {
            return Ok((host, default_port));
        }
        return Ok((host, port));
    }

    if let Some((host, port_str)) = s.rsplit_once(':') {
        if !host.is_empty() && !host.contains(':') {
            if port_str.is_empty() {
                return Ok((host.to_string(), default_port));
            }
            let port: u16 = port_str
                .parse()
                .with_context(|| format!("invalid listen port in '{raw}'"))?;
            if port == 0 {
                return Ok((host.to_string(), default_port));
            }
            return Ok((host.to_string(), port));
        }
    }

    Ok((s.to_string(), default_port))
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            quic_port: 0,
            kcp_port: 0,
            http_gw_port: 0,
            https_gw_port: 0,
            root_domain: String::new(),
            auth: AuthConfig::default(),
            proxy_addr: default_proxy_addr(),
            transport: ServerTransportConfig::default(),
            dashboard: DashboardConfig::default(),
            udp_packet_size: default_udp_packet_size(),
            proxy_protocol: false,
            proxy_protocol_trusted_cidrs: Vec::new(),
            deny_src_cidrs: Vec::new(),
            proxy_protocol_timeout_secs: default_proxy_protocol_timeout(),
            udp_work_read_secs: 0,
            work_conn_timeout_secs: 0,
            single_client_per_user: false,
            ctrl_heartbeat_interval_secs: 0,
            ctrl_heartbeat_timeout_secs: 0,
        }
    }
}

impl ServerConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let file = super::read_toml_file(path)?;
        let expanded = super::expand_env_placeholders(&file)?;
        let mut cfg: Self = toml::from_str(&expanded)
            .with_context(|| format!("failed to parse config file '{}'", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        cfg.resolve_paths(base);
        cfg.complete();
        cfg.validate()?;
        Ok(cfg)
    }

    fn resolve_paths(&mut self, base: &Path) {
        let tls = &mut self.transport.tls;
        tls.cert_file = super::resolve_maybe_relative(base, &tls.cert_file);
        tls.key_file = super::resolve_maybe_relative(base, &tls.key_file);
        tls.trusted_ca_file = super::resolve_maybe_relative(base, &tls.trusted_ca_file);
        if !self.dashboard.static_dir.trim().is_empty() {
            self.dashboard.static_dir =
                super::resolve_maybe_relative(base, &self.dashboard.static_dir);
        }
    }

    pub fn from_defaults() -> Self {
        let mut cfg = Self::default();
        cfg.complete();
        cfg
    }

    pub fn listen_host(&self) -> anyhow::Result<String> {
        Ok(parse_host_port(&self.listen, default_listen_port())?.0)
    }

    pub fn listen_port(&self) -> anyhow::Result<u16> {
        Ok(parse_host_port(&self.listen, default_listen_port())?.1)
    }

    pub fn complete(&mut self) {
        match parse_host_port(&self.listen, default_listen_port()) {
            Ok((host, port)) => {
                self.listen = format!("{host}:{port}");
            }
            Err(_) => {
                self.listen = default_listen();
            }
        }
        if self.proxy_addr.trim().is_empty() {
            self.proxy_addr = self.listen_host().unwrap_or_else(|_| default_listen_host());
        }
        if self.auth.auth_type.trim().is_empty() {
            self.auth.auth_type = default_auth_type();
        }
        if self.udp_packet_size == 0 {
            self.udp_packet_size = default_udp_packet_size();
        }
        self.dashboard.complete();
        if self.transport.max_conn_pool == 0 {
            self.transport.max_conn_pool = 5;
        }
        if self.transport.heartbeat_timeout == 0 {
            self.transport.heartbeat_timeout = if self.transport.tcp_mux { -1 } else { 90 };
        }
        if !self.transport.tls.trusted_ca_file.trim().is_empty() {
            self.transport.tls.force = true;
        }
        if self.udp_work_read_secs == 0 {
            self.udp_work_read_secs = 60;
        }
        if self.work_conn_timeout_secs == 0 {
            self.work_conn_timeout_secs = 10;
        }
        if self.ctrl_heartbeat_interval_secs == 0 {
            self.ctrl_heartbeat_interval_secs = 30;
        }
        if self.ctrl_heartbeat_timeout_secs == 0 {
            self.ctrl_heartbeat_timeout_secs = 90;
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let (listen_host, listen_port) = parse_host_port(&self.listen, default_listen_port())
            .with_context(|| format!("invalid listen '{}'", self.listen))?;

        if self.quic_enabled() && self.kcp_enabled() && self.quic_port == self.kcp_port {
            anyhow::bail!(
                "quicPort and kcpPort both use UDP and must differ (got {})",
                self.quic_port
            );
        }

        if self.http_gw_enabled()
            && tcp_listen_conflicts(
                &listen_host,
                listen_port,
                &self.proxy_addr,
                self.http_gw_port,
            )
        {
            anyhow::bail!(
                "httpGwPort ({}) must not share a TCP listen with listen ({}) \
                 on overlapping addresses (listen host={}, proxyAddr={}). \
                 HTTP gateway and the control/WebSocket listener are separate sockets; \
                 put HTTP on 80 (or another free port), keep control on listen.",
                self.http_gw_port,
                self.listen,
                listen_host,
                self.proxy_addr
            );
        }

        if self.https_gw_enabled()
            && tcp_listen_conflicts(
                &listen_host,
                listen_port,
                &self.proxy_addr,
                self.https_gw_port,
            )
        {
            anyhow::bail!(
                "httpsGwPort ({}) must not share a TCP listen with listen ({}) \
                 on overlapping addresses (listen host={}, proxyAddr={}). \
                 HTTPS visitors and control TLS both start with 0x16; Orbien does not \
                 mux them on one port. Use 443 (or another free port) for HTTPS gateway.",
                self.https_gw_port,
                self.listen,
                listen_host,
                self.proxy_addr
            );
        }

        if self.http_gw_enabled()
            && self.https_gw_enabled()
            && self.http_gw_port == self.https_gw_port
        {
            anyhow::bail!(
                "httpGwPort and httpsGwPort must differ (both set to {})",
                self.http_gw_port
            );
        }

        self.dashboard.validate()?;

        Ok(())
    }

    pub fn quic_enabled(&self) -> bool {
        self.quic_port != 0
    }
    pub fn kcp_enabled(&self) -> bool {
        self.kcp_port != 0
    }
    pub fn http_gw_enabled(&self) -> bool {
        self.http_gw_port != 0
    }
    pub fn https_gw_enabled(&self) -> bool {
        self.https_gw_port != 0
    }

    pub fn udp_work_read_deadline(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.udp_work_read_secs.max(1))
    }

    pub fn work_conn_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.work_conn_timeout_secs.max(1))
    }

    pub fn ctrl_heartbeat_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.ctrl_heartbeat_interval_secs.max(1))
    }

    pub fn ctrl_heartbeat_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.ctrl_heartbeat_timeout_secs.max(1))
    }
}

fn tcp_listen_conflicts(addr_a: &str, port_a: u16, addr_b: &str, port_b: u16) -> bool {
    if port_a == 0 || port_b == 0 || port_a != port_b {
        return false;
    }
    listen_addrs_overlap(addr_a, addr_b)
}

fn listen_addrs_overlap(a: &str, b: &str) -> bool {
    let a = a.trim();
    let b = b.trim();
    if a.is_empty() || b.is_empty() {
        return true;
    }
    if is_unspecified_bind(a) || is_unspecified_bind(b) {
        return true;
    }
    a.eq_ignore_ascii_case(b)
}

fn is_unspecified_bind(addr: &str) -> bool {
    matches!(addr, "0.0.0.0" | "::" | "[::]")
}
