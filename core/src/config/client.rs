use super::server::{parse_host_port, QuicOptions};
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default = "default_server")]
    pub server: String,

    #[serde(default)]
    pub user: String,

    #[serde(default)]
    pub auth: AuthConfig,

    #[serde(default)]
    pub transport: TransportConfig,

    #[serde(default)]
    pub tunnels: Vec<TunnelConfig>,

    #[serde(
        default = "default_udp_packet_size",
        rename = "udpPacketSize",
        alias = "udp_packet_size"
    )]
    pub udp_packet_size: usize,

    /// Max visitor sockets/tasks per UDP tunnel forwarder (#14).
    /// 0 in the config file means the default (see `complete()`).
    #[serde(
        default = "default_udp_max_sessions",
        rename = "udpMaxSessions",
        alias = "udp_max_sessions"
    )]
    pub udp_max_sessions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(
        default = "default_auth_type",
        rename = "type",
        alias = "auth_type",
        alias = "authType"
    )]
    pub auth_type: String,
    #[serde(default)]
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    #[serde(default = "default_protocol")]
    pub protocol: String,

    #[serde(
        default = "default_pool_count",
        rename = "poolCount",
        alias = "pool_count"
    )]
    pub pool_count: i32,

    #[serde(default = "default_tcp_mux", rename = "tcpMux", alias = "tcp_mux")]
    pub tcp_mux: bool,

    #[serde(
        default = "default_mux_keepalive_secs",
        rename = "muxKeepaliveSecs",
        alias = "mux_keepalive_secs"
    )]
    pub mux_keepalive_secs: i64,

    #[serde(
        default = "default_heartbeat_interval",
        rename = "heartbeatInterval",
        alias = "heartbeat_interval"
    )]
    pub heartbeat_interval: i64,
    #[serde(
        default = "default_heartbeat_timeout",
        rename = "heartbeatTimeout",
        alias = "heartbeat_timeout"
    )]
    pub heartbeat_timeout: i64,
    #[serde(default)]
    pub quic: QuicOptions,

    #[serde(default)]
    pub tls: ClientTlsConfig,

    /// Override the per-connection yamux stream concurrency limit.
    /// Defaults to [`orbien_core::transport::MAX_NUM_STREAMS`] (256) when absent.
    /// Set via config key `transport.maxYamuxStreams` / `transport.max_yamux_streams`.
    #[serde(
        default,
        rename = "maxYamuxStreams",
        alias = "max_yamux_streams",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_yamux_streams: Option<usize>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            protocol: default_protocol(),
            pool_count: default_pool_count(),
            tcp_mux: default_tcp_mux(),
            mux_keepalive_secs: default_mux_keepalive_secs(),
            heartbeat_interval: default_heartbeat_interval(),
            heartbeat_timeout: default_heartbeat_timeout(),
            quic: QuicOptions::default(),
            tls: ClientTlsConfig::default(),
            max_yamux_streams: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientTlsConfig {
    #[serde(default = "default_tls_enable")]
    pub enable: bool,
    #[serde(default, rename = "certFile", alias = "cert_file")]
    pub cert_file: String,
    #[serde(default, rename = "keyFile", alias = "key_file")]
    pub key_file: String,
    #[serde(default, rename = "trustedCaFile", alias = "trusted_ca_file")]
    pub trusted_ca_file: String,
    #[serde(default, rename = "serverName", alias = "server_name")]
    pub server_name: String,
    /// H1 (TOFU): path to the server certificate fingerprint store. When set
    /// (and no trustedCaFile), the client pins the whole server certificate
    /// (SHA-256 of the DER) on first connect and refuses connections if it
    /// ever changes. Empty = legacy insecure skip-verify behaviour (kept
    /// for backward compatibility).
    #[serde(default, rename = "tofuStoreFile", alias = "tofu_store_file")]
    pub tofu_store_file: String,
    /// #12: explicit opt-in to skip server-certificate verification
    /// (the old default). Default false: with TLS on and neither a
    /// trusted CA nor a TOFU store configured, the client refuses to
    /// connect instead of silently trusting any server. Set it only on
    /// networks you control; skipped verification is a MITM hole.
    #[serde(default, rename = "insecureSkipVerify", alias = "insecure_skip_verify")]
    pub insecure_skip_verify: bool,
}

impl Default for ClientTlsConfig {
    fn default() -> Self {
        Self {
            enable: default_tls_enable(),
            cert_file: String::new(),
            key_file: String::new(),
            trusted_ca_file: String::new(),
            server_name: String::new(),
            tofu_store_file: String::new(),
            insecure_skip_verify: false,
        }
    }
}

fn default_tls_enable() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    pub name: String,

    pub protocol: String,

    #[serde(default)]
    pub service: String,

    #[serde(default, rename = "remotePort", alias = "remote_port")]
    pub remote_port: u16,

    #[serde(default)]
    pub domains: Vec<String>,

    #[serde(default)]
    pub locations: Vec<String>,

    #[serde(default, rename = "basicAuthUser", alias = "basic_auth_user")]
    pub basic_auth_user: String,
    #[serde(default, rename = "basicAuthPassword", alias = "basic_auth_password")]
    pub basic_auth_password: String,

    #[serde(default, rename = "hostHeaderRewrite", alias = "host_header_rewrite")]
    pub host_header_rewrite: String,
    #[serde(default, rename = "routeByHTTPUser", alias = "route_by_http_user")]
    pub route_by_http_user: String,

    #[serde(default)]
    pub transport: TunnelTransportConfig,

    #[serde(default)]
    pub plugin: Option<PluginConfig>,

    /// Maximum simultaneous connections allowed for this proxy.
    /// 0 (default) means unlimited.
    /// TCP/HTTP/HTTPS count live streams; UDP counts recent visitor sessions.
    /// For UDP the server's `maxUdpVisitorsPerTunnel` is the hard cap;
    /// this value can only lower it (#14).
    #[serde(default, rename = "maxConnections", alias = "max_connections")]
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    #[serde(rename = "type", alias = "plugin_type", alias = "pluginType")]
    pub plugin_type: String,

    #[serde(default)]
    pub service: String,

    #[serde(default, rename = "certFile", alias = "cert_file")]
    pub cert_file: String,
    #[serde(default, rename = "keyFile", alias = "key_file")]
    pub key_file: String,
    #[serde(default, rename = "hostHeaderRewrite", alias = "host_header_rewrite")]
    pub host_header_rewrite: String,

    #[serde(default, rename = "requestHeaders", alias = "request_headers")]
    pub request_headers: PluginRequestHeaders,

    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PluginRequestHeaders {
    #[serde(default)]
    pub set: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TunnelTransportConfig {
    #[serde(default)]
    pub bandwidth: f64,

    #[serde(
        default = "default_bandwidth_limit_side",
        rename = "bandwidthLimitSide",
        alias = "bandwidth_limit_side"
    )]
    pub bandwidth_limit_side: String,

    #[serde(
        default,
        rename = "proxyProtocolVersion",
        alias = "proxy_protocol_version"
    )]
    pub proxy_protocol_version: String,
}

fn default_bandwidth_limit_side() -> String {
    "client".into()
}

fn default_auth_type() -> String {
    "token".into()
}

fn default_protocol() -> String {
    "tcp".into()
}

fn default_pool_count() -> i32 {
    1
}

fn default_tcp_mux() -> bool {
    true
}

fn default_mux_keepalive_secs() -> i64 {
    30
}

fn default_heartbeat_interval() -> i64 {
    -1
}

fn default_heartbeat_timeout() -> i64 {
    -1
}

fn default_udp_packet_size() -> usize {
    1500
}

fn default_udp_max_sessions() -> usize {
    1024
}

fn default_server() -> String {
    "127.0.0.1:9527".into()
}

impl TunnelConfig {
    pub fn service_host_port(&self) -> anyhow::Result<(String, u16)> {
        let raw = self.service.trim();
        if raw.is_empty() {
            return Ok(("127.0.0.1".into(), 0));
        }
        let (host, port) = parse_host_port(raw, 0)
            .map_err(|e| anyhow!("tunnel `{}` invalid service: {e}", self.name))?;
        if port == 0 {
            return Err(anyhow!(
                "tunnel `{}` service must include a port (got {raw:?})",
                self.name
            ));
        }
        if host.is_empty() {
            return Err(anyhow!("tunnel `{}` service has empty host", self.name));
        }
        Ok((host, port))
    }

    pub fn has_plugin(&self) -> bool {
        matches!(
            self.plugin
                .as_ref()
                .map(|p| p.plugin_type.trim().is_empty()),
            Some(false)
        )
    }

    pub fn requires_local_service(&self) -> bool {
        !self.has_plugin()
    }
}

enum LoadMode {
    Runtime,
    Edit,
}

impl ClientConfig {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::load_with(path, LoadMode::Runtime)
    }

    pub fn load_for_edit(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        Self::load_with(path, LoadMode::Edit)
    }

    fn load_with(path: impl AsRef<Path>, mode: LoadMode) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let file = super::read_toml_file(path)?;
        let expanded = match mode {
            LoadMode::Runtime => Some(super::expand_env_placeholders(&file)?),
            LoadMode::Edit => {
                super::env::reject_env_placeholders(&file)?;
                None
            }
        };
        let text = expanded.as_deref().unwrap_or(file.as_str());
        let mut cfg: Self = toml::from_str(text)
            .with_context(|| format!("failed to parse config file '{}'", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        if matches!(mode, LoadMode::Runtime) {
            cfg.resolve_paths(base);
        }
        cfg.complete();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn prepare_runtime(&mut self, config_path: &Path) {
        let base = config_path.parent().unwrap_or_else(|| Path::new("."));
        self.resolve_paths(base);
        self.complete();
    }

    fn resolve_paths(&mut self, base: &Path) {
        let tls = &mut self.transport.tls;
        tls.cert_file = super::resolve_maybe_relative(base, &tls.cert_file);
        tls.key_file = super::resolve_maybe_relative(base, &tls.key_file);
        tls.trusted_ca_file = super::resolve_maybe_relative(base, &tls.trusted_ca_file);
        for t in &mut self.tunnels {
            if let Some(ref mut plugin) = t.plugin {
                plugin.cert_file = super::resolve_maybe_relative(base, &plugin.cert_file);
                plugin.key_file = super::resolve_maybe_relative(base, &plugin.key_file);
            }
        }
    }

    pub fn complete(&mut self) {
        if matches!(self.protocol().ok(), Some(crate::transport::Protocol::Quic)) {
            self.transport.tcp_mux = false;
            self.transport.tls.enable = true;
        }

        if !self.transport.tcp_mux {
            if self.transport.heartbeat_interval < 0 {
                self.transport.heartbeat_interval = 30;
            }
            if self.transport.heartbeat_timeout < 0 {
                self.transport.heartbeat_timeout = 90;
            }
        }

        if self.auth.auth_type.trim().is_empty() {
            self.auth.auth_type = default_auth_type();
        }

        if self.udp_packet_size == 0 {
            self.udp_packet_size = default_udp_packet_size();
        }

        if self.udp_max_sessions == 0 {
            self.udp_max_sessions = default_udp_max_sessions();
        }

        if self.transport.tls.server_name.trim().is_empty() {
            if let Ok(host) = self.server_host() {
                self.transport.tls.server_name = host;
            }
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.server.trim().is_empty() {
            return Err(anyhow!("server is required (host:port)"));
        }
        let (host, port) = parse_host_port(&self.server, 9527)
            .map_err(|e| anyhow!("invalid server {:?}: {e}", self.server))?;
        if host.is_empty() {
            return Err(anyhow!("server host is empty"));
        }
        if port == 0 {
            return Err(anyhow!("server port must be > 0"));
        }
        let _ = self.protocol()?;
        if self.transport.pool_count < 1 {
            return Err(anyhow!(
                "transport.poolCount must be >= 1, got {}",
                self.transport.pool_count
            ));
        }
        if self.udp_packet_size == 0 || self.udp_packet_size > 65535 {
            return Err(anyhow!(
                "udpPacketSize out of range: {}",
                self.udp_packet_size
            ));
        }
        if self.transport.heartbeat_timeout > 0
            && self.transport.heartbeat_interval > 0
            && self.transport.heartbeat_timeout < self.transport.heartbeat_interval
        {
            return Err(anyhow!(
                "heartbeatTimeout ({}) must be >= heartbeatInterval ({})",
                self.transport.heartbeat_timeout,
                self.transport.heartbeat_interval
            ));
        }
        for t in &self.tunnels {
            if t.name.trim().is_empty() {
                return Err(anyhow!("tunnel name is required"));
            }
            let proto = t.protocol.trim().to_ascii_lowercase();
            if !matches!(proto.as_str(), "tcp" | "udp" | "http" | "https") {
                return Err(anyhow!(
                    "tunnel `{}` unsupported protocol {:?}",
                    t.name,
                    t.protocol
                ));
            }
            if !t.transport.bandwidth.is_finite() || t.transport.bandwidth < 0.0 {
                return Err(anyhow!(
                    "tunnel `{}` invalid bandwidth {}",
                    t.name,
                    t.transport.bandwidth
                ));
            }
            let side = t.transport.bandwidth_limit_side.trim().to_ascii_lowercase();
            if !side.is_empty() && side != "client" && side != "server" {
                return Err(anyhow!(
                    "tunnel `{}` invalid bandwidthLimitSide {:?}",
                    t.name,
                    t.transport.bandwidth_limit_side
                ));
            }
            match proto.as_str() {
                "tcp" | "udp" => {
                    if t.remote_port == 0 {
                        return Err(anyhow!(
                            "tunnel `{}` remotePort is required for {}",
                            t.name,
                            proto
                        ));
                    }
                    if t.requires_local_service() {
                        let _ = t.service_host_port()?;
                    }
                    if let Some(plugin) = &t.plugin {
                        Self::validate_tcp_tunnel_plugin(t.name.as_str(), plugin)?;
                    }
                }
                "http" | "https" => {
                    if t.domains.is_empty() {
                        return Err(anyhow!(
                            "tunnel `{}` domains is required for {}",
                            t.name,
                            proto
                        ));
                    }
                    if t.requires_local_service() {
                        let _ = t.service_host_port()?;
                    }
                    if let Some(plugin) = &t.plugin {
                        Self::validate_https_tunnel_plugin(t.name.as_str(), plugin)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn validate_tcp_tunnel_plugin(name: &str, plugin: &PluginConfig) -> anyhow::Result<()> {
        let pt = plugin.plugin_type.trim().to_ascii_lowercase();
        if pt.is_empty() {
            return Ok(());
        }
        match pt.as_str() {
            "socks5" => Self::validate_socks5_plugin_fields(name, plugin),
            other => Err(anyhow!(
                "tunnel `{}` unsupported plugin.type {:?}",
                name,
                other
            )),
        }
    }

    fn validate_https_tunnel_plugin(name: &str, plugin: &PluginConfig) -> anyhow::Result<()> {
        let pt = plugin.plugin_type.trim().to_ascii_lowercase();
        if pt.is_empty() {
            return Ok(());
        }
        match pt.as_str() {
            "tls-term" => {
                if plugin.service.trim().is_empty() {
                    return Err(anyhow!(
                        "tunnel `{}` plugin.service is required for tls-term",
                        name
                    ));
                }
                let (h, p) = parse_host_port(&plugin.service, 0)
                    .map_err(|e| anyhow!("tunnel `{}` invalid plugin.service: {e}", name))?;
                if h.is_empty() || p == 0 {
                    return Err(anyhow!(
                        "tunnel `{}` plugin.service must be host:port",
                        name
                    ));
                }
                Ok(())
            }
            other => Err(anyhow!(
                "tunnel `{}` unsupported plugin.type {:?}",
                name,
                other
            )),
        }
    }

    fn validate_socks5_plugin_fields(name: &str, plugin: &PluginConfig) -> anyhow::Result<()> {
        let user = plugin.username.trim();
        let pass = plugin.password.trim();
        if user.is_empty() || pass.is_empty() {
            return Err(anyhow!(
                "tunnel `{}` socks5 requires username and password",
                name
            ));
        }
        Ok(())
    }

    pub fn server_host(&self) -> anyhow::Result<String> {
        Ok(parse_host_port(&self.server, 9527)?.0)
    }

    pub fn server_port(&self) -> anyhow::Result<u16> {
        Ok(parse_host_port(&self.server, 9527)?.1)
    }

    pub fn tls_server_name(&self) -> String {
        let sn = self.transport.tls.server_name.trim();
        if sn.is_empty() {
            self.server_host().unwrap_or_else(|_| "localhost".into())
        } else {
            sn.to_string()
        }
    }

    pub fn server_endpoint(&self) -> String {
        self.server.trim().to_string()
    }

    pub fn protocol(&self) -> anyhow::Result<crate::transport::Protocol> {
        crate::transport::Protocol::parse(&self.transport.protocol).ok_or_else(|| {
            anyhow::anyhow!(
                "unsupported transport.protocol {:?}, use tcp|quic|websocket|kcp",
                self.transport.protocol
            )
        })
    }

    pub fn uses_yamux(&self) -> bool {
        self.transport.tcp_mux
            && matches!(
                self.protocol().ok(),
                Some(
                    crate::transport::Protocol::Tcp
                        | crate::transport::Protocol::Websocket
                        | crate::transport::Protocol::Kcp
                )
            )
    }

    // ── P2P defaults ────────────────────────────────────────────────────────
    // ponytail: no dedicated p2p config section yet; these return fixed
    // defaults.  Upgrade path: add a `p2p` config section (enable_udp,
    // stun_servers, timeout_secs) and read from it here.

    /// Whether the UDP hole-punch path is enabled for P2P tunnels.
    pub fn p2p_enable_udp(&self) -> bool {
        true
    }

    /// STUN servers used for public-address discovery (empty = local-only).
    pub fn p2p_stun_servers(&self) -> Vec<String> {
        Vec::new()
    }

    /// P2P hole-punch timeout in seconds (0 = use the 10 s fallback).
    pub fn p2p_timeout_secs(&self) -> u32 {
        10
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ClientConfig {
        ClientConfig {
            server: "example.com:9527".into(),
            user: "alice".into(),
            auth: AuthConfig {
                auth_type: "token".into(),
                token: "secret".into(),
            },
            transport: TransportConfig::default(),
            tunnels: vec![],
            udp_packet_size: 1500,
            udp_max_sessions: default_udp_max_sessions(),
        }
    }

    #[test]
    fn server_endpoint_formats() {
        let cfg = sample();
        assert_eq!(cfg.server_endpoint(), "example.com:9527");
    }

    #[test]
    fn tls_server_name_falls_back_to_server_addr() {
        let mut cfg = sample();
        cfg.transport.tls.server_name = String::new();
        assert_eq!(cfg.tls_server_name(), "example.com");
    }

    #[test]
    fn tls_server_name_uses_explicit() {
        let mut cfg = sample();
        cfg.transport.tls.server_name = "sni.example.com".into();
        assert_eq!(cfg.tls_server_name(), "sni.example.com");
    }

    #[test]
    fn complete_sets_server_name() {
        let mut cfg = sample();
        cfg.transport.tls.server_name = String::new();
        cfg.complete();
        assert_eq!(cfg.transport.tls.server_name, "example.com");
    }

    #[test]
    fn complete_repairs_negative_heartbeat_when_no_mux() {
        let mut cfg = sample();
        cfg.transport.tcp_mux = false;
        cfg.transport.heartbeat_interval = -1;
        cfg.transport.heartbeat_timeout = -1;
        cfg.complete();
        assert_eq!(cfg.transport.heartbeat_interval, 30);
        assert_eq!(cfg.transport.heartbeat_timeout, 90);
    }

    #[test]
    fn complete_keeps_heartbeat_when_mux() {
        let mut cfg = sample();
        cfg.transport.tcp_mux = true;
        cfg.transport.heartbeat_interval = -1;
        cfg.complete();
        assert_eq!(cfg.transport.heartbeat_interval, -1);
    }

    #[test]
    fn protocol_parses() {
        let mut cfg = sample();
        cfg.transport.protocol = "tcp".into();
        assert!(cfg.protocol().is_ok());
        cfg.transport.protocol = "quic".into();
        assert!(cfg.protocol().is_ok());
        cfg.transport.protocol = "websocket".into();
        assert!(cfg.protocol().is_ok());
        cfg.transport.protocol = "kcp".into();
        assert!(cfg.protocol().is_ok());
    }

    #[test]
    fn protocol_rejects_unknown() {
        let mut cfg = sample();
        cfg.transport.protocol = "sctp".into();
        assert!(cfg.protocol().is_err());
    }

    #[test]
    fn uses_yamux_only_for_muxable_protocols() {
        let mut cfg = sample();
        cfg.transport.tcp_mux = true;
        cfg.transport.protocol = "tcp".into();
        assert!(cfg.uses_yamux());
        cfg.transport.protocol = "quic".into();
        assert!(!cfg.uses_yamux());
        cfg.transport.tcp_mux = false;
        cfg.transport.protocol = "tcp".into();
        assert!(!cfg.uses_yamux());
    }

    #[test]
    fn load_parses_toml_with_defaults() {
        let dir = std::env::temp_dir();
        let path = dir.join("orbien_test_client.toml");
        std::fs::write(
            &path,
            r#"
server = "127.0.0.1:9527"
[[tunnels]]
name = "web"
protocol = "http"
domains = ["web.example.com"]
remotePort = 80
"#,
        )
        .unwrap();
        let cfg = ClientConfig::load(&path).unwrap();
        assert_eq!(cfg.server, "127.0.0.1:9527");
        assert_eq!(cfg.server_host().unwrap(), "127.0.0.1");
        assert_eq!(cfg.server_port().unwrap(), 9527);
        assert_eq!(cfg.tunnels.len(), 1);
        assert_eq!(cfg.tunnels[0].name, "web");
        assert_eq!(cfg.transport.protocol, "tcp"); // default
        // No [auth] block present -> AuthConfig::default() -> auth_type is "token".
        assert_eq!(cfg.auth.auth_type, "token");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn load_errors_on_missing_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("orbien_nonexistent_xyz.toml");
        assert!(ClientConfig::load(&path).is_err());
    }
}
