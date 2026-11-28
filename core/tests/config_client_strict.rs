use orbien_core::config::{
    ClientConfig, ClientTlsConfig, PluginConfig, PluginRequestHeaders, ServerConfig,
    TransportConfig, TunnelConfig, TunnelTransportConfig,
};
use serde::de::DeserializeOwned;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

fn rejects_unknown<T: DeserializeOwned>(text: &str, key: &str) {
    let error = match toml::from_str::<T>(text) {
        Ok(_) => panic!("accepted unknown key {key}"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(message.contains("unknown field"), "{message}");
    assert!(message.contains(key), "{message}");
}

#[test]
fn client_config_rejects_unknown_fields() {
    rejects_unknown::<ClientConfig>("udpPacketSze = 1500", "udpPacketSze");
}

#[test]
fn client_auth_rejects_unknown_fields() {
    rejects_unknown::<ClientConfig>("[auth]\ntokne = 'test'", "tokne");
    rejects_unknown::<ClientConfig>("[auth]\ntokenPolicies = []", "tokenPolicies");
}

#[test]
fn client_transport_rejects_unknown_fields() {
    rejects_unknown::<TransportConfig>("poolCont = 2", "poolCont");
}

#[test]
fn client_tls_rejects_unknown_fields() {
    rejects_unknown::<ClientTlsConfig>("trusted_ca = 'ca.pem'", "trusted_ca");
}

#[test]
fn tunnel_rejects_unknown_fields() {
    rejects_unknown::<TunnelConfig>(
        "name = 'web'\nprotocol = 'http'\nremotePrt = 9000",
        "remotePrt",
    );
}

#[test]
fn plugin_rejects_unknown_fields() {
    rejects_unknown::<PluginConfig>(
        "type = 'tls-term'\nhostHeaderRewite = 'backend.example'",
        "hostHeaderRewite",
    );
}

#[test]
fn request_headers_reject_unknown_fields_outside_set() {
    rejects_unknown::<PluginRequestHeaders>("seet = {}", "seet");
}

#[test]
fn tunnel_transport_rejects_unknown_fields() {
    rejects_unknown::<TunnelTransportConfig>(
        "bandwidthLimitSid = 'client'",
        "bandwidthLimitSid",
    );
}

#[test]
fn nested_client_tables_reject_unknown_fields() {
    for (text, key) in [
        ("[transport.tls]\ntrusted_ca = 'ca.pem'", "trusted_ca"),
        (
            "[[tunnels]]\nname = 'web'\nprotocol = 'http'\n[tunnels.plugin]\ntype = 'tls-term'\n[tunnels.plugin.requestHeaders]\nseet = {}",
            "seet",
        ),
    ] {
        rejects_unknown::<ClientConfig>(text, key);
    }
}

#[test]
fn auth_and_plugin_type_keep_all_supported_spellings() {
    for key in ["type", "auth_type", "authType"] {
        let text = format!("[auth]\n{key} = 'token'\ntoken = 'test'");
        let cfg: ClientConfig = toml::from_str(&text).unwrap();
        assert_eq!(cfg.auth.auth_type, "token");
        assert_eq!(cfg.auth.token, "test");
    }
    for key in ["type", "plugin_type", "pluginType"] {
        let cfg: PluginConfig = toml::from_str(&format!("{key} = 'tls-term'")).unwrap();
        assert_eq!(cfg.plugin_type, "tls-term");
    }
}

#[test]
fn client_keys_accept_both_styles_without_changing_values() {
    let pairs = [
        ("udpPacketSize", "udp_packet_size"),
        ("poolCount", "pool_count"),
        ("tcpMux", "tcp_mux"),
        ("muxKeepaliveSecs", "mux_keepalive_secs"),
        ("heartbeatInterval", "heartbeat_interval"),
        ("heartbeatTimeout", "heartbeat_timeout"),
        ("maxYamuxStreams", "max_yamux_streams"),
        ("certFile", "cert_file"),
        ("keyFile", "key_file"),
        ("trustedCaFile", "trusted_ca_file"),
        ("serverName", "server_name"),
        ("tofuStoreFile", "tofu_store_file"),
        ("remotePort", "remote_port"),
        ("basicAuthUser", "basic_auth_user"),
        ("basicAuthPassword", "basic_auth_password"),
        ("hostHeaderRewrite", "host_header_rewrite"),
        ("routeByHTTPUser", "route_by_http_user"),
        ("maxConnections", "max_connections"),
        ("udpMaxSessions", "udp_max_sessions"),
        ("bandwidthLimitSide", "bandwidth_limit_side"),
        ("proxyProtocolVersion", "proxy_protocol_version"),
        ("requestHeaders", "request_headers"),
    ];
    let camel = r#"
udpPacketSize = 1400
udpMaxSessions = 48
[auth]
type = 'token'
token = 'test'
[transport]
poolCount = 2
tcpMux = false
muxKeepaliveSecs = 12
heartbeatInterval = 15
heartbeatTimeout = 45
maxYamuxStreams = 64
[transport.tls]
certFile = 'client.crt'
keyFile = 'client.key'
trustedCaFile = 'ca.crt'
serverName = 'control.example'
tofuStoreFile = 'pins.json'
[[tunnels]]
name = 'web'
protocol = 'https'
remotePort = 9000
domains = ['web.example']
basicAuthUser = 'alice'
basicAuthPassword = 'test-password'
hostHeaderRewrite = 'backend.example'
routeByHTTPUser = 'alice'
maxConnections = 3
[tunnels.transport]
bandwidth = 1024.0
bandwidthLimitSide = 'server'
proxyProtocolVersion = 'v2'
[tunnels.plugin]
type = 'tls-term'
service = '127.0.0.1:8080'
certFile = 'app.crt'
keyFile = 'app.key'
hostHeaderRewrite = 'local.example'
[tunnels.plugin.requestHeaders.set]
X-App = 'trusted'
"#;
    let mut snake = camel.to_owned();
    for (from, to) in pairs {
        snake = snake.replace(from, to);
    }
    for text in [camel, snake.as_str()] {
        let mut cfg: ClientConfig = toml::from_str(text).unwrap();
        cfg.complete();
        cfg.validate().unwrap();
        assert_eq!(cfg.udp_packet_size, 1400);
        assert_eq!(cfg.udp_max_sessions, 48);
        assert_eq!(cfg.auth.token, "test");
        let transport = &cfg.transport;
        assert_eq!(transport.pool_count, 2);
        assert!(!transport.tcp_mux);
        assert_eq!(transport.mux_keepalive_secs, 12);
        assert_eq!(transport.heartbeat_interval, 15);
        assert_eq!(transport.heartbeat_timeout, 45);
        assert_eq!(transport.max_yamux_streams, Some(64));
        let tls = &transport.tls;
        assert_eq!(tls.cert_file, "client.crt");
        assert_eq!(tls.key_file, "client.key");
        assert_eq!(tls.trusted_ca_file, "ca.crt");
        assert_eq!(tls.server_name, "control.example");
        assert_eq!(tls.tofu_store_file, "pins.json");
        let tunnel = &cfg.tunnels[0];
        assert_eq!(tunnel.remote_port, 9000);
        assert_eq!(tunnel.basic_auth_user, "alice");
        assert_eq!(tunnel.basic_auth_password, "test-password");
        assert_eq!(tunnel.host_header_rewrite, "backend.example");
        assert_eq!(tunnel.route_by_http_user, "alice");
        assert_eq!(tunnel.max_connections, 3);
        assert_eq!(tunnel.transport.bandwidth, 1024.0);
        assert_eq!(tunnel.transport.bandwidth_limit_side, "server");
        assert_eq!(tunnel.transport.proxy_protocol_version, "v2");
        let plugin = tunnel.plugin.as_ref().unwrap();
        assert_eq!(plugin.cert_file, "app.crt");
        assert_eq!(plugin.key_file, "app.key");
        assert_eq!(plugin.host_header_rewrite, "local.example");
        assert_eq!(plugin.request_headers.set["X-App"], "trusted");
    }
}

#[test]
fn request_header_set_keeps_dynamic_names() {
    for table in ["requestHeaders", "request_headers"] {
        let text = format!(
            "type = 'tls-term'\n[{table}.set]\nX-App = 'trusted'\nx-custom-trace-42 = 'trace'"
        );
        let plugin: PluginConfig = toml::from_str(&text).unwrap();
        assert_eq!(plugin.request_headers.set.len(), 2);
        assert_eq!(plugin.request_headers.set["X-App"], "trusted");
        assert_eq!(plugin.request_headers.set["x-custom-trace-42"], "trace");
    }
}

#[test]
fn duplicate_aliases_are_rejected() {
    for text in [
        "[auth]\ntype = 'token'\nauthType = 'token'",
        "[auth]\nauth_type = 'token'\nauthType = 'token'",
        "[[tunnels]]\nname = 'web'\nprotocol = 'http'\nremotePort = 9000\nremote_port = 9001",
        "[[tunnels]]\nname = 'web'\nprotocol = 'http'\n[tunnels.plugin]\nplugin_type = 'tls-term'\npluginType = 'tls-term'",
        "[[tunnels]]\nname = 'web'\nprotocol = 'http'\n[tunnels.plugin]\ntype = 'tls-term'\nrequestHeaders = {}\nrequest_headers = {}",
    ] {
        assert!(toml::from_str::<ClientConfig>(text).is_err(), "{text}");
    }
}

struct ConfigFile(PathBuf);

impl ConfigFile {
    fn new(text: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = loop {
            let path = std::env::temp_dir().join(format!(
                "orbien-config-strict-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create test directory: {error}"),
            }
        };
        let path = dir.join("orbien.toml");
        std::fs::write(&path, text).unwrap();
        Self(path)
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        if let Some(parent) = self.0.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }
}

#[test]
fn runtime_and_edit_loaders_reject_unknown_keys() {
    let file = ConfigFile::new("[transport.tls]\ntrusted_ca = 'ca.pem'");
    for result in [
        ClientConfig::load(&file.0),
        ClientConfig::load_for_edit(&file.0),
    ] {
        let error = result.unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("trusted_ca"), "{message}");
        assert!(message.contains("unknown field"), "{message}");
    }
}

#[test]
fn runtime_and_edit_loaders_keep_valid_minimal_config() {
    let file = ConfigFile::new("[auth]\nauthType = 'token'\ntoken = 'test'");
    for result in [
        ClientConfig::load(&file.0),
        ClientConfig::load_for_edit(&file.0),
    ] {
        let cfg = result.unwrap();
        assert_eq!(cfg.auth.auth_type, "token");
        assert_eq!(cfg.auth.token, "test");
        assert!(cfg.tunnels.is_empty());
        assert!(cfg.transport.tls.enable);
    }
}

fn enabled_docker_dashboard() -> String {
    let source = include_str!("../../docker/conf/orbien-server.toml");
    let mut found = false;
    let mut lines = Vec::new();
    for line in source.lines() {
        if line == "#[dashboard]" {
            found = true;
        }
        lines.push(if found {
            line.strip_prefix('#').unwrap_or(line)
        } else {
            line
        });
    }
    assert!(
        found,
        "Docker sample must contain a commented [dashboard] block"
    );
    lines.join("\n")
}

#[test]
fn docker_server_sample_parses_as_shipped() {
    let source = include_str!("../../docker/conf/orbien-server.toml");
    let mut cfg: ServerConfig = toml::from_str(source).unwrap();
    cfg.complete();
    cfg.validate().unwrap();
    assert!(!cfg.dashboard.enabled());
}

#[test]
fn docker_dashboard_block_parses_when_enabled() {
    let mut cfg: ServerConfig = toml::from_str(&enabled_docker_dashboard()).unwrap();
    cfg.complete();
    cfg.validate().unwrap();
    assert!(cfg.dashboard.enabled());
    assert_eq!(cfg.dashboard.port, 8020);
    assert_eq!(cfg.dashboard.user, "YOUR_USERNAME");
    assert_eq!(cfg.dashboard.password, "YOUR_PASSWORD");
}

#[test]
fn legacy_web_server_table_is_rejected() {
    let text = enabled_docker_dashboard().replace("[dashboard]", "[webServer]");
    rejects_unknown::<ServerConfig>(&text, "webServer");
}
