use orbien_core::config::{
    DashboardConfig, QuicOptions, ServerConfig, ServerTlsConfig, ServerTransportConfig,
};
use serde::de::DeserializeOwned;

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
fn server_config_rejects_unknown_fields() {
    rejects_unknown::<ServerConfig>("httpsGwport = 443", "httpsGwport");
}

#[test]
fn token_policy_rejects_unknown_fields() {
    rejects_unknown::<ServerConfig>(
        "[[auth.token_policies]]\ntoken = 'test'\nallowed_remote_port = [9000]",
        "allowed_remote_port",
    );
}

#[test]
fn auth_config_rejects_unknown_fields() {
    rejects_unknown::<ServerConfig>("[auth]\ntokne = 'test'", "tokne");
}

#[test]
fn server_transport_rejects_unknown_fields() {
    rejects_unknown::<ServerTransportConfig>("tcpMxu = true", "tcpMxu");
}

#[test]
fn dashboard_rejects_unknown_fields() {
    rejects_unknown::<DashboardConfig>("disableAth = true", "disableAth");
    rejects_unknown::<DashboardConfig>("config_file = 'other.toml'", "config_file");
}

#[test]
fn server_tls_rejects_unknown_fields() {
    rejects_unknown::<ServerTlsConfig>("trusted_ca = 'ca.pem'", "trusted_ca");
}

#[test]
fn shared_quic_rejects_unknown_fields() {
    rejects_unknown::<QuicOptions>("maxIdleTimout = 30", "maxIdleTimout");
}

#[test]
fn nested_unknown_fields_are_rejected() {
    rejects_unknown::<ServerConfig>(
        "[transport.tls]\ntrusted_ca = 'ca.pem'",
        "trusted_ca",
    );
    rejects_unknown::<ServerConfig>(
        "[[auth.token_policies]]\ntoken = 'test'\nallowed_remote_port = [9000]",
        "allowed_remote_port",
    );
    rejects_unknown::<ServerConfig>("[webServer]\nport = 8020", "webServer");
}

#[test]
fn token_policy_accepts_both_key_styles() {
    for (table, tunnels, protocols, ports) in [
        (
            "token_policies",
            "allowed_tunnels",
            "allowed_protocols",
            "allowed_remote_ports",
        ),
        (
            "tokenPolicies",
            "allowedTunnels",
            "allowedProtocols",
            "allowedRemotePorts",
        ),
    ] {
        let text = format!(
            "[[auth.{table}]]\ntoken = 'test'\n{tunnels} = ['web']\n\
             {protocols} = ['http']\n{ports} = [9000]"
        );
        let cfg: ServerConfig = toml::from_str(&text).unwrap();
        let policy = &cfg.auth.token_policies[0];
        assert_eq!(policy.token, "test");
        assert_eq!(policy.allowed_tunnels, vec!["web".to_owned()]);
        assert_eq!(policy.allowed_protocols, vec!["http".to_owned()]);
        assert_eq!(policy.allowed_remote_ports, vec![9000]);
    }
}

#[test]
fn token_policy_allowed_domains_alias() {
    for key in ["allowed_domains", "allowedDomains"] {
        let text = format!(
            "[[auth.token_policies]]\ntoken = 'test'\n{key} = ['example.com', '*.example.org']"
        );
        let cfg: ServerConfig = toml::from_str(&text).unwrap();
        assert_eq!(
            cfg.auth.token_policies[0].allowed_domains,
            vec!["example.com".to_owned(), "*.example.org".to_owned()]
        );
    }
}

#[test]
fn duplicate_policy_aliases_are_rejected() {
    assert!(toml::from_str::<ServerConfig>(
        "[auth]\ntoken_policies = []\ntokenPolicies = []"
    )
    .is_err());
    assert!(toml::from_str::<ServerConfig>(
        "[[auth.token_policies]]\ntoken = 'test'\nallowed_tunnels = []\nallowedTunnels = []"
    )
    .is_err());
}

#[test]
fn minimal_config_keeps_existing_defaults() {
    let mut cfg: ServerConfig = toml::from_str("").unwrap();
    cfg.complete();
    cfg.validate().unwrap();
    assert_eq!(cfg.listen, "0.0.0.0:9527");
    assert!(!cfg.transport.tls.force);
    assert!(cfg.auth.token_policies.is_empty());
}

#[test]
fn limits_rejects_unknown_fields() {
    rejects_unknown::<ServerConfig>("[limits]\npreLoginTimeoutSec = 10", "preLoginTimeoutSec");
}

#[test]
fn limits_defaults_are_the_approved_values() {
    let cfg: ServerConfig = toml::from_str("").unwrap();
    let l = &cfg.limits;
    assert_eq!(l.pre_login_timeout_secs, 10);
    assert_eq!(l.idle_timeout_secs, 3600);
    assert_eq!(l.first_message_max_bytes, 4096);
    assert_eq!(l.pre_login_max_conns, 512);
    assert_eq!(l.pre_login_max_conns_per_ip, 32);
    assert_eq!(l.max_waiting_visitors_per_tunnel, 32);
    assert_eq!(l.max_outstanding_data_conns, 8);
    assert_eq!(l.pool_idle_ttl_secs, 300);
    assert_eq!(l.max_udp_visitors_per_tunnel, 1024);
    assert_eq!(l.udp_packets_per_sec_per_source, 1000);
    assert_eq!(l.udp_packets_per_sec_per_tunnel, 10_000);
}

#[test]
fn limits_aliases_parse() {
    for (key, want) in [
        ("preLoginTimeoutSecs", 5u64),
        ("pre_login_timeout_secs", 5u64),
    ] {
        let cfg: ServerConfig =
            toml::from_str(&format!("[limits]\n{key} = 5")).unwrap();
        assert_eq!(cfg.limits.pre_login_timeout_secs, want);
    }
    let cfg: ServerConfig =
        toml::from_str("[limits]\nidleTimeoutSecs = 0").unwrap();
    assert_eq!(cfg.limits.idle_timeout_secs, 0);
    // idleTimeoutSecs == 0 is the one allowed opt-out.
    let mut cfg2 = cfg.clone();
    cfg2.complete();
    cfg2.validate().unwrap();
    assert!(cfg2
        .risk_warnings()
        .iter()
        .any(|w| w.contains("[no-idle-timeout]")));
}

#[test]
fn limits_zero_cap_fails_validation() {
    let mut cfg: ServerConfig = toml::from_str("[limits]\npreLoginMaxConns = 0").unwrap();
    cfg.complete();
    let err = cfg.validate().unwrap_err();
    assert!(err.to_string().contains("limits.preLoginMaxConns must be > 0"), "{err}");
}

#[test]
fn limits_udp_aliases_parse_and_zero_visitor_cap_fails_validation() {
    for (key, want) in [
        ("maxUdpVisitorsPerTunnel", 7usize),
        ("max_udp_visitors_per_tunnel", 7usize),
    ] {
        let cfg: ServerConfig =
            toml::from_str(&format!("[limits]\n{key} = 7")).unwrap();
        assert_eq!(cfg.limits.max_udp_visitors_per_tunnel, want);
    }
    let cfg: ServerConfig =
        toml::from_str("[limits]\nudpPacketsPerSecPerSource = 0").unwrap();
    assert_eq!(cfg.limits.udp_packets_per_sec_per_source, 0);
    let mut cfg2: ServerConfig =
        toml::from_str("[limits]\nmaxUdpVisitorsPerTunnel = 0").unwrap();
    cfg2.complete();
    let err = cfg2.validate().unwrap_err();
    assert!(err.to_string().contains("limits.maxUdpVisitorsPerTunnel must be > 0"), "{err}");
}

#[test]
fn quic_window_aliases_parse_and_zero_fails_validation() {
    let cfg: ServerConfig =
        toml::from_str("[transport.quic]\nstream_recv_window = 1048576").unwrap();
    assert_eq!(cfg.transport.quic.stream_recv_window, 1_048_576);
    let mut cfg2: ServerConfig =
        toml::from_str("[transport.quic]\nstreamRecvWindow = 0").unwrap();
    cfg2.complete();
    let err = cfg2.validate().unwrap_err();
    assert!(
        err.to_string().contains("transport.quic.streamRecvWindow must be > 0"),
        "{err}"
    );
}

#[test]
fn quic_defaults_are_the_approved_values() {
    // #13: lowered from 100_000 streams / 32+64+64 MiB windows.
    let cfg: ServerConfig = toml::from_str("").unwrap();
    let q = &cfg.transport.quic;
    assert_eq!(q.max_incoming_streams, 1_000);
    assert_eq!(q.stream_recv_window, 1_048_576);
    assert_eq!(q.conn_recv_window, 8_388_608);
    assert_eq!(q.send_window, 8_388_608);
}

#[test]
fn quic_old_values_still_overridable() {
    let cfg: ServerConfig = toml::from_str(
        "[transport.quic]\nmaxIncomingStreams = 100000\nstreamRecvWindow = 33554432\nconnRecvWindow = 67108864\nsendWindow = 67108864",
    )
    .unwrap();
    let q = &cfg.transport.quic;
    assert_eq!(q.max_incoming_streams, 100_000);
    assert_eq!(q.stream_recv_window, 33_554_432);
    assert_eq!(q.conn_recv_window, 67_108_864);
    assert_eq!(q.send_window, 67_108_864);
}
