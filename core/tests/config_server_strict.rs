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
