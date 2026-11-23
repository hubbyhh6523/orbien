use orbien_core::config::{ClientConfig, ServerConfig};

#[test]
fn server_warnings_cover_effective_policy_dimensions_without_leaking_secrets() {
    let mut cfg: ServerConfig = toml::from_str(r#"
[auth]
token = 'YOUR_PRIVATE_TOKEN'
[[auth.token_policies]]
token = 'YOUR_OTHER_PRIVATE_TOKEN'
allowed_tunnels = [' ']
allowed_protocols = []
allowed_remote_ports = [0]
[dashboard]
port = 8020
user = 'admin'
password = 'CHANGE_ME_NOT_FOR_LOGS'
"#).unwrap();
    cfg.complete();
    cfg.validate().unwrap();
    let warnings = cfg.risk_warnings().join("\n");
    for expected in ["tls-not-forced", "no-client-ca", "allowed_tunnels", "allowed_protocols", "allowed_remote_ports", "dashboard.password", "placeholder-secret"] {
        assert!(warnings.contains(expected), "{warnings}");
    }
    for secret in ["YOUR_PRIVATE_TOKEN", "YOUR_OTHER_PRIVATE_TOKEN", "CHANGE_ME_NOT_FOR_LOGS"] {
        assert!(!warnings.contains(secret));
    }
}

#[test]
fn placeholder_secrets_refuse_startup_but_only_warn_on_check_config() {
    // --check-config stays warn-only: risk_warnings reports the
    // placeholder, but only the runtime refusal rejects it.
    let mut cfg: ServerConfig = toml::from_str("[auth]\ntoken = 'YOUR_TOKEN'").unwrap();
    cfg.complete();
    assert!(cfg.risk_warnings().join("\n").contains("placeholder-secret"));
    assert!(cfg.refuse_placeholder_secrets().is_err());
    // Empty token with no policies is refused too.
    assert!(ServerConfig::default().refuse_placeholder_secrets().is_err());
    // A real token passes; a short one only warns.
    let mut ok: ServerConfig =
        toml::from_str("[auth]\ntoken = 'a-very-long-real-token-that-is-long-enough-1234'").unwrap();
    ok.complete();
    assert!(ok.refuse_placeholder_secrets().is_ok());
    assert!(!ok.risk_warnings().join("\n").contains("short-token"));
    let mut short: ServerConfig = toml::from_str("[auth]\ntoken = 'short-token'").unwrap();
    short.complete();
    assert!(short.risk_warnings().join("\n").contains("short-token"));
    assert!(short.refuse_placeholder_secrets().is_ok());
    // Placeholder dashboard password is refused when the dashboard is
    // on and auth is enabled.
    let mut dash: ServerConfig = toml::from_str(
        "[auth]\ntoken = 'a-very-long-real-token-that-is-long-enough-1234'\n[dashboard]\nport = 8020\nuser = 'admin'\npassword = 'CHANGE_ME'",
    )
    .unwrap();
    dash.complete();
    assert!(dash.refuse_placeholder_secrets().is_err());
}

#[test]
fn completed_mtls_config_does_not_warn_that_tls_is_optional() {
    let mut cfg: ServerConfig = toml::from_str("[transport.tls]\ntrustedCaFile = 'ca.pem'").unwrap();
    cfg.complete();
    assert!(cfg.transport.tls.force);
    let warnings = cfg.risk_warnings().join("\n");
    assert!(!warnings.contains("tls-not-forced"));
    assert!(!warnings.contains("no-client-ca"));
}

#[test]
fn client_tls_disabled_ca_and_tofu_modes_are_distinct() {
    let mut cfg: ClientConfig = toml::from_str("[auth]\ntoken = 'YOUR_PRIVATE_TOKEN'").unwrap();
    cfg.complete();
    let warnings = cfg.risk_warnings().join("\n");
    assert!(warnings.contains("no-server-trust"));
    assert!(warnings.contains("placeholder-secret"));
    assert!(!warnings.contains("YOUR_PRIVATE_TOKEN"));
    cfg.transport.tls.tofu_store_file = "pins.txt".into();
    assert!(!cfg.risk_warnings().join("\n").contains("no-server-trust"));
    cfg.transport.tls.tofu_store_file.clear();
    cfg.transport.tls.trusted_ca_file = "ca.pem".into();
    assert!(!cfg.risk_warnings().join("\n").contains("no-server-trust"));
    cfg.transport.tls.enable = false;
    let warnings = cfg.risk_warnings().join("\n");
    assert!(warnings.contains("tls-disabled"));
    assert!(!warnings.contains("no-server-trust"));
}
