use super::{ClientConfig, ServerConfig};

pub fn print_config_warnings(warnings: &[String]) {
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
}

fn placeholder(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value.starts_with("your_")
        || value.contains("change_me")
        || value.contains("changeme")
        || matches!(value.as_str(), "password" | "admin")
}

fn secret_warning(out: &mut Vec<String>, path: &str, value: &str) {
    if placeholder(value) {
        out.push(format!("[placeholder-secret] {path} contains an example/default secret"));
    }
}

/// #12: a token shorter than 32 characters is a warning only, not a
/// refusal — it may be a test token, and length alone does not prove
/// weakness. Documented minimum is 32 random bytes.
fn short_token_warning(out: &mut Vec<String>, path: &str, value: &str) {
    let token = value.trim();
    if !token.is_empty() && token.chars().count() < 32 {
        out.push(format!(
            "[short-token] {path} is shorter than 32 characters; use at least 32 random bytes (e.g. `openssl rand -hex 32`)"
        ));
    }
}

impl ServerConfig {
    /// #12: refuse to start with an empty or placeholder token, a
    /// placeholder policy token, or a placeholder dashboard password.
    /// Runtime-only — called from server main after the `--check-config`
    /// early return. `--check-config` stays warn-only so the sample
    /// configs, which contain YOUR_TOKEN, keep passing CI's check set.
    /// An empty policy token stays ignored-with-warning (existing
    /// behaviour) and is not a refusal.
    pub fn refuse_placeholder_secrets(&self) -> Result<(), String> {
        if self.auth.token.trim().is_empty() && self.auth.token_policies.is_empty() {
            return Err(
                "auth has no token or token policies; set auth.token to at least 32 random bytes (e.g. `openssl rand -hex 32`)".into(),
            );
        }
        if placeholder(&self.auth.token) {
            return Err("auth.token contains an example/default secret; set a real token".into());
        }
        for (index, policy) in self.auth.token_policies.iter().enumerate() {
            if policy.token.trim().is_empty() {
                continue;
            }
            if placeholder(&policy.token) {
                return Err(format!(
                    "auth.token_policies[{index}].token contains an example/default secret; set a real token"
                ));
            }
        }
        if self.dashboard.enabled() && !self.dashboard.disable_auth && placeholder(&self.dashboard.password) {
            return Err(
                "dashboard.password contains an example/default secret; set a real password".into(),
            );
        }
        Ok(())
    }

    pub fn risk_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.transport.tls.force {
            out.push("[tls-not-forced] transport.tls.force is false; plaintext is accepted".into());
        }
        if self.transport.tls.trusted_ca_file.trim().is_empty() {
            out.push("[no-client-ca] transport.tls.trustedCaFile is empty; no client certificate verification".into());
        }
        if self.auth.token.trim().is_empty() && self.auth.token_policies.is_empty() {
            out.push("[empty-token] auth has no token or token policies".into());
        }
        secret_warning(&mut out, "auth.token", &self.auth.token);
        short_token_warning(&mut out, "auth.token", &self.auth.token);
        for (index, policy) in self.auth.token_policies.iter().enumerate() {
            let path = format!("auth.token_policies[{index}]");
            secret_warning(&mut out, &format!("{path}.token"), &policy.token);
            short_token_warning(&mut out, &format!("{path}.token"), &policy.token);
            if policy.token.trim().is_empty() {
                out.push(format!("[empty-policy-token] {path}.token is empty; policy is ignored"));
            }
            for (dimension, empty) in [
                ("allowed_tunnels", policy.allowed_tunnels.iter().all(|s| s.trim().is_empty())),
                ("allowed_protocols", policy.allowed_protocols.iter().all(|s| s.trim().is_empty())),
                ("allowed_remote_ports", policy.allowed_remote_ports.iter().all(|p| *p == 0)),
                ("allowed_domains", policy.allowed_domains.iter().all(|s| s.trim().is_empty())),
            ] {
                if empty {
                    out.push(format!("[unrestricted-policy] {path}.{dimension} has no effective restriction"));
                }
            }
        }
        if self.dashboard.enabled() {
            if self.dashboard.disable_auth {
                out.push("[dashboard-no-auth] dashboard.disableAuth is true".into());
            }
            secret_warning(&mut out, "dashboard.password", &self.dashboard.password);
        }
        // #13: idleTimeoutSecs == 0 is a deliberate opt-out, but joined
        // connections then have no idle protection at all.
        if self.limits.idle_timeout_secs == 0 {
            out.push("[no-idle-timeout] limits.idleTimeoutSecs is 0; joined connections have no idle timeout".into());
        }
        out
    }
}

impl ClientConfig {
    pub fn risk_warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        let tls = &self.transport.tls;
        if !tls.enable {
            out.push("[tls-disabled] transport.tls.enable is false; control traffic is plaintext".into());
        } else if tls.trusted_ca_file.trim().is_empty() && tls.tofu_store_file.trim().is_empty() {
            out.push("[no-server-trust] transport.tls has neither trustedCaFile nor tofuStoreFile; server identity is not verified".into());
        }
        if self.auth.token.trim().is_empty() {
            out.push("[empty-token] auth.token is empty".into());
        }
        secret_warning(&mut out, "auth.token", &self.auth.token);
        short_token_warning(&mut out, "auth.token", &self.auth.token);
        for (index, tunnel) in self.tunnels.iter().enumerate() {
            secret_warning(&mut out, &format!("tunnels[{index}].basicAuthPassword"), &tunnel.basic_auth_password);
            if let Some(plugin) = &tunnel.plugin {
                secret_warning(&mut out, &format!("tunnels[{index}].plugin.password"), &plugin.password);
                // #17: a SOCKS5 password shorter than 16 characters warns
                // for one release; a later release will refuse it. SOCKS5
                // user/pass auth is cleartext on the visitor path, so a
                // short password is trivially guessable once observed.
                if plugin.plugin_type.trim().eq_ignore_ascii_case("socks5") {
                    let pass = plugin.password.trim();
                    if !pass.is_empty() && pass.chars().count() < 16 {
                        out.push(format!(
                            "[short-socks5-password] tunnels[{index}].plugin.password is shorter than 16 characters; it will be refused in a future release — generate one with `openssl rand -base64 24`"
                        ));
                    }
                }
            }
        }
        out
    }
}
