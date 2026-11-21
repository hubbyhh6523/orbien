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

impl ServerConfig {
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
        for (index, policy) in self.auth.token_policies.iter().enumerate() {
            let path = format!("auth.token_policies[{index}]");
            secret_warning(&mut out, &format!("{path}.token"), &policy.token);
            if policy.token.trim().is_empty() {
                out.push(format!("[empty-policy-token] {path}.token is empty; policy is ignored"));
            }
            for (dimension, empty) in [
                ("allowed_tunnels", policy.allowed_tunnels.iter().all(|s| s.trim().is_empty())),
                ("allowed_protocols", policy.allowed_protocols.iter().all(|s| s.trim().is_empty())),
                ("allowed_remote_ports", policy.allowed_remote_ports.iter().all(|p| *p == 0)),
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
        for (index, tunnel) in self.tunnels.iter().enumerate() {
            secret_warning(&mut out, &format!("tunnels[{index}].basicAuthPassword"), &tunnel.basic_auth_password);
            if let Some(plugin) = &tunnel.plugin {
                secret_warning(&mut out, &format!("tunnels[{index}].plugin.password"), &plugin.password);
            }
        }
        out
    }
}
