//! #12: persist the server's auto-generated TLS certificate.
//!
//! Without `certFile`/`keyFile` the server used to generate an ephemeral
//! self-signed certificate on every start, which broke whole-certificate
//! pinning (TOFU) on every restart: the fingerprint changed, so pinned
//! clients refused to connect until re-pinned. Now the generated pair is
//! saved next to the server config file and reloaded on restart, so the
//! fingerprint stays stable until the files are deleted.
//!
//! Only when the server was started with `-c <config>` (config file
//! known); otherwise — tests, `ServerConfig::default()` — the old
//! ephemeral behaviour stays, so `Service::new` has no filesystem side
//! effects there. `--check-config` never calls this (it is runtime
//! only, inside `Service::new`).

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use orbien_core::config::ServerConfig;
use orbien_core::transport::{generate_self_signed_cert, load_pem_cert_key};
use std::fs;
use std::path::{Path, PathBuf};

/// Suffixes for the generated pair, next to the server config file:
/// `<config-stem>.generated-cert.pem` / `.generated-key.pem`.
pub const GENERATED_CERT_SUFFIX: &str = ".generated-cert.pem";
pub const GENERATED_KEY_SUFFIX: &str = ".generated-key.pem";

/// Resolve the server TLS certificate before the TLS config is built.
/// When no `certFile`/`keyFile` is configured and the server was started
/// with a config file, load a previously generated pair from next to
/// that file, or generate and persist one. Never overwrites an existing
/// valid pair. Returns `Ok(())` when nothing had to be done (explicit
/// cert configured, or no config file).
pub fn resolve_generated_cert(cfg: &mut ServerConfig) -> Result<()> {
    let tls = &cfg.transport.tls;
    if !tls.cert_file.trim().is_empty() || !tls.key_file.trim().is_empty() {
        return Ok(()); // explicit cert configured (even one-sided)
    }
    let Some(config_file) = cfg.dashboard.config_file.clone() else {
        tracing::info!(
            "transport.tls: no certFile/keyFile and no config file — generating ephemeral self-signed cert (pinning will not survive restarts)"
        );
        return Ok(());
    };
    // Canonicalize so `..` in the `-c` path cannot reach
    // `load_pem_cert_key`'s path-traversal rejection on restart.
    let config_path = Path::new(&config_file)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(&config_file));
    let stem = config_path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "orbien-server".to_string());
    let dir = config_path
        .parent()
        .map(|d| d.to_path_buf())
        .unwrap_or_default();
    let cert_path = dir.join(format!("{stem}{GENERATED_CERT_SUFFIX}"));
    let key_path = dir.join(format!("{stem}{GENERATED_KEY_SUFFIX}"));
    if cert_path.exists() && key_path.exists() {
        // Both present: they must parse, or fail loudly — never silently
        // overwrite a pair the operator may rely on.
        load_pem_cert_key(
            &cert_path.to_string_lossy(),
            &key_path.to_string_lossy(),
        )
        .with_context(|| {
            format!(
                "generated certificate pair {} / {} exists but does not parse; delete both files to regenerate",
                cert_path.display(),
                key_path.display()
            )
        })?;
        tracing::info!(
            "transport.tls: loaded persisted generated certificate {} (fingerprint stable across restarts)",
            cert_path.display()
        );
    } else {
        if cert_path.exists() || key_path.exists() {
            tracing::warn!(
                "transport.tls: only one half of the generated certificate pair exists; regenerating both"
            );
        }
        let gen = generate_self_signed_cert("orbien-server")?;
        let cert_pem = pem_encode("CERTIFICATE", gen.certs[0].as_ref());
        let key_pem = pem_encode("PRIVATE KEY", gen.key.secret_pkcs8_der());
        write_owner_only(&key_path, key_pem.as_bytes())?;
        fs::write(&cert_path, cert_pem.as_bytes())
            .with_context(|| format!("write generated certificate {}", cert_path.display()))?;
        tracing::info!(
            "transport.tls: generated self-signed certificate and saved it to {} / {} (kept across restarts; delete both files to regenerate)",
            cert_path.display(),
            key_path.display()
        );
    }
    cfg.transport.tls.cert_file = cert_path.to_string_lossy().into_owned();
    cfg.transport.tls.key_file = key_path.to_string_lossy().into_owned();
    Ok(())
}

/// Encode DER bytes as PEM text with 64-column wrapping.
fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = B64.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Write a file with owner-only permissions (0600 on Unix), mirroring
/// the session-secret pattern in the client. The generated private key
/// must not be world-readable. On Windows this is a plain write — a
/// documented limitation (#12).
fn write_owner_only(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn test_cfg(config_file: &Path) -> ServerConfig {
        let mut cfg = ServerConfig::default();
        cfg.dashboard.config_file = Some(config_file.to_string_lossy().into_owned());
        cfg
    }

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orbien-12-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Canonicalize: resolve_generated_cert canonicalizes the config
        // path, and on Windows that changes the spelling (\\?\ prefix,
        // 8.3 names expanded) — compare canonical with canonical.
        fs::canonicalize(&dir).unwrap_or(dir)
    }

    #[test]
    fn generates_once_then_reloads_the_same_pair() {
        let dir = tmpdir("gen-cert");
        let config_file = dir.join("server.toml");
        fs::write(&config_file, "listen = \"127.0.0.1:9527\"\n").unwrap();

        let mut cfg = test_cfg(&config_file);
        resolve_generated_cert(&mut cfg).unwrap();
        let cert_path = dir.join("server.generated-cert.pem");
        let key_path = dir.join("server.generated-key.pem");
        assert_eq!(cfg.transport.tls.cert_file, cert_path.to_string_lossy());
        assert_eq!(cfg.transport.tls.key_file, key_path.to_string_lossy());
        let first_cert = fs::read(&cert_path).unwrap();
        let first_key = fs::read(&key_path).unwrap();
        assert!(!first_cert.is_empty() && !first_key.is_empty());
        // Key is owner-only on Unix.
        #[cfg(unix)]
        assert_eq!(fs::metadata(&key_path).unwrap().permissions().mode() & 0o777, 0o600);

        // A fresh config (restart) reloads the same pair, not a new one.
        let mut cfg2 = test_cfg(&config_file);
        resolve_generated_cert(&mut cfg2).unwrap();
        assert_eq!(fs::read(&cert_path).unwrap(), first_cert);
        assert_eq!(fs::read(&key_path).unwrap(), first_key);
        assert_eq!(cfg2.transport.tls.cert_file, cfg.transport.tls.cert_file);

        // An invalid existing pair fails loudly instead of overwriting.
        fs::write(&cert_path, "not a certificate").unwrap();
        let mut cfg3 = test_cfg(&config_file);
        assert!(resolve_generated_cert(&mut cfg3).is_err());
        assert_eq!(fs::read(&cert_path).unwrap(), b"not a certificate");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_config_file_stays_ephemeral() {
        let mut cfg = ServerConfig::default();
        assert!(cfg.dashboard.config_file.is_none());
        resolve_generated_cert(&mut cfg).unwrap();
        assert!(cfg.transport.tls.cert_file.is_empty());
        assert!(cfg.transport.tls.key_file.is_empty());
    }
}
