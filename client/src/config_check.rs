use anyhow::{Context, Result};
use orbien_core::config::ClientConfig;

/// Construct only offline startup resources. Neither constructor starts a
/// task, resolves an address, opens a socket, or writes a TOFU fingerprint.
pub fn check_config(cfg: &ClientConfig) -> Result<()> {
    cfg.validate()?;
    crate::connector::check_tls_config(cfg).context("transport.tls preflight")?;
    let _ = crate::tunnel::TunnelManager::from_config(cfg).context("tunnels/plugins preflight")?;
    Ok(())
}
