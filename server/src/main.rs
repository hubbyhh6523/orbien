mod accept;
mod access;
mod control;
mod dashboard;
mod metrics;
mod sanitize;
mod service;
mod tunnel;

use anyhow::Result;
use clap::Parser;
use orbien_core::config::ServerConfig;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "orbien-server",
    about = "orbien server — TCP tunnel",
    after_help = "Example:\n  orbien-server -c conf/orbien-server.toml"
)]
struct Args {
    #[arg(short, long, value_name = "FILE")]
    config: Option<String>,

    /// Check a file offline, without starting the runtime or any listeners.
    #[arg(long, requires = "config")]
    check_config: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args = Args::parse();
    if args.check_config
        && args.config.as_deref().is_none_or(|path| path.trim().is_empty())
    {
        anyhow::bail!("--check-config requires a non-empty -c/--config path");
    }
    let cfg = load_server_config(&args)?;
    if args.check_config {
        service::Service::check_config(&cfg)?;
        orbien_core::config::print_config_warnings(&cfg.risk_warnings());
        println!("configuration OK");
        return Ok(());
    }
    // #12: refuse to start on an empty or placeholder token, a
    // placeholder policy token, or a placeholder dashboard password.
    // --check-config above stays warn-only for the sample configs.
    if let Err(e) = cfg.refuse_placeholder_secrets() {
        anyhow::bail!("refusing to start: {e}");
    }
    orbien_core::config::print_config_warnings(&cfg.risk_warnings());

    tracing::info!(
        listen = %cfg.listen,
        quic_port = cfg.quic_port,
        kcp_port = cfg.kcp_port,
        http_gw = cfg.http_gw_port,
        https_gw = cfg.https_gw_port,
        "starting orbien-server"
    );

    tokio::runtime::Runtime::new()?.block_on(async move {
        service::Service::new(cfg)?.run().await
    })
}

fn load_server_config(args: &Args) -> Result<ServerConfig> {
    if let Some(path) = args
        .config
        .as_deref()
        .map(str::trim)
        .filter(|p| !p.is_empty())
    {
        tracing::info!(config = %path, "loading config");
        let mut cfg = ServerConfig::load(path)?;
        // Inject the resolved path so that POST /api/v1/config/reload can
        // re-read the file without the caller supplying it every time.
        cfg.dashboard.config_file = Some(path.to_string());
        return Ok(cfg);
    }

    tracing::info!("using built-in defaults");
    let mut cfg = ServerConfig::default();
    cfg.complete();
    cfg.validate()?;
    Ok(cfg)
}
