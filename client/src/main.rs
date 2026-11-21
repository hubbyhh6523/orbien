use anyhow::Result;
use clap::Parser;
use orbien_client::ClientHandle;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "orbien",
    about = "orbien client",
    after_help = "Config:\n  \
        orbien                         # try ./orbien.toml, then ./conf/orbien.toml\n  \
        orbien -c conf/orbien.toml     # explicit path"
)]
struct Args {
    #[arg(short, long, value_name = "FILE")]
    config: Option<String>,

    /// Check offline; do not start a runtime, resolve DNS, or contact peers.
    #[arg(long)]
    check_config: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let args = Args::parse();
    let config_path = orbien_client::resolve_client_config_path(args.config.as_deref())?;
    tracing::info!(config = %config_path.display(), "loading config");

    let cfg = orbien_client::ClientConfig::load(&config_path)?;
    orbien_client::check_config(&cfg)?;
    orbien_core::config::print_config_warnings(&cfg.risk_warnings());
    if args.check_config {
        println!("configuration OK");
        return Ok(());
    }
    tracing::info!(
        server = %cfg.server_endpoint(),
        protocol = %cfg.transport.protocol,
        tunnels = cfg.tunnels.len(),
        "starting orbien"
    );

    tokio::runtime::Runtime::new()?
        .block_on(ClientHandle::new().run_foreground(cfg, config_path))
}
