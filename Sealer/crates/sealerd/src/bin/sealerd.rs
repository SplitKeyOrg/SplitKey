//! The daemon binary: `sealerd --config /etc/splitkey/sealer.toml`

use anyhow::Result;
use clap::Parser;
use sealerd::{config::Config, pipeline};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sealerd", version, about = "SplitKey Sealer daemon")]
struct Args {
    #[arg(long, env = "SEALER_CONFIG", default_value = "/etc/splitkey/sealer.toml")]
    config: PathBuf,
    /// Validate config and exit.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = Config::load(&args.config)?;

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cfg.log.level.clone().into()),
        )
        .init();

    if args.check {
        println!("config OK: {}", args.config.display());
        return Ok(());
    }

    let (tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutdown signal received");
        let _ = tx.send(true);
    });

    pipeline::run(cfg, rx).await
}
