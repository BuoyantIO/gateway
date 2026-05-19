use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(version, about = "TCP gateway daemon")]
struct Args {
    /// Path to a YAML configuration file.
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let yaml = std::fs::read_to_string(&args.config)?;
    let cfg = gateway_config::parse_yaml(&yaml)?;
    if let Err(rejections) = gateway_config::validate(&cfg) {
        for r in &rejections {
            tracing::error!(rejection = %r, "config validation failed");
        }
        anyhow::bail!(
            "config rejected by validation ({} rejections)",
            rejections.len()
        );
    }

    let store = gateway_state::Store::new();
    let report = store.apply(&cfg);
    for skipped in &report.skipped {
        tracing::warn!(entry = %skipped, "config entry skipped");
    }
    tracing::info!(applied = report.applied, "config applied");

    let gateway = gateway_runtime::Gateway::new(store);
    gateway
        .run(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("ctrl-c received; shutting down");
        })
        .await?;

    Ok(())
}
