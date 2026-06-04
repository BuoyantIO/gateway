use std::path::PathBuf;

use clap::Parser;
use tokio::sync::watch;

#[derive(Parser)]
#[command(version, about = "HTTP gateway daemon")]
struct Args {
    /// YAML config file. Mutually exclusive with --control-plane.
    #[arg(short, long, conflicts_with = "control_plane")]
    config: Option<PathBuf>,

    /// gRPC endpoint of the control plane. Requires --client-id.
    #[arg(long, requires = "client_id", conflicts_with = "config")]
    control_plane: Option<String>,

    /// K8s Gateway this DP serves: "{namespace}/{gateway-name}".
    /// Required with --control-plane.
    #[arg(long)]
    client_id: Option<String>,
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
    if args.config.is_none() && args.control_plane.is_none() {
        anyhow::bail!("either --config or --control-plane must be set");
    }

    let store = gateway_state::Store::new();

    if let Some(path) = &args.config {
        load_yaml_into_store(path, &store)?;
    }

    // Shared shutdown flag. ctrl-c flips it; both the CP client task
    // (if any) and the gateway run loop wait on it.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("ctrl-c received; shutting down");
        let _ = signal_tx.send(true);
    });

    let cp_handle = if let Some(cp_url) = args.control_plane {
        let client_id = args.client_id.expect("required by clap");
        let endpoint = tonic::transport::Endpoint::try_from(cp_url)
            .map_err(|e| anyhow::anyhow!("invalid --control-plane URL: {e}"))?;
        let store_clone = store.clone();
        let mut rx = shutdown_rx.clone();
        tracing::info!(?endpoint, client_id, "connecting to control plane");
        Some(tokio::spawn(async move {
            if let Err(e) = gateway_cp_client::run(endpoint, client_id, store_clone, async move {
                let _ = rx.wait_for(|v| *v).await;
            })
            .await
            {
                tracing::error!(error = %e, "control-plane client exited with error");
            }
        }))
    } else {
        None
    };

    let gateway = gateway_runtime::Gateway::new(store);
    let mut rx = shutdown_rx;
    gateway
        .run(async move {
            let _ = rx.wait_for(|v| *v).await;
        })
        .await?;

    if let Some(handle) = cp_handle {
        let _ = handle.await;
    }

    Ok(())
}

fn load_yaml_into_store(
    path: &std::path::Path,
    store: &gateway_state::Store,
) -> anyhow::Result<()> {
    let yaml = std::fs::read_to_string(path)?;
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
    let report = store.apply(&cfg);
    for skipped in &report.skipped {
        tracing::warn!(entry = %skipped, "config entry skipped");
    }
    tracing::info!(applied = report.applied, "config applied");
    Ok(())
}
