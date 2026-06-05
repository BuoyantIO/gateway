//! Control-plane daemon. Connects to the K8s API, runs the watch
//! loop, and serves the `ConfigStream` gRPC service to data planes.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use gateway_cp::{ConfigStreamService, ServerState, run_watch};
use gateway_cp_proto::v1::config_stream_server::ConfigStreamServer;
use tokio::sync::watch;
use tonic::transport::Server;

#[derive(Parser)]
#[command(version, about = "Gateway control plane")]
struct Args {
    /// gRPC listen address for connecting data planes.
    #[arg(long, default_value = "0.0.0.0:8443")]
    listen: SocketAddr,

    /// Controller name we claim. Gateways referencing a
    /// `GatewayClass` with this `spec.controllerName` are considered
    /// ours.
    #[arg(long, default_value = "gateway.buoyant.io/controller")]
    controller_name: String,
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
    let client = kube::Client::try_default().await?;
    let state = Arc::new(ServerState::new());

    // Single shutdown channel; ctrl-c flips it and both the watch
    // loop and the gRPC server drain off the same signal.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("ctrl-c received; shutting down");
        let _ = signal_tx.send(true);
    });

    let watch_handle = {
        let state = state.clone();
        let controller_name = args.controller_name.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let shutdown = async move {
                let _ = rx.wait_for(|v| *v).await;
            };
            if let Err(e) = run_watch(client, controller_name, state, shutdown).await {
                tracing::error!(error = %e, "watch loop exited with error");
            }
        })
    };

    let service = ConfigStreamServer::new(ConfigStreamService::new(state));
    let server_shutdown = {
        let mut rx = shutdown_rx;
        async move {
            let _ = rx.wait_for(|v| *v).await;
        }
    };

    tracing::info!(listen = %args.listen, controller = %args.controller_name, "control plane listening");
    Server::builder()
        .add_service(service)
        .serve_with_shutdown(args.listen, server_shutdown)
        .await?;

    let _ = watch_handle.await;
    Ok(())
}
