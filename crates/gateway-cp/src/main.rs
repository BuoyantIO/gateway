//! Control-plane daemon. Connects to the K8s API, runs the watch
//! loop, and serves the `ConfigStream` gRPC service to data planes.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use gateway_cp::infra::{InfraConfig, InfraPublisher, writer as infra_writer};
use gateway_cp::status::{StatusWork, writer as status_writer};
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

    /// gatewayd image for provisioned data planes. Data-plane
    /// provisioning is active only when this and --cp-url are both
    /// set.
    #[arg(long, requires = "cp_url")]
    dp_image: Option<String>,

    /// Control-plane gRPC URL provisioned data planes dial (e.g.
    /// `http://gateway-cp.gateway-system.svc:8443`).
    #[arg(long, requires = "dp_image")]
    cp_url: Option<String>,

    /// Admin (readiness) port on provisioned data planes.
    #[arg(long, default_value_t = 15021)]
    dp_admin_port: u16,
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

    // Data-plane provisioning: the watch loop publishes desired
    // infra into a channel and the writer task owns the apiserver
    // writes. Inactive unless both flags are set.
    let (infra_publisher, writer_handle) =
        if let (Some(dp_image), Some(cp_url)) = (args.dp_image, args.cp_url) {
            let config = InfraConfig {
                dp_image,
                cp_url,
                admin_port: args.dp_admin_port,
            };
            let (tx, rx) = watch::channel(Vec::new());
            let writer_client = client.clone();
            let mut shutdown = shutdown_rx.clone();
            let handle = tokio::spawn(async move {
                infra_writer::run(writer_client, rx, async move {
                    let _ = shutdown.wait_for(|v| *v).await;
                })
                .await;
            });
            tracing::info!("data-plane provisioning enabled");
            (Some(InfraPublisher { config, tx }), Some(handle))
        } else {
            tracing::info!("data-plane provisioning disabled (--dp-image / --cp-url unset)");
            (None, None)
        };

    // Status writeback: the watch loop publishes desired status per
    // pass; this task owns the apiserver writes. Always on — writing
    // status is a controller duty, not an optional feature.
    let (status_tx, status_rx) = watch::channel(StatusWork::default());
    let status_handle = {
        let writer_client = client.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            status_writer::run(writer_client, status_rx, async move {
                let _ = rx.wait_for(|v| *v).await;
            })
            .await;
        })
    };

    let watch_handle = {
        let state = state.clone();
        let controller_name = args.controller_name.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let shutdown = async move {
                let _ = rx.wait_for(|v| *v).await;
            };
            if let Err(e) = run_watch(
                client,
                controller_name,
                state,
                infra_publisher,
                status_tx,
                shutdown,
            )
            .await
            {
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
    let _ = status_handle.await;
    if let Some(handle) = writer_handle {
        let _ = handle.await;
    }
    Ok(())
}
