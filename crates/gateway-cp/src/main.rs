//! Control-plane daemon. Connects to the K8s API, runs the watch
//! loop, and serves the `ConfigStream` gRPC service to data planes.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use gateway_cp::infra::{InfraConfig, InfraPublisher, writer as infra_writer};
use gateway_cp::lease;
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

    /// This replica's identity for leader election; the Deployment
    /// sets it from the pod name via the downward API.
    #[arg(long, env = "POD_NAME", default_value_t = default_pod_name())]
    pod_name: String,

    /// Namespace holding the leader-election Lease (the control
    /// plane's own namespace, via the downward API).
    #[arg(long, env = "POD_NAMESPACE", default_value = "gateway-system")]
    pod_namespace: String,
}

fn default_pod_name() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "gateway-cp-0".to_string())
}

/// Spawn the lease elector; returns the leadership channel consumed
/// by the watch loop and writer tasks.
fn spawn_elector(
    client: kube::Client,
    namespace: String,
    identity: String,
    mut shutdown_rx: watch::Receiver<bool>,
) -> (watch::Receiver<bool>, tokio::task::JoinHandle<()>) {
    let (leader_tx, is_leader) = watch::channel(false);
    tracing::info!(identity = %identity, namespace = %namespace, "leader election started");
    let handle = tokio::spawn(async move {
        lease::run(client, &namespace, identity, leader_tx, async move {
            let _ = shutdown_rx.wait_for(|v| *v).await;
        })
        .await;
    });
    (is_leader, handle)
}

/// Flip `tx` on SIGINT or SIGTERM. SIGTERM is what the kubelet sends
/// on pod deletion; draining on it lets the elector vacate the lease
/// so the peer takes over immediately during rolling updates.
fn spawn_signal_handler(tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("ctrl-c received; shutting down"),
            _ = term.recv() => tracing::info!("SIGTERM received; shutting down"),
        }
        let _ = tx.send(true);
    });
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

    // Single shutdown channel; SIGINT/SIGTERM flip it and every task
    // drains off the same signal.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    spawn_signal_handler(shutdown_tx.clone());

    // Leader election: every replica translates and serves data
    // planes, but only the lease holder writes status and reconciles
    // infra. The elector task publishes transitions on a watch
    // channel the writer tasks and watch loop consume.
    let (is_leader, lease_handle) = spawn_elector(
        client.clone(),
        args.pod_namespace.clone(),
        args.pod_name.clone(),
        shutdown_rx.clone(),
    );

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
            let leader = is_leader.clone();
            let mut shutdown = shutdown_rx.clone();
            let handle = tokio::spawn(async move {
                infra_writer::run(writer_client, rx, leader, async move {
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
        let leader = is_leader.clone();
        let mut rx = shutdown_rx.clone();
        tokio::spawn(async move {
            status_writer::run(writer_client, status_rx, leader, async move {
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
                is_leader,
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
    // Last: vacating the lease happens inside the elector's shutdown
    // path, after the writers above have stopped acting on leadership.
    let _ = lease_handle.await;
    Ok(())
}
