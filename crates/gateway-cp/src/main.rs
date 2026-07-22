//! Control-plane daemon. Connects to the K8s API, runs the watch
//! loop, and serves the `ConfigStream` gRPC service to data planes.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use gateway_cp::admin;
use gateway_cp::infra::{InfraConfig, InfraPublisher, writer as infra_writer};
use gateway_cp::lease;
use gateway_cp::status::{StatusWork, writer as status_writer};
use gateway_cp::{ConfigStreamService, ServerState, run_watch};
use gateway_cp_proto::v1::config_stream_server::ConfigStreamServer;
use gateway_drain as drain;
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

    /// Admin HTTP listen address (readiness and liveness probes).
    #[arg(long, default_value = "0.0.0.0:15021")]
    admin_addr: SocketAddr,

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

/// Deadline for the control plane's tasks to finish after shutdown
/// starts: apiserver writes, the lease vacate, and stream teardown
/// are all short, bounded operations.
const DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(5);

/// A shutdown future for a task that only needs the signal: resolves
/// when draining starts and releases its barrier hold immediately
/// (the task's own `Watch` clone keeps the barrier up until it
/// finishes).
async fn stopped(drain: drain::Watch) {
    let _ = drain.signaled().await;
}

/// Register SIGINT/SIGTERM and spawn the drain driver: on the first
/// signal, fire the data drain and wait it out under the grace
/// deadline, then drain the admin server (which served unready
/// probes throughout). A second signal skips the wait and exits
/// immediately.
fn spawn_drain_driver(
    data: drain::Signal,
    admin: drain::Signal,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{SignalKind, signal as unix_signal};
    let mut interrupt = unix_signal(SignalKind::interrupt())?;
    let mut terminate = unix_signal(SignalKind::terminate())?;
    Ok(tokio::spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => tracing::info!("SIGINT received; draining"),
            _ = terminate.recv() => tracing::info!("SIGTERM received; draining"),
        }
        tokio::spawn(async move {
            tokio::select! {
                _ = interrupt.recv() => {},
                _ = terminate.recv() => {},
            }
            tracing::warn!("second signal received; exiting immediately");
            std::process::exit(1);
        });
        if tokio::time::timeout(DRAIN_GRACE, data.drain())
            .await
            .is_err()
        {
            tracing::warn!("drain deadline expired with tasks still running; exiting");
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), admin.drain()).await;
    }))
}

/// Bind and spawn the admin (probe) server; returns the readiness
/// sender the watch loop drives. Binding here means a bad address
/// fails startup instead of leaving a silently unready pod.
async fn spawn_admin(
    addr: SocketAddr,
    drain: drain::Watch,
) -> anyhow::Result<(
    watch::Sender<admin::ReadyState>,
    tokio::task::JoinHandle<()>,
)> {
    let (ready_tx, ready_rx) = watch::channel(admin::ReadyState {
        pending: gateway_cp::watch::WATCHED_KINDS.to_vec(),
        shutting_down: false,
    });
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let handle = tokio::spawn(admin::serve(listener, ready_rx, drain));
    tracing::info!(admin = %addr, "admin server listening");
    Ok((ready_tx, handle))
}

/// Spawn the lease elector; returns the leadership channel consumed
/// by the watch loop and writer tasks.
fn spawn_elector(
    client: kube::Client,
    namespace: String,
    identity: String,
    drain: drain::Watch,
) -> (watch::Receiver<bool>, tokio::task::JoinHandle<()>) {
    let (leader_tx, is_leader) = watch::channel(false);
    tracing::info!(identity = %identity, namespace = %namespace, "leader election started");
    let handle = tokio::spawn(async move {
        lease::run(
            client,
            &namespace,
            identity,
            leader_tx,
            stopped(drain.clone()),
        )
        .await;
        drop(drain);
    });
    (is_leader, handle)
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

    // One drain channel is the whole shutdown story: the Watch side
    // is the shutdown signal every task listens on (and holds, so the
    // barrier tracks task completion), the Signal side is what the
    // driver waits out. The admin server drains on its own channel,
    // chained after: it must answer probes (as unready) while the
    // other tasks finish, and stop only afterwards.
    let (drain_signal, drain_watch) = drain::channel();
    let (admin_signal, admin_watch) = drain::channel();
    let driver = spawn_drain_driver(drain_signal, admin_signal)?;

    // Admin server: readiness flips once the watch loop has run a
    // full pass over synced reflectors.
    let (ready_tx, admin_handle) = spawn_admin(args.admin_addr, admin_watch).await?;

    // Leader election: every replica translates and serves data
    // planes, but only the lease holder writes status and reconciles
    // infra. The elector task publishes transitions on a watch
    // channel the writer tasks and watch loop consume.
    let (is_leader, lease_handle) = spawn_elector(
        client.clone(),
        args.pod_namespace.clone(),
        args.pod_name.clone(),
        drain_watch.clone(),
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
            let w = drain_watch.clone();
            let handle = tokio::spawn(async move {
                infra_writer::run(writer_client, rx, leader, stopped(w.clone())).await;
                drop(w);
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
        let w = drain_watch.clone();
        tokio::spawn(async move {
            status_writer::run(writer_client, status_rx, leader, stopped(w.clone())).await;
            drop(w);
        })
    };

    let watch_handle = {
        let state = state.clone();
        let controller_name = args.controller_name.clone();
        let w = drain_watch.clone();
        tokio::spawn(async move {
            if let Err(e) = run_watch(
                client,
                controller_name,
                state,
                infra_publisher,
                status_tx,
                is_leader,
                ready_tx,
                stopped(w.clone()),
            )
            .await
            {
                tracing::error!(error = %e, "watch loop exited with error");
            }
            drop(w);
        })
    };

    // Data-plane config streams are infinite, so the gRPC server's
    // graceful shutdown would wait on them forever; on drain, end
    // them cleanly instead — the data planes reconnect to a peer
    // replica and re-bootstrap.
    let disconnect_handle = {
        let state = state.clone();
        let w = drain_watch.clone();
        tokio::spawn(async move {
            let _ = w.signaled().await;
            state.disconnect_all();
        })
    };

    let service = ConfigStreamServer::new(ConfigStreamService::new(state));
    tracing::info!(listen = %args.listen, controller = %args.controller_name, "control plane listening");
    Server::builder()
        .add_service(service)
        .serve_with_shutdown(args.listen, stopped(drain_watch.clone()))
        .await?;
    drop(drain_watch);

    let _ = watch_handle.await;
    let _ = status_handle.await;
    if let Some(handle) = writer_handle {
        let _ = handle.await;
    }
    let _ = lease_handle.await;
    let _ = disconnect_handle.await;
    // The driver has waited out the data drain and then drained the
    // admin server, which answered unready probes throughout.
    let _ = driver.await;
    let _ = admin_handle.await;
    Ok(())
}
