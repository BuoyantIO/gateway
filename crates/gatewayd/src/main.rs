use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use tokio::sync::watch;

mod admin;

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

    /// Admin HTTP listen address (readiness endpoint). No admin
    /// server when unset.
    #[arg(long)]
    admin_addr: Option<SocketAddr>,

    /// Seconds in-flight connections get to finish after shutdown or
    /// a bind teardown starts. Sized under the default Kubernetes
    /// termination grace period (30s) so draining beats the SIGKILL.
    #[arg(long, default_value_t = 25)]
    drain_grace: u64,

    /// Log output format: text for humans, json for log pipelines.
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,
}

#[derive(Clone, Copy, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Nothing logs during parsing; --help/--version exit here.
    let args = Args::parse();

    let env_filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    };
    match args.log_format {
        LogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(env_filter())
            .init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter())
            .init(),
    }

    if args.config.is_none() && args.control_plane.is_none() {
        anyhow::bail!("either --config or --control-plane must be set");
    }

    let store = gateway_state::Store::new();

    // Metric families the proxy records into, registered under the
    // `gateway_` prefix; the admin server renders the registry.
    let metrics = gateway_runtime::Metrics::new();
    let mut registry = prometheus_client::registry::Registry::with_prefix("gateway");
    metrics.register(&mut registry);
    let registry = std::sync::Arc::new(registry);

    // Readiness latch for the admin endpoint: flipped once the
    // config bootstrap has been applied, never flipped back.
    let (ready_tx, ready_rx) = watch::channel(false);

    if let Some(path) = &args.config {
        load_yaml_into_store(path, &store)?;
        ready_tx.send_replace(true);
    }

    // One drain channel is the whole shutdown story: the Watch side
    // is the shutdown signal every component
    // listens on, the Signal side is the barrier the driver waits
    // out. SIGTERM is what the kubelet sends on pod deletion —
    // handling it is what makes rolling updates drain instead of
    // riding out the grace period to SIGKILL.
    let grace = std::time::Duration::from_secs(args.drain_grace);
    let (drain_signal, drain_watch) = gateway_runtime::drain::channel();
    // The admin server drains on its own channel, chained after the
    // data drain: it must keep answering probes (as unready) while
    // connections finish, and stop only afterwards. shutting_down is
    // the level the probe state reads during that window.
    let (admin_signal, admin_watch) = gateway_runtime::drain::channel();
    let (shutting_down_tx, shutting_down_rx) = watch::channel(false);
    let driver = spawn_drain_driver(drain_signal, admin_signal, shutting_down_tx, grace)?;

    let admin_handle = if let Some(addr) = args.admin_addr {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(%addr, "admin server listening");
        let probe_rx = spawn_probe_state(ready_rx.clone(), shutting_down_rx.clone());
        Some(tokio::spawn(admin::serve(
            listener,
            probe_rx,
            std::sync::Arc::clone(&registry),
            admin_watch,
        )))
    } else {
        None
    };

    let cp_handle = if let Some(cp_url) = args.control_plane {
        let client_id = args.client_id.expect("required by clap");
        let endpoint = gateway_cp_client::endpoint(cp_url)
            .map_err(|e| anyhow::anyhow!("invalid --control-plane URL: {e}"))?;
        let store_clone = store.clone();
        let w = drain_watch.clone();
        tracing::info!(?endpoint, client_id, "connecting to control plane");
        Some(tokio::spawn(async move {
            if let Err(e) =
                gateway_cp_client::run(endpoint, client_id, store_clone, ready_tx, async move {
                    let _ = w.signaled().await;
                })
                .await
            {
                tracing::error!(error = %e, "control-plane client exited with error");
            }
        }))
    } else {
        None
    };

    let mut classes = gateway_runtime::extension::Registry::new();
    gateway_extension_impls::register_builtins(&mut classes);
    classes
        .register(
            gateway_extension_impls::kinference::KINFERENCE_SELECTOR,
            std::sync::Arc::new(gateway_extension_impls::kinference::KinferenceSelectorClass),
        )
        .expect("kinference_selector is not a reserved name");
    let gateway = gateway_runtime::Gateway::with_metrics(store, metrics).with_classes(classes);
    gateway.run(drain_watch).await?;

    // The run loop exited: on a signal the driver is already waiting
    // out in-flight work under the grace deadline; without one (event
    // channel closed) there is nothing to drain against.
    if *shutting_down_rx.borrow() {
        let _ = driver.await;
    } else {
        driver.abort();
    }

    if let Some(handle) = cp_handle {
        let _ = handle.await;
    }
    if let Some(handle) = admin_handle {
        let _ = handle.await;
    }

    Ok(())
}

/// Register SIGINT/SIGTERM and spawn the drain driver: on the first
/// signal, go unready and fire the data drain, waiting out in-flight
/// connections under the grace deadline, then drain the admin server
/// (which served unready probes throughout). A second signal skips
/// the wait and exits immediately — a courtesy for an impatient
/// operator; Kubernetes itself never sends a second SIGTERM.
fn spawn_drain_driver(
    data: gateway_runtime::drain::Signal,
    admin: gateway_runtime::drain::Signal,
    shutting_down: watch::Sender<bool>,
    grace: std::time::Duration,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{SignalKind, signal as unix_signal};
    let mut interrupt = unix_signal(SignalKind::interrupt())?;
    let mut terminate = unix_signal(SignalKind::terminate())?;
    Ok(tokio::spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => tracing::info!("SIGINT received; draining"),
            _ = terminate.recv() => tracing::info!("SIGTERM received; draining"),
        }
        let _ = shutting_down.send(true);
        tokio::spawn(async move {
            tokio::select! {
                _ = interrupt.recv() => {},
                _ = terminate.recv() => {},
            }
            tracing::warn!("second signal received; exiting immediately");
            std::process::exit(1);
        });
        if tokio::time::timeout(grace, data.drain()).await.is_err() {
            tracing::warn!("drain deadline expired with connections still open; exiting");
        }
        // Probe responses are sub-second; a short deadline is plenty.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), admin.drain()).await;
    }))
}

/// Effective probe readiness = bootstrapped && not shutting down: a
/// draining pod goes unready so it leaves the Service endpoints while
/// in-flight work finishes.
fn spawn_probe_state(
    mut ready: watch::Receiver<bool>,
    mut shutdown: watch::Receiver<bool>,
) -> watch::Receiver<bool> {
    let (probe_tx, probe_rx) = watch::channel(false);
    tokio::spawn(async move {
        loop {
            let up = *ready.borrow_and_update() && !*shutdown.borrow_and_update();
            if probe_tx.send(up).is_err() {
                return;
            }
            tokio::select! {
                c = ready.changed() => { if c.is_err() { return; } }
                c = shutdown.changed() => { if c.is_err() { return; } }
            }
        }
    });
    probe_rx
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
