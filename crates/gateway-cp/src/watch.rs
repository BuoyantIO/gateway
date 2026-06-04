//! kube watch loop.
//!
//! Four `kube_runtime::reflector` instances keep an in-memory view of
//! `GatewayClass`, `Gateway`, `HTTPRoute`, and `core/v1 Service`. A
//! single `tokio::select!` over the four watcher streams marks state
//! dirty on any event and starts a debounce timer; when the timer
//! fires, the loop collects the four stores, calls `translate()`,
//! and hands the result to `ServerState::publish` which fans
//! per-Gateway diffs out to connected DPs.

use std::future::{Future, pending};
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use k8s_openapi::api::core::v1::Service;
use kube::Api;
use kube::runtime::reflector::{self, Store as ReflectorStore};
use kube::runtime::watcher::{self, Config};
use thiserror::Error;
use tokio::time::{Sleep, sleep};

use crate::server::ServerState;
use crate::snapshot::Snapshot;
use crate::translator::{K8sState, translate};

/// Debounce window between the first event in a burst and the
/// translate-and-publish pass. 50ms is short enough that propagation
/// stays bench-friendly and long enough to coalesce typical
/// kubectl-apply / controller bursts.
const DEBOUNCE: Duration = Duration::from_millis(50);

#[derive(Debug, Error)]
pub enum WatchError {
    #[error(transparent)]
    Kube(#[from] kube::Error),
}

/// Run the watch loop until `shutdown` resolves. Sets up four
/// reflectors against the cluster `client` and drives them under one
/// `select!`.
///
/// # Errors
/// Returns `WatchError::Kube` only for setup failures (the kube
/// client can't construct the API handles). Watcher-stream errors
/// are transient and handled by `kube_runtime::watcher` internally;
/// we log and continue.
#[allow(clippy::similar_names)] // gc/gw/hr/svc bindings are intentionally parallel
pub async fn run(
    client: kube::Client,
    controller_name: String,
    state: Arc<ServerState>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), WatchError> {
    let mut shutdown = pin!(shutdown);

    let (gc_store, gc_writer) = reflector::store::<GatewayClass>();
    let gc_api: Api<GatewayClass> = Api::all(client.clone());
    let mut gc_stream =
        reflector::reflector(gc_writer, watcher::watcher(gc_api, Config::default())).boxed();

    let (gw_store, gw_writer) = reflector::store::<Gateway>();
    let gw_api: Api<Gateway> = Api::all(client.clone());
    let mut gw_stream =
        reflector::reflector(gw_writer, watcher::watcher(gw_api, Config::default())).boxed();

    let (hr_store, hr_writer) = reflector::store::<HTTPRoute>();
    let hr_api: Api<HTTPRoute> = Api::all(client.clone());
    let mut hr_stream =
        reflector::reflector(hr_writer, watcher::watcher(hr_api, Config::default())).boxed();

    let (svc_store, svc_writer) = reflector::store::<Service>();
    let svc_api: Api<Service> = Api::all(client);
    let mut svc_stream =
        reflector::reflector(svc_writer, watcher::watcher(svc_api, Config::default())).boxed();

    // `pending_debounce` is Some only while a debounce timer is
    // armed. Each new event re-arms it, so a burst of events fires
    // exactly one publish after `DEBOUNCE` of quiet.
    let mut pending_debounce: Option<Pin<Box<Sleep>>> = None;

    loop {
        // Yield from the debounce timer if armed; otherwise hand
        // `select!` a future that never resolves so only the stream
        // arms can fire.
        let mut wait: Pin<Box<dyn Future<Output = ()> + Send>> = match pending_debounce.take() {
            Some(s) => s,
            None => Box::pin(pending::<()>()),
        };

        let mut got_event = false;
        tokio::select! {
            biased;
            () = &mut shutdown => break,

            // Debounce fired: collect and publish. Do NOT re-arm.
            () = &mut wait => {
                let k8s = collect_state(&gc_store, &gw_store, &hr_store, &svc_store);
                let world: std::collections::HashMap<_, Snapshot> =
                    translate(&k8s, &controller_name);
                state.publish(&world);
            }

            // Any event from any kind: log errors, then re-arm the
            // debounce timer below.
            ev = gc_stream.next() => { log_event_err("GatewayClass", ev.as_ref()); got_event = true; }
            ev = gw_stream.next() => { log_event_err("Gateway", ev.as_ref()); got_event = true; }
            ev = hr_stream.next() => { log_event_err("HTTPRoute", ev.as_ref()); got_event = true; }
            ev = svc_stream.next() => { log_event_err("Service", ev.as_ref()); got_event = true; }
        }

        // Only rearm on event; the publish branch finishes a burst,
        // and we stay idle until the next event arrives.
        if got_event {
            pending_debounce = Some(Box::pin(sleep(DEBOUNCE)));
        }
    }

    Ok(())
}

/// Walk each reflector store once and clone the resources into a
/// `K8sState` the translator can consume.
fn collect_state(
    gc: &ReflectorStore<GatewayClass>,
    gw: &ReflectorStore<Gateway>,
    hr: &ReflectorStore<HTTPRoute>,
    svc: &ReflectorStore<Service>,
) -> K8sState {
    K8sState {
        gateway_classes: gc.state().iter().map(|a| (**a).clone()).collect(),
        gateways: gw.state().iter().map(|a| (**a).clone()).collect(),
        http_routes: hr.state().iter().map(|a| (**a).clone()).collect(),
        services: svc.state().iter().map(|a| (**a).clone()).collect(),
    }
}

fn log_event_err<T, E: std::fmt::Display>(kind: &str, ev: Option<&Result<T, E>>) {
    if let Some(Err(e)) = ev {
        tracing::warn!(kind, error = %e, "watcher emitted error");
    }
}
