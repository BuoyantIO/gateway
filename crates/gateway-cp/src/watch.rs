//! kube watch loop.
//!
//! Five `kube_runtime::reflector` instances keep an in-memory view of
//! `GatewayClass`, `Gateway`, `HTTPRoute`, `core/v1 Service`, and
//! `core/v1 Secret` (filtered to `type: kubernetes.io/tls`). A single
//! `tokio::select!` over the watcher streams drives the loop: every
//! event triggers a `translate` + `ServerState::publish`.
//!
//! Currently publishes on every event. `diff` returns `None` when nothing
//! changed, so spurious publishes are no-ops at the broadcast layer
//! and never reach the data planes. Add debouncing back when
//! translate cost during config bursts becomes measurable.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;

use futures::StreamExt;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use k8s_openapi::api::core::v1::{Secret, Service};
use kube::Api;
use kube::runtime::reflector::{self, Store as ReflectorStore};
use kube::runtime::watcher::{self, Config};
use thiserror::Error;

use crate::infra::{self, InfraPublisher};
use crate::server::ServerState;
use crate::translator::{K8sState, translate};

#[derive(Debug, Error)]
pub enum WatchError {
    #[error(transparent)]
    Kube(#[from] kube::Error),
}

/// Run the watch loop until `shutdown` resolves. Sets up five
/// reflectors against the cluster `client` and drives them under one
/// `select!`.
///
/// # Errors
/// Returns `WatchError::Kube` only for setup failures. Per-event
/// watcher errors are transient and handled by `kube_runtime::watcher`
/// internally; we log and continue.
#[allow(clippy::similar_names)] // gc/gw/hr/svc/sec bindings are intentionally parallel
pub async fn run(
    client: kube::Client,
    controller_name: String,
    state: Arc<ServerState>,
    infra: Option<InfraPublisher>,
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
    let svc_api: Api<Service> = Api::all(client.clone());
    let mut svc_stream =
        reflector::reflector(svc_writer, watcher::watcher(svc_api, Config::default())).boxed();

    let (sec_store, sec_writer) = reflector::store::<Secret>();
    let sec_api: Api<Secret> = Api::all(client);
    let sec_config = Config::default().fields("type=kubernetes.io/tls");
    let mut sec_stream =
        reflector::reflector(sec_writer, watcher::watcher(sec_api, sec_config)).boxed();

    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            ev = gc_stream.next() => log_event_err("GatewayClass", ev.as_ref()),
            ev = gw_stream.next() => log_event_err("Gateway", ev.as_ref()),
            ev = hr_stream.next() => log_event_err("HTTPRoute", ev.as_ref()),
            ev = svc_stream.next() => log_event_err("Service", ev.as_ref()),
            ev = sec_stream.next() => log_event_err("Secret", ev.as_ref()),
        }

        let k8s = collect_state(&gc_store, &gw_store, &hr_store, &svc_store, &sec_store);
        let world = translate(&k8s, &controller_name);
        state.publish(&world);

        // Desired data-plane infra rides the same pass; the channel
        // dedups so the writer only wakes on real changes.
        if let Some(publisher) = &infra {
            let set = infra::desired_set(&k8s, &controller_name, &publisher.config);
            publisher.tx.send_if_modified(|current| {
                if *current == set {
                    false
                } else {
                    *current = set;
                    true
                }
            });
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
    sec: &ReflectorStore<Secret>,
) -> K8sState {
    K8sState {
        gateway_classes: gc.state().iter().map(|a| (**a).clone()).collect(),
        gateways: gw.state().iter().map(|a| (**a).clone()).collect(),
        http_routes: hr.state().iter().map(|a| (**a).clone()).collect(),
        services: svc.state().iter().map(|a| (**a).clone()).collect(),
        secrets: sec.state().iter().map(|a| (**a).clone()).collect(),
    }
}

fn log_event_err<T, E: std::fmt::Display>(kind: &str, ev: Option<&Result<T, E>>) {
    if let Some(Err(e)) = ev {
        tracing::warn!(kind, error = %e, "watcher emitted error");
    }
}
