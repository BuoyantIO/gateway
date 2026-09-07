//! kube watch loop.
//!
//! Eight `kube_runtime::reflector` instances keep an in-memory view
//! of `GatewayClass`, `Gateway`, `HTTPRoute`, `core/v1 Service`,
//! `discovery/v1 EndpointSlice` (filtered to slices carrying the
//! `kubernetes.io/service-name` label), `core/v1 Secret`, and our own
//! `Extension` and `GatewayBackend`. A single `tokio::select!` over
//! the watcher streams drives the loop: each relevant event triggers
//! one pass (resolve, translate, publish, status, infra).
//!
//! Secrets are watched whatever their type. A certificate arrives as
//! `kubernetes.io/tls` by convention, but a credential a
//! `GatewayBackend` names is whatever the operator's secret tooling
//! produced — usually `Opaque` — and requiring them to retype it
//! would be a contract about provisioning rather than about the
//! gateway. Nothing here reads `type`; what a secret is taken to be
//! is decided by the data keys the reference asks for.
//!
//! The cost is worth stating: this reflector holds every
//! Secret in the cluster, and every Secret write drives a pass. If
//! that becomes a problem, the narrowing that keeps the contract
//! intact is a field selector excluding the types nothing here can
//! reference (`kubernetes.io/service-account-token`,
//! `helm.sh/release.v1`), not a rule operators have to follow.
//!
//! Not every event is relevant. A status-only write does not bump
//! `metadata.generation` and changes nothing the pass reads, so it is
//! skipped. This matters because we write status ourselves: without
//! the skip, every one of our own writes would echo back as an event
//! and trigger a useless pass. Other controllers writing status to
//! the same objects are filtered the same way.
//!
//! Per kind:
//! - `GatewayClass`, `HTTPRoute`, `Extension`, `GatewayBackend`:
//!   skip unless the generation changed.
//! - `Gateway`: skip unless the generation or the annotations changed
//!   (the provisioner reads the self-managed opt-out annotation).
//! - `Service`, `Secret`, `EndpointSlice`: never skipped. Service
//!   status carries the `LoadBalancer` address; Secret data has no
//!   generation; every `EndpointSlice` write is an endpoint-set
//!   change.
//!
//! A watcher resync replays every object; the replay runs one pass at
//! the end (`InitDone`) instead of one per object.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;

use futures::StreamExt;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::HTTPRoute;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::Api;
use kube::runtime::reflector::{self, Store as ReflectorStore};
use kube::runtime::watcher::{self, Config};
use thiserror::Error;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use tokio::sync::watch as tokio_watch;

use crate::admin::ReadyState;
use crate::crd::{Extension, GatewayBackend};
use crate::infra::{self, InfraPublisher};
use crate::resolve::{SERVICE_NAME_LABEL, resolve};
use crate::server::ServerState;
use crate::status::{StatusWork, build_work};
use crate::translator::{K8sState, translate_resolution};

/// The resource kinds the loop watches, in reflector order. Also the
/// initial pending set for the readiness endpoint.
pub const WATCHED_KINDS: [&str; 8] = [
    "GatewayClass",
    "Gateway",
    "HTTPRoute",
    "Service",
    "EndpointSlice",
    "Secret",
    "Extension",
    "GatewayBackend",
];

#[derive(Debug, Error)]
pub enum WatchError {
    #[error(transparent)]
    Kube(#[from] kube::Error),
}

/// Run the watch loop until `shutdown` resolves. Sets up one
/// reflector per watched kind against the cluster `client` and
/// drives them all under one `select!`.
///
/// # Errors
/// Returns `WatchError::Kube` only for setup failures. Per-event
/// watcher errors are transient and handled by `kube_runtime::watcher`
/// internally; we log and continue.
#[allow(clippy::similar_names)] // gc/gw/hr/svc/sec/gb bindings are intentionally parallel
#[allow(clippy::too_many_arguments)] // the loop is the wiring point for every channel
pub async fn run(
    client: kube::Client,
    controller_name: String,
    state: Arc<ServerState>,
    infra: Option<InfraPublisher>,
    status_tx: tokio_watch::Sender<StatusWork>,
    mut is_leader: tokio_watch::Receiver<bool>,
    ready_tx: tokio_watch::Sender<ReadyState>,
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

    let (es_store, es_writer) = reflector::store::<EndpointSlice>();
    let es_api: Api<EndpointSlice> = Api::all(client.clone());
    let es_config = Config::default().labels(SERVICE_NAME_LABEL);
    let mut es_stream =
        reflector::reflector(es_writer, watcher::watcher(es_api, es_config)).boxed();

    let (sec_store, sec_writer) = reflector::store::<Secret>();
    let sec_api: Api<Secret> = Api::all(client.clone());
    let mut sec_stream =
        reflector::reflector(sec_writer, watcher::watcher(sec_api, Config::default())).boxed();

    let (ext_store, ext_writer) = reflector::store::<Extension>();
    let ext_api: Api<Extension> = Api::all(client.clone());
    let mut ext_stream =
        reflector::reflector(ext_writer, watcher::watcher(ext_api, Config::default())).boxed();

    let (gb_store, gb_writer) = reflector::store::<GatewayBackend>();
    let gb_api: Api<GatewayBackend> = Api::all(client);
    let mut gb_stream =
        reflector::reflector(gb_writer, watcher::watcher(gb_api, Config::default())).boxed();

    let mut gc_filter = EventFilter::generation_only();
    let mut gw_filter = EventFilter::generation_and_annotations();
    let mut hr_filter = EventFilter::generation_only();
    let mut ext_filter = EventFilter::generation_only();
    let mut gb_filter = EventFilter::generation_only();

    let mut sync = SyncTracker::new();

    loop {
        let relevant = tokio::select! {
            biased;
            () = &mut shutdown => break,
            // A promotion runs a full pass immediately so the status
            // and infra skipped while following are emitted without
            // waiting for the next cluster event.
            _ = is_leader.changed() => *is_leader.borrow(),
            ev = gc_stream.next() => { sync.mark("GatewayClass", ev.as_ref()); gc_filter.relevant("GatewayClass", ev) }
            ev = gw_stream.next() => { sync.mark("Gateway", ev.as_ref()); gw_filter.relevant("Gateway", ev) }
            ev = hr_stream.next() => { sync.mark("HTTPRoute", ev.as_ref()); hr_filter.relevant("HTTPRoute", ev) }
            ev = svc_stream.next() => { sync.mark("Service", ev.as_ref()); EventFilter::always("Service", ev) }
            ev = es_stream.next() => { sync.mark("EndpointSlice", ev.as_ref()); EventFilter::always("EndpointSlice", ev) }
            ev = sec_stream.next() => { sync.mark("Secret", ev.as_ref()); EventFilter::always("Secret", ev) }
            ev = ext_stream.next() => { sync.mark("Extension", ev.as_ref()); ext_filter.relevant("Extension", ev) }
            ev = gb_stream.next() => { sync.mark("GatewayBackend", ev.as_ref()); gb_filter.relevant("GatewayBackend", ev) }
        };
        if !relevant {
            continue;
        }

        let k8s = collect_state(
            &gc_store, &gw_store, &hr_store, &svc_store, &es_store, &sec_store, &ext_store,
            &gb_store,
        );
        let resolution = resolve(&k8s, &controller_name);
        let world = translate_resolution(&resolution);
        state.publish(&world);

        // Readiness follows the pass, not the stores: a pod is ready
        // once the world it serves derives from complete cluster
        // state. Kinds drop off the pending list as their reflectors
        // deliver initial state.
        ready_tx.send_if_modified(|s| {
            let next = sync.ready_state();
            if *s == next {
                false
            } else {
                *s = next;
                true
            }
        });

        // Status and infra are apiserver writes: leader-only. Every
        // replica still publishes to its own data planes above.
        if !*is_leader.borrow() {
            continue;
        }

        // Desired status rides the same pass; the writer task on the
        // other side of the channel owns the apiserver writes.
        let now = Time(k8s_openapi::jiff::Timestamp::now());
        let _ = status_tx.send(build_work(&resolution, &now));

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

    // Draining: go unready so the pod leaves the Service endpoints
    // before its streams close (data planes reconnect to a peer).
    let _ = ready_tx.send(ReadyState {
        pending: Vec::new(),
        shutting_down: true,
    });

    Ok(())
}

/// Tracks which reflectors have delivered their initial state.
/// `run` marks streams as they yield `InitDone`; the pending list
/// feeds the readiness endpoint.
struct SyncTracker {
    pending: Vec<&'static str>,
}

impl SyncTracker {
    fn new() -> Self {
        Self {
            pending: WATCHED_KINDS.to_vec(),
        }
    }

    fn mark<K>(
        &mut self,
        kind: &'static str,
        ev: Option<&Result<watcher::Event<K>, watcher::Error>>,
    ) {
        if matches!(ev, Some(Ok(watcher::Event::InitDone))) {
            self.pending.retain(|k| *k != kind);
        }
    }

    fn ready_state(&self) -> ReadyState {
        ReadyState {
            pending: self.pending.clone(),
            shutting_down: false,
        }
    }
}

/// Walk each reflector store once and clone the resources into a
/// `K8sState` the translator can consume.
#[allow(clippy::too_many_arguments)] // one parameter per watched kind
fn collect_state(
    gc: &ReflectorStore<GatewayClass>,
    gw: &ReflectorStore<Gateway>,
    hr: &ReflectorStore<HTTPRoute>,
    svc: &ReflectorStore<Service>,
    es: &ReflectorStore<EndpointSlice>,
    sec: &ReflectorStore<Secret>,
    ext: &ReflectorStore<Extension>,
    gb: &ReflectorStore<GatewayBackend>,
) -> K8sState {
    K8sState {
        gateway_classes: gc.state().iter().map(|a| (**a).clone()).collect(),
        gateways: gw.state().iter().map(|a| (**a).clone()).collect(),
        http_routes: hr.state().iter().map(|a| (**a).clone()).collect(),
        services: svc.state().iter().map(|a| (**a).clone()).collect(),
        endpoint_slices: es.state().iter().map(|a| (**a).clone()).collect(),
        secrets: sec.state().iter().map(|a| (**a).clone()).collect(),
        extensions: ext.state().iter().map(|a| (**a).clone()).collect(),
        gateway_backends: gb.state().iter().map(|a| (**a).clone()).collect(),
    }
}

/// The parts of an object the pass reads: generation, and (for
/// Gateways) the annotations.
type Fingerprint = (Option<i64>, Option<BTreeMap<String, String>>);

/// Decides whether an event is worth a pass. If an object's
/// fingerprint is the same as last time, the event was a status-only
/// write and is skipped.
///
/// If a pass ever starts reading a new metadata field from a filtered
/// kind, that field must be added to the fingerprint.
struct EventFilter {
    /// Fingerprint of each object at its last event, by uid.
    seen: HashMap<String, Fingerprint>,
    /// Track annotations too. Only Gateways need this: the
    /// provisioner reads the self-managed opt-out annotation, and
    /// annotation edits don't bump the generation.
    track_annotations: bool,
    /// During a resync: the uids seen so far. Used by `InitDone` to
    /// drop entries for objects deleted while the watch was down
    /// (those never get a `Delete` event).
    resync: Option<std::collections::HashSet<String>>,
}

impl EventFilter {
    fn generation_only() -> Self {
        Self {
            seen: HashMap::new(),
            track_annotations: false,
            resync: None,
        }
    }

    fn generation_and_annotations() -> Self {
        Self {
            seen: HashMap::new(),
            track_annotations: true,
            resync: None,
        }
    }

    /// True if this event should trigger a pass.
    fn relevant<K: kube::Resource>(
        &mut self,
        kind: &str,
        ev: Option<Result<watcher::Event<K>, watcher::Error>>,
    ) -> bool {
        match ev {
            Some(Ok(watcher::Event::Apply(obj))) => self.apply(&obj),
            Some(Ok(watcher::Event::Delete(obj))) => {
                if let Some(uid) = obj.meta().uid.as_deref() {
                    self.seen.remove(uid);
                }
                true
            }
            // Resync replay: remember the object, but don't run a
            // pass per object — InitDone runs one pass at the end,
            // after the reflector store has swapped.
            Some(Ok(watcher::Event::InitApply(obj))) => {
                self.apply(&obj);
                if let (Some(replayed), Some(uid)) = (&mut self.resync, obj.meta().uid.as_deref()) {
                    replayed.insert(uid.to_string());
                }
                false
            }
            Some(Ok(watcher::Event::Init)) => {
                self.resync = Some(std::collections::HashSet::new());
                false
            }
            Some(Ok(watcher::Event::InitDone)) => {
                if let Some(replayed) = self.resync.take() {
                    self.seen.retain(|uid, _| replayed.contains(uid));
                }
                true
            }
            None => false,
            Some(Err(e)) => {
                tracing::warn!(kind, error = %e, "watcher emitted error");
                false
            }
        }
    }

    fn apply<K: kube::Resource>(&mut self, obj: &K) -> bool {
        let meta = obj.meta();
        // Without a uid we can't track the object; don't risk a wrong
        // skip.
        let Some(uid) = meta.uid.as_deref() else {
            return true;
        };
        let fingerprint: Fingerprint = (
            meta.generation,
            self.track_annotations
                .then(|| meta.annotations.clone())
                .flatten(),
        );
        match self.seen.insert(uid.to_string(), fingerprint.clone()) {
            Some(prev) => prev != fingerprint,
            None => true,
        }
    }

    /// For Services and Secrets: every change matters, so never skip
    /// `Apply` or `Delete`. Resyncs still collapse into the single
    /// `InitDone` pass.
    fn always<K: kube::Resource>(
        kind: &str,
        ev: Option<Result<watcher::Event<K>, watcher::Error>>,
    ) -> bool {
        match ev {
            Some(Ok(
                watcher::Event::Apply(_) | watcher::Event::Delete(_) | watcher::Event::InitDone,
            )) => true,
            Some(Ok(watcher::Event::Init | watcher::Event::InitApply(_))) | None => false,
            Some(Err(e)) => {
                tracing::warn!(kind, error = %e, "watcher emitted error");
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn gw(uid: &str, generation: i64, annotations: Option<&[(&str, &str)]>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                uid: Some(uid.into()),
                generation: Some(generation),
                annotations: annotations.map(|kv| {
                    kv.iter()
                        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                        .collect()
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[allow(clippy::unnecessary_wraps)] // mirrors the stream item shape
    fn ev(g: Gateway) -> Option<Result<watcher::Event<Gateway>, watcher::Error>> {
        Some(Ok(watcher::Event::Apply(g)))
    }

    #[test]
    fn status_only_write_is_skipped() {
        let mut f = EventFilter::generation_only();
        assert!(f.relevant("Gateway", ev(gw("u1", 1, None))));
        // A status write leaves the generation untouched.
        assert!(!f.relevant("Gateway", ev(gw("u1", 1, None))));
        // A spec change bumps it.
        assert!(f.relevant("Gateway", ev(gw("u1", 2, None))));
    }

    #[test]
    fn annotation_change_relevant_only_when_tracked() {
        let mut tracked = EventFilter::generation_and_annotations();
        assert!(tracked.relevant("Gateway", ev(gw("u1", 1, None))));
        assert!(tracked.relevant("Gateway", ev(gw("u1", 1, Some(&[("a", "b")])))));

        let mut untracked = EventFilter::generation_only();
        assert!(untracked.relevant("Gateway", ev(gw("u1", 1, None))));
        assert!(!untracked.relevant("Gateway", ev(gw("u1", 1, Some(&[("a", "b")])))));
    }

    #[test]
    fn delete_forgets_the_uid() {
        let mut f = EventFilter::generation_only();
        assert!(f.relevant("Gateway", ev(gw("u1", 1, None))));
        assert!(f.relevant(
            "Gateway",
            Some(Ok(watcher::Event::Delete(gw("u1", 1, None))))
        ));
        // After a delete the uid is forgotten, so the next apply
        // counts as new.
        assert!(f.relevant("Gateway", ev(gw("u1", 1, None))));
    }

    #[test]
    fn resync_coalesces_to_the_init_done_pass() {
        let mut f = EventFilter::generation_and_annotations();
        assert!(!f.relevant::<Gateway>("Gateway", Some(Ok(watcher::Event::Init))));
        assert!(!f.relevant(
            "Gateway",
            Some(Ok(watcher::Event::InitApply(gw("u1", 1, None))))
        ));
        assert!(f.relevant::<Gateway>("Gateway", Some(Ok(watcher::Event::InitDone))));
        // The replay recorded u1's fingerprint, so a status echo
        // after the resync still skips.
        assert!(!f.relevant("Gateway", ev(gw("u1", 1, None))));

        // u1 is deleted while the watch is down: the resync replays
        // only u2, so InitDone drops u1's entry.
        assert!(!f.relevant::<Gateway>("Gateway", Some(Ok(watcher::Event::Init))));
        assert!(!f.relevant(
            "Gateway",
            Some(Ok(watcher::Event::InitApply(gw("u2", 1, None))))
        ));
        assert!(f.relevant::<Gateway>("Gateway", Some(Ok(watcher::Event::InitDone))));
        assert!(!f.seen.contains_key("u1"));
        assert!(f.seen.contains_key("u2"));
    }
}
