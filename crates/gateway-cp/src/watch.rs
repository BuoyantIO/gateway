//! kube watch loop.
//!
//! Five `kube_runtime::reflector` instances keep an in-memory view of
//! `GatewayClass`, `Gateway`, `HTTPRoute`, `core/v1 Service`, and
//! `core/v1 Secret` (filtered to `type: kubernetes.io/tls`). A single
//! `tokio::select!` over the watcher streams drives the loop: each
//! relevant event triggers one pass (resolve, translate, publish,
//! status, infra).
//!
//! Not every event is relevant. A status-only write does not bump
//! `metadata.generation` and changes nothing the pass reads, so it is
//! skipped. This matters because we write status ourselves: without
//! the skip, every one of our own writes would echo back as an event
//! and trigger a useless pass. Other controllers writing status to
//! the same objects are filtered the same way.
//!
//! Per kind:
//! - `GatewayClass`, `HTTPRoute`: skip unless the generation changed.
//! - `Gateway`: skip unless the generation or the annotations changed
//!   (the provisioner reads the self-managed opt-out annotation).
//! - `Service`, `Secret`: never skipped. Service status carries the
//!   `LoadBalancer` address; Secret data has no generation.
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
use kube::Api;
use kube::runtime::reflector::{self, Store as ReflectorStore};
use kube::runtime::watcher::{self, Config};
use thiserror::Error;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use tokio::sync::watch as tokio_watch;

use crate::infra::{self, InfraPublisher};
use crate::server::ServerState;
use crate::status::StatusWork;
use crate::translator::K8sState;
use crate::world::WorldCache;

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
    status_tx: tokio_watch::Sender<StatusWork>,
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

    let mut gc_filter = EventFilter::generation_only();
    let mut gw_filter = EventFilter::generation_and_annotations();
    let mut hr_filter = EventFilter::generation_only();
    let mut cache = WorldCache::new();

    loop {
        let action = tokio::select! {
            biased;
            () = &mut shutdown => break,
            ev = gc_stream.next() => Action::full_if(gc_filter.relevant("GatewayClass", ev)),
            ev = gw_stream.next() => Action::full_if(gw_filter.relevant("Gateway", ev)),
            ev = hr_stream.next() => hr_filter.route_action(ev),
            ev = svc_stream.next() => Action::full_if(EventFilter::always("Service", ev)),
            ev = sec_stream.next() => Action::full_if(EventFilter::always("Secret", ev)),
        };
        let now = Time(k8s_openapi::jiff::Timestamp::now());
        match action {
            Action::Skip => {}
            // One route changed: resolve just that route against the
            // cached state and send deltas. Routes never affect the
            // desired infra, so that part is skipped.
            Action::Route(route_id, route) => {
                let (deltas, status) = cache.route_event(&route_id, route, &controller_name, &now);
                for (gw_id, delta) in deltas {
                    state.apply_delta(&gw_id, delta);
                }
                let _ = status_tx.send(status);
            }
            Action::FullPass => {
                let k8s = collect_state(&gc_store, &gw_store, &hr_store, &svc_store, &sec_store);
                let (world, status) = cache.full_pass(k8s, &controller_name, &now);
                state.publish(world);

                // The writer task on the other side of the channel
                // owns the apiserver writes.
                let _ = status_tx.send(status);

                // The channel dedups, so the infra writer only wakes
                // on real changes.
                if let Some(publisher) = &infra {
                    let set =
                        infra::desired_set(cache.state(), &controller_name, &publisher.config);
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
        }
    }

    Ok(())
}

/// What the loop does with one event.
// The Route variant is large; there is exactly one Action alive at a
// time, so boxing would only add an allocation to the hot path.
#[allow(clippy::large_enum_variant)]
enum Action {
    Skip,
    /// Recompute everything (non-route change, or a resync).
    FullPass,
    /// One route changed; `None` means it was deleted.
    Route(crate::translator::RouteId, Option<HTTPRoute>),
}

impl Action {
    fn full_if(relevant: bool) -> Self {
        if relevant { Self::FullPass } else { Self::Skip }
    }
}

fn route_id_of(route: &HTTPRoute) -> Option<crate::translator::RouteId> {
    Some((
        route.metadata.namespace.clone()?,
        route.metadata.name.clone()?,
    ))
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

    /// `HTTPRoute` events feed the incremental path: a relevant
    /// `Apply` or `Delete` carries the route out so the loop can
    /// resolve just that route. Resyncs and odd shapes (no
    /// namespace/name) fall back to a full pass.
    fn route_action(
        &mut self,
        ev: Option<Result<watcher::Event<HTTPRoute>, watcher::Error>>,
    ) -> Action {
        match ev {
            Some(Ok(watcher::Event::Apply(route))) => {
                if !self.apply(&route) {
                    return Action::Skip;
                }
                match route_id_of(&route) {
                    Some(id) => Action::Route(id, Some(route)),
                    None => Action::FullPass,
                }
            }
            Some(Ok(watcher::Event::Delete(route))) => {
                if let Some(uid) = route.metadata.uid.as_deref() {
                    self.seen.remove(uid);
                }
                match route_id_of(&route) {
                    Some(id) => Action::Route(id, None),
                    None => Action::FullPass,
                }
            }
            other => Action::full_if(self.relevant("HTTPRoute", other)),
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
