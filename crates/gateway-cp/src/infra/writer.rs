//! Reconcile provisioned data-plane infra against the cluster.
//!
//! One task owns every apiserver write the provisioner makes:
//! server-side apply under [`FIELD_MANAGER`], forced (we own the
//! fields we send). The desired set arrives over a `watch` channel
//! from the kube watch loop; three label-filtered reflectors over
//! the managed child kinds re-trigger reconciles on drift.
//!
//! An apply is skipped when the object was last applied with
//! identical content *and* the cluster still agrees (a JSON-subset
//! check against the reflector cache), so steady-state write load is
//! zero. An existing object that is neither controller-owned by its
//! Gateway nor labeled as managed is refused, never adopted.
//! Deletion is not handled here at all: every object is
//! owner-referenced to its Gateway, so removal is the garbage
//! collector's job.

use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::NamespaceResourceScope;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount};
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::reflector::{self, ObjectRef, Store};
use kube::runtime::watcher::{self, Config};
use kube::{Client, Resource};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::watch;
use tokio::time::sleep;

use super::desired::GatewayInfra;
use super::{MANAGED_BY_LABEL, MANAGED_BY_VALUE};

/// SSA field manager for every provisioner write.
pub const FIELD_MANAGER: &str = "gateway.buoyant.io/cp";

const RETRY_INITIAL: Duration = Duration::from_millis(500);
const RETRY_MAX: Duration = Duration::from_secs(30);

/// Run the writer until `shutdown` resolves. Reconciles on every
/// desired-set change and on every event from the managed-children
/// watches; a failed pass retries with doubling backoff until a pass
/// succeeds.
pub async fn run(
    client: Client,
    mut desired_rx: watch::Receiver<Vec<GatewayInfra>>,
    shutdown: impl Future<Output = ()>,
) {
    let mut shutdown = pin!(shutdown);

    // Only objects we created carry the managed-by label, so these
    // watches see our children and nothing else.
    let managed = Config::default().labels(&format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}"));
    let (sa_store, sa_writer) = reflector::store::<ServiceAccount>();
    let mut sa_stream = reflector::reflector(
        sa_writer,
        watcher::watcher(Api::all(client.clone()), managed.clone()),
    )
    .boxed();
    let (svc_store, svc_writer) = reflector::store::<Service>();
    let mut svc_stream = reflector::reflector(
        svc_writer,
        watcher::watcher(Api::all(client.clone()), managed.clone()),
    )
    .boxed();
    let (dep_store, dep_writer) = reflector::store::<Deployment>();
    let mut dep_stream = reflector::reflector(
        dep_writer,
        watcher::watcher(Api::all(client.clone()), managed),
    )
    .boxed();

    let mut reconciler = Reconciler::new(client, sa_store, svc_store, dep_store);
    let mut retry_delay = RETRY_INITIAL;
    let mut retry_pending = false;

    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => return,
            _ = desired_rx.changed() => {}
            ev = sa_stream.next() => log_watch_err("ServiceAccount", ev.as_ref()),
            ev = svc_stream.next() => log_watch_err("Service", ev.as_ref()),
            ev = dep_stream.next() => log_watch_err("Deployment", ev.as_ref()),
            () = sleep(retry_delay), if retry_pending => {}
        }

        let desired = desired_rx.borrow_and_update().clone();
        match reconciler.reconcile(&desired).await {
            Ok(()) => {
                retry_pending = false;
                retry_delay = RETRY_INITIAL;
            }
            Err(e) => {
                tracing::warn!(error = %e, "infra reconcile failed; will retry");
                retry_pending = true;
                retry_delay = (retry_delay * 2).min(RETRY_MAX);
            }
        }
    }
}

/// One apply decision. `Refuse` is terminal for the object (warn,
/// move on): overwriting something we don't manage is never right.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    Apply,
    Skip,
    Refuse,
}

/// Applies desired objects and remembers what it last applied.
struct Reconciler {
    client: Client,
    service_accounts: Store<ServiceAccount>,
    services: Store<Service>,
    deployments: Store<Deployment>,
    /// JSON of the last successfully applied object, keyed by
    /// `(kind, namespace, name)`. Catches desired-set changes a
    /// subset check cannot see (removed fields), and keeps
    /// steady-state passes write-free.
    last_applied: HashMap<(&'static str, String, String), Value>,
}

impl Reconciler {
    fn new(
        client: Client,
        service_accounts: Store<ServiceAccount>,
        services: Store<Service>,
        deployments: Store<Deployment>,
    ) -> Self {
        Self {
            client,
            service_accounts,
            services,
            deployments,
            last_applied: HashMap::new(),
        }
    }

    /// Apply the whole desired set, `ServiceAccount` then `Service`
    /// then `Deployment` per Gateway. A failing object is logged and
    /// skipped so it can never wedge the rest of the set; the first
    /// error is returned at the end and the caller retries the pass
    /// (applies are idempotent).
    async fn reconcile(&mut self, desired: &[GatewayInfra]) -> Result<(), kube::Error> {
        let mut first_err: Option<kube::Error> = None;
        for infra in desired {
            let observed = lookup(&self.service_accounts, &infra.service_account);
            let results = [
                self.apply_one("ServiceAccount", &infra.service_account, observed)
                    .await,
                {
                    let observed = lookup(&self.services, &infra.service);
                    self.apply_one("Service", &infra.service, observed).await
                },
                {
                    let observed = lookup(&self.deployments, &infra.deployment);
                    self.apply_one("Deployment", &infra.deployment, observed)
                        .await
                },
            ];
            for result in results {
                if let Err(e) = result {
                    tracing::warn!(error = %e, "infra object apply failed; continuing with the rest");
                    first_err.get_or_insert(e);
                }
            }
        }
        self.prune_last_applied(desired);
        first_err.map_or(Ok(()), Err)
    }

    async fn apply_one<K>(
        &mut self,
        kind: &'static str,
        desired: &K,
        observed: Option<K>,
    ) -> Result<(), kube::Error>
    where
        K: Resource<Scope = NamespaceResourceScope>
            + Serialize
            + DeserializeOwned
            + Clone
            + std::fmt::Debug,
        K::DynamicType: Default,
    {
        let namespace = desired.meta().namespace.clone().unwrap_or_default();
        let name = desired.meta().name.clone().unwrap_or_default();
        let key = (kind, namespace.clone(), name.clone());
        let api: Api<K> = Api::namespaced(self.client.clone(), &namespace);

        // The child watches are label-filtered to managed objects, so
        // an unmanaged object squatting on our name is invisible to
        // the cache. On a cache miss, ask the cluster directly before
        // the first apply — otherwise the adoption guard could never
        // fire for exactly the objects it exists to protect.
        let observed = match observed {
            Some(o) => Some(o),
            None => api.get_opt(&name).await?,
        };

        let desired_json = serde_json::to_value(desired).map_err(kube::Error::SerdeError)?;
        let observed_json = observed
            .map(|o| serde_json::to_value(&o))
            .transpose()
            .map_err(kube::Error::SerdeError)?;

        match decide(
            &desired_json,
            observed_json.as_ref(),
            self.last_applied.get(&key),
        ) {
            Action::Skip => {}
            Action::Refuse => {
                tracing::warn!(
                    kind,
                    namespace,
                    name,
                    "refusing to apply over an existing object this controller does not manage"
                );
            }
            Action::Apply => {
                api.patch(
                    &name,
                    &PatchParams::apply(FIELD_MANAGER).force(),
                    &Patch::Apply(desired),
                )
                .await?;
                tracing::info!(kind, namespace, name, "applied data-plane infra object");
                self.last_applied.insert(key, desired_json);
            }
        }
        Ok(())
    }

    /// Drop memory for objects no longer in the desired set (their
    /// Gateways are gone; the GC owns the objects themselves).
    fn prune_last_applied(&mut self, desired: &[GatewayInfra]) {
        let expected: std::collections::HashSet<(&'static str, String, String)> = desired
            .iter()
            .flat_map(|i| {
                let id = |kind, meta: &kube::api::ObjectMeta| {
                    (
                        kind,
                        meta.namespace.clone().unwrap_or_default(),
                        meta.name.clone().unwrap_or_default(),
                    )
                };
                [
                    id("ServiceAccount", &i.service_account.metadata),
                    id("Service", &i.service.metadata),
                    id("Deployment", &i.deployment.metadata),
                ]
            })
            .collect();
        self.last_applied.retain(|k, _| expected.contains(k));
    }
}

/// Look `desired`'s key up in the reflector cache.
fn lookup<K>(store: &Store<K>, desired: &K) -> Option<K>
where
    K: Resource + Clone + 'static,
    K::DynamicType: Default + Clone + Eq + std::hash::Hash,
{
    let name = desired.meta().name.as_deref()?;
    let namespace = desired.meta().namespace.as_deref()?;
    store
        .get(&ObjectRef::new(name).within(namespace))
        .map(|o| (*o).clone())
}

fn decide(desired: &Value, observed: Option<&Value>, last_applied: Option<&Value>) -> Action {
    let Some(observed) = observed else {
        return Action::Apply;
    };
    if !manages(desired, observed) {
        return Action::Refuse;
    }
    if last_applied == Some(desired) && is_subset(desired, observed) {
        Action::Skip
    } else {
        Action::Apply
    }
}

/// An existing object is ours iff it carries the managed-by label or
/// a `controller: true` ownerReference with the desired owner's uid.
fn manages(desired: &Value, observed: &Value) -> bool {
    // JSON-pointer escapes '/' in the label key as '~1'.
    if observed
        .pointer("/metadata/labels/app.kubernetes.io~1managed-by")
        .and_then(Value::as_str)
        == Some(MANAGED_BY_VALUE)
    {
        return true;
    }
    let Some(owner_uid) = desired
        .pointer("/metadata/ownerReferences/0/uid")
        .and_then(Value::as_str)
    else {
        return false;
    };
    observed
        .pointer("/metadata/ownerReferences")
        .and_then(Value::as_array)
        .is_some_and(|owners| {
            owners.iter().any(|o| {
                o.get("controller").and_then(Value::as_bool) == Some(true)
                    && o.get("uid").and_then(Value::as_str) == Some(owner_uid)
            })
        })
}

/// `a ⊆ b`: every field `a` sets is present in `b` with the same
/// value. Objects recurse per key (extra keys in `b` — apiserver
/// defaults, status — are fine); arrays must match element-wise
/// (the server adds fields *within* elements, e.g. `nodePort`, but
/// never reorders an applied list).
fn is_subset(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Object(am), Value::Object(bm)) => am
            .iter()
            .all(|(k, av)| bm.get(k).is_some_and(|bv| is_subset(av, bv))),
        (Value::Array(aa), Value::Array(ba)) => {
            aa.len() == ba.len() && aa.iter().zip(ba).all(|(av, bv)| is_subset(av, bv))
        }
        _ => a == b,
    }
}

fn log_watch_err<T, E: std::fmt::Display>(kind: &str, ev: Option<&Result<T, E>>) {
    if let Some(Err(e)) = ev {
        tracing::warn!(kind, error = %e, "infra child watcher emitted error");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use http_body_util::BodyExt;
    use kube::client::Body;
    use kube::runtime::watcher::Event;
    use serde_json::json;

    use crate::infra::desired::{InfraConfig, desired};
    use gateway_api::apis::standard::gateways::{Gateway, GatewayListeners, GatewaySpec};
    use kube::api::ObjectMeta;

    // ----- is_subset -----

    #[test]
    fn subset_ignores_extra_server_fields() {
        let desired = json!({"spec": {"ports": [{"port": 80}]}});
        let observed = json!({
            "metadata": {"uid": "x", "resourceVersion": "42"},
            "spec": {"ports": [{"port": 80, "nodePort": 30080}], "clusterIP": "10.0.0.1"},
            "status": {}
        });
        assert!(is_subset(&desired, &observed));
    }

    #[test]
    fn subset_detects_changed_scalar_and_array_shape() {
        let observed = json!({"spec": {"ports": [{"port": 80}]}});
        assert!(!is_subset(
            &json!({"spec": {"ports": [{"port": 81}]}}),
            &observed
        ));
        assert!(!is_subset(
            &json!({"spec": {"ports": [{"port": 80}, {"port": 443}]}}),
            &observed
        ));
        assert!(!is_subset(&json!({"spec": {"replicas": 1}}), &observed));
    }

    // ----- decide -----

    fn managed_observed() -> Value {
        json!({"metadata": {"labels": {"app.kubernetes.io/managed-by": "gateway.buoyant.io"}}})
    }

    fn desired_value() -> Value {
        json!({"metadata": {"ownerReferences": [{"controller": true, "uid": "uid-1"}]}})
    }

    #[test]
    fn decide_missing_object_applies() {
        assert_eq!(decide(&desired_value(), None, None), Action::Apply);
    }

    #[test]
    fn decide_refuses_unmanaged_object() {
        let foreign = json!({
            "metadata": {
                "labels": {"app": "user-thing"},
                "ownerReferences": [{"controller": true, "uid": "someone-else"}]
            }
        });
        assert_eq!(
            decide(&desired_value(), Some(&foreign), None),
            Action::Refuse
        );
    }

    #[test]
    fn decide_owner_uid_match_counts_as_managed() {
        let observed = json!({
            "metadata": {"ownerReferences": [{"controller": true, "uid": "uid-1"}]}
        });
        let desired = desired_value();
        // Managed but never applied by us and not a subset: Apply.
        assert_eq!(decide(&desired, Some(&observed), None), Action::Apply);
    }

    #[test]
    fn decide_skips_only_when_memory_and_cluster_agree() {
        let desired = json!({"metadata": {"labels": {
            "app.kubernetes.io/managed-by": "gateway.buoyant.io"
        }}});
        let observed = managed_observed();
        // Cluster agrees + identical last apply: Skip.
        assert_eq!(
            decide(&desired, Some(&observed), Some(&desired.clone())),
            Action::Skip
        );
        // Desired changed since the last apply (e.g. a field was
        // *removed*, which the subset check can't see): Apply.
        let stale = json!({"old": true});
        assert_eq!(
            decide(&desired, Some(&observed), Some(&stale)),
            Action::Apply
        );
        // No memory of a previous apply (restart): Apply once.
        assert_eq!(decide(&desired, Some(&observed), None), Action::Apply);
    }

    // ----- Reconciler against a mock apiserver -----

    fn gateway(ns: &str, name: &str) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                uid: Some("uid-1234".into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "buoyant-gateway".into(),
                listeners: vec![GatewayListeners {
                    name: "http".into(),
                    protocol: "HTTP".into(),
                    port: 80,
                    ..Default::default()
                }],
                ..Default::default()
            },
            status: None,
        }
    }

    fn infra(ns: &str, name: &str) -> GatewayInfra {
        let cfg = InfraConfig {
            dp_image: "gateway-data-plane:latest".into(),
            cp_url: "http://cp:8443".into(),
            admin_port: 15021,
        };
        desired(&gateway(ns, name), &cfg).expect("provisioned")
    }

    /// Per-path-substring scripting for the mock apiserver.
    #[derive(Default)]
    struct MockBehavior {
        /// `GET`s whose path contains the key return this object;
        /// everything else 404s (kube maps that to `None`).
        get: HashMap<&'static str, Value>,
        /// `PATCH`es whose path contains the key fail with this
        /// status code; everything else echoes the body back.
        patch_fail: HashMap<&'static str, u16>,
    }

    fn status_json(code: u16, reason: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "kind": "Status",
            "apiVersion": "v1",
            "metadata": {},
            "status": "Failure",
            "message": reason,
            "reason": reason,
            "code": code,
        }))
        .unwrap()
    }

    /// Mock apiserver: records `METHOD path` lines; behavior per
    /// [`MockBehavior`].
    fn mock_client(requests: Arc<Mutex<Vec<String>>>, behavior: MockBehavior) -> Client {
        let (service, mut handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        tokio::spawn(async move {
            while let Some((req, respond)) = handle.next_request().await {
                let path = req.uri().path().to_string();
                requests
                    .lock()
                    .unwrap()
                    .push(format!("{} {path}", req.method()));

                let response = if req.method() == http::Method::GET {
                    match behavior.get.iter().find(|(k, _)| path.contains(*k)) {
                        Some((_, obj)) => http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(Body::from(serde_json::to_vec(obj).unwrap()))
                            .unwrap(),
                        None => http::Response::builder()
                            .status(404)
                            .header("content-type", "application/json")
                            .body(Body::from(status_json(404, "NotFound")))
                            .unwrap(),
                    }
                } else if let Some((_, code)) =
                    behavior.patch_fail.iter().find(|(k, _)| path.contains(*k))
                {
                    http::Response::builder()
                        .status(*code)
                        .header("content-type", "application/json")
                        .body(Body::from(status_json(*code, "Invalid")))
                        .unwrap()
                } else {
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_vec()))
                        .unwrap()
                };
                respond.send_response(response);
            }
        });
        Client::new(service, "default")
    }

    struct Fixture {
        reconciler: Reconciler,
        requests: Arc<Mutex<Vec<String>>>,
        sa_writer: reflector::store::Writer<ServiceAccount>,
        svc_writer: reflector::store::Writer<Service>,
        dep_writer: reflector::store::Writer<Deployment>,
    }

    fn fixture() -> Fixture {
        fixture_with(MockBehavior::default())
    }

    fn fixture_with(behavior: MockBehavior) -> Fixture {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let client = mock_client(requests.clone(), behavior);
        let (sa_store, sa_writer) = reflector::store();
        let (svc_store, svc_writer) = reflector::store();
        let (dep_store, dep_writer) = reflector::store();
        Fixture {
            reconciler: Reconciler::new(client, sa_store, svc_store, dep_store),
            requests,
            sa_writer,
            svc_writer,
            dep_writer,
        }
    }

    #[tokio::test]
    async fn empty_cluster_applies_all_objects_in_order() {
        let mut fx = fixture();
        fx.reconciler
            .reconcile(&[infra("demo", "web")])
            .await
            .unwrap();

        // Each cache miss checks the cluster (adoption guard) before
        // the apply.
        let requests = fx.requests.lock().unwrap().clone();
        assert_eq!(
            requests,
            vec![
                "GET /api/v1/namespaces/demo/serviceaccounts/web-gatewayd".to_string(),
                "PATCH /api/v1/namespaces/demo/serviceaccounts/web-gatewayd".to_string(),
                "GET /api/v1/namespaces/demo/services/web-gatewayd".to_string(),
                "PATCH /api/v1/namespaces/demo/services/web-gatewayd".to_string(),
                "GET /apis/apps/v1/namespaces/demo/deployments/web-gatewayd".to_string(),
                "PATCH /apis/apps/v1/namespaces/demo/deployments/web-gatewayd".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn second_pass_with_agreeing_cache_writes_nothing() {
        let mut fx = fixture();
        let set = vec![infra("demo", "web")];
        fx.reconciler.reconcile(&set).await.unwrap();
        assert_eq!(fx.requests.lock().unwrap().len(), 6);

        // Feed the reflector caches what the "cluster" now holds —
        // exactly what we applied.
        fx.sa_writer
            .apply_watcher_event(&Event::Apply(set[0].service_account.clone()));
        fx.svc_writer
            .apply_watcher_event(&Event::Apply(set[0].service.clone()));
        fx.dep_writer
            .apply_watcher_event(&Event::Apply(set[0].deployment.clone()));

        fx.reconciler.reconcile(&set).await.unwrap();
        assert_eq!(
            fx.requests.lock().unwrap().len(),
            6,
            "steady-state pass must be request-free"
        );
    }

    #[tokio::test]
    async fn drifted_object_is_reapplied() {
        let mut fx = fixture();
        let set = vec![infra("demo", "web")];
        fx.reconciler.reconcile(&set).await.unwrap();

        // Cluster state drifted on the Deployment (replicas bumped by
        // hand); SA and Service agree.
        let mut drifted = set[0].deployment.clone();
        drifted.spec.as_mut().unwrap().replicas = Some(3);
        fx.sa_writer
            .apply_watcher_event(&Event::Apply(set[0].service_account.clone()));
        fx.svc_writer
            .apply_watcher_event(&Event::Apply(set[0].service.clone()));
        fx.dep_writer.apply_watcher_event(&Event::Apply(drifted));

        fx.reconciler.reconcile(&set).await.unwrap();
        let requests = fx.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 7);
        assert_eq!(
            requests[6],
            "PATCH /apis/apps/v1/namespaces/demo/deployments/web-gatewayd"
        );
    }

    #[tokio::test]
    async fn unmanaged_existing_object_is_refused_but_others_apply() {
        let mut fx = fixture();

        // A user Service already owns the target name: no managed-by
        // label, no owner ref.
        let user_service = Service {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some("web-gatewayd".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        fx.svc_writer
            .apply_watcher_event(&Event::Apply(user_service));

        fx.reconciler
            .reconcile(&[infra("demo", "web")])
            .await
            .unwrap();
        let requests = fx.requests.lock().unwrap().clone();
        assert_eq!(
            requests,
            vec![
                "GET /api/v1/namespaces/demo/serviceaccounts/web-gatewayd".to_string(),
                "PATCH /api/v1/namespaces/demo/serviceaccounts/web-gatewayd".to_string(),
                "GET /apis/apps/v1/namespaces/demo/deployments/web-gatewayd".to_string(),
                "PATCH /apis/apps/v1/namespaces/demo/deployments/web-gatewayd".to_string(),
            ],
            "the squatted Service must not be touched"
        );
    }

    #[tokio::test]
    async fn squatter_invisible_to_the_filtered_cache_is_still_refused() {
        // The child watches filter on the managed-by label, so an
        // unmanaged Service on our name never enters the cache. The
        // pre-apply live GET must catch it.
        let squatter = Service {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some("web-gatewayd".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut behavior = MockBehavior::default();
        behavior
            .get
            .insert("/services/", serde_json::to_value(&squatter).unwrap());
        let mut fx = fixture_with(behavior);

        fx.reconciler
            .reconcile(&[infra("demo", "web")])
            .await
            .unwrap();

        let requests = fx.requests.lock().unwrap().clone();
        assert!(
            !requests
                .iter()
                .any(|r| r.starts_with("PATCH") && r.contains("/services/")),
            "squatted Service must not be applied over: {requests:?}"
        );
        assert!(
            requests
                .iter()
                .any(|r| r.starts_with("PATCH") && r.contains("/deployments/")),
            "siblings must still apply: {requests:?}"
        );
    }

    #[tokio::test]
    async fn failing_object_does_not_block_the_rest() {
        // The Service apply is rejected by the apiserver (as a real
        // 422 would); the Deployment must still be applied and the
        // pass must report the error for retry.
        let mut behavior = MockBehavior::default();
        behavior.patch_fail.insert("/services/", 422);
        let mut fx = fixture_with(behavior);

        let result = fx.reconciler.reconcile(&[infra("demo", "web")]).await;
        assert!(result.is_err(), "the failed apply must surface for retry");

        let requests = fx.requests.lock().unwrap().clone();
        assert!(
            requests
                .iter()
                .any(|r| r.starts_with("PATCH") && r.contains("/deployments/")),
            "objects after the failure must still apply: {requests:?}"
        );
    }
}
