//! The status writer task: the only place status writes happen.
//!
//! Consumes [`StatusWork`] from a `watch` channel (latest wins — a
//! burst of translate passes collapses into one reconcile) and
//! writes through the status subresource with `replace_status`,
//! conflict-checked by the observed object's `resourceVersion`. A
//! 409 means our cached view was stale: re-read, re-reconcile
//! (usually the fresh status is already equal and the write is
//! skipped), retry a bounded number of times. Semantically unchanged
//! statuses are never written — that equality skip is what breaks
//! the loop of our own writes waking our own watches.
//!
//! A failed pass retries with doubling backoff, per-object errors
//! are isolated (one broken object cannot wedge the rest), and the
//! writer never blocks config publication — it lives on the other
//! side of the channel.

use std::fmt::Debug;
use std::future::Future;
use std::pin::pin;
use std::time::Duration;

use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use kube::api::{Api, PostParams};
use kube::{Client, Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::watch;
use tokio::time::sleep;

use super::build::{
    StatusWork, reconcile_backend_binding_status, reconcile_gateway_backend_status,
    reconcile_gateway_class_status, reconcile_gateway_status,
};
use crate::crd::{BackendBinding, GatewayBackend};

const RETRY_INITIAL: Duration = Duration::from_millis(500);
const RETRY_MAX: Duration = Duration::from_secs(30);
/// Conflict (409) retries per object within one pass; the pass-level
/// backoff picks up from there.
const CONFLICT_RETRIES: usize = 3;

/// Run the writer until `shutdown` resolves. Only the leader writes;
/// while following, work (and retries) sit parked until promotion.
pub async fn run(
    client: Client,
    mut work_rx: watch::Receiver<StatusWork>,
    mut is_leader: watch::Receiver<bool>,
    shutdown: impl Future<Output = ()>,
) {
    let mut shutdown = pin!(shutdown);
    let mut retry_delay = RETRY_INITIAL;
    let mut retry_pending = false;

    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => return,
            _ = is_leader.changed() => {}
            _ = work_rx.changed() => {}
            () = sleep(retry_delay), if retry_pending => {}
        }

        // Guards the retry loop too: a demoted leader must not keep
        // retrying stale work against the new leader's writes.
        if !*is_leader.borrow_and_update() {
            continue;
        }

        let work = work_rx.borrow_and_update().clone();
        match write_all(&client, &work).await {
            Ok(()) => {
                retry_pending = false;
                retry_delay = RETRY_INITIAL;
            }
            Err(e) => {
                tracing::warn!(error = %e, "status pass failed; will retry");
                retry_pending = true;
                retry_delay = (retry_delay * 2).min(RETRY_MAX);
            }
        }
    }
}

/// One pass over the whole work set. Per-object failures are logged
/// and skipped; the first error is returned so the caller retries
/// the pass (writes are idempotent under the equality skip).
async fn write_all(client: &Client, work: &StatusWork) -> Result<(), kube::Error> {
    let mut first_err: Option<kube::Error> = None;

    for (observed, desired) in &work.gateway_classes {
        let api: Api<GatewayClass> = Api::all(client.clone());
        let result = write_object(
            &api,
            observed,
            desired.clone(),
            |gc| &mut gc.status,
            reconcile_gateway_class_status,
        )
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, kind = "GatewayClass", name = observed.name_any(),
                "status write failed; continuing with the rest");
            first_err.get_or_insert(e);
        }
    }

    for (observed, desired) in &work.gateways {
        let namespace = observed.namespace().unwrap_or_default();
        let api: Api<Gateway> = Api::namespaced(client.clone(), &namespace);
        let result = write_object(
            &api,
            observed,
            desired.clone(),
            |gw| &mut gw.status,
            reconcile_gateway_status,
        )
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, kind = "Gateway", namespace, name = observed.name_any(),
                "status write failed; continuing with the rest");
            first_err.get_or_insert(e);
        }
    }

    for (observed, desired) in &work.gateway_backends {
        let namespace = observed.namespace().unwrap_or_default();
        let api: Api<GatewayBackend> = Api::namespaced(client.clone(), &namespace);
        let result = write_object(
            &api,
            observed,
            desired.clone(),
            |gb| &mut gb.status,
            reconcile_gateway_backend_status,
        )
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, kind = "GatewayBackend", namespace,
                name = observed.name_any(),
                "status write failed; continuing with the rest");
            first_err.get_or_insert(e);
        }
    }

    for (observed, desired) in &work.backend_bindings {
        let namespace = observed.namespace().unwrap_or_default();
        let api: Api<BackendBinding> = Api::namespaced(client.clone(), &namespace);
        let result = write_object(
            &api,
            observed,
            desired.clone(),
            |bb| &mut bb.status,
            reconcile_backend_binding_status,
        )
        .await;
        if let Err(e) = result {
            tracing::warn!(error = %e, kind = "BackendBinding", namespace,
                name = observed.name_any(),
                "status write failed; continuing with the rest");
            first_err.get_or_insert(e);
        }
    }

    first_err.map_or(Ok(()), Err)
}

/// Reconcile `desired` against the observed status and, when a write
/// is needed, `replace_status` with conflict retries: each 409
/// re-reads the object and re-reconciles against the fresh status —
/// which usually reports "already equal" and ends the loop without a
/// write.
async fn write_object<K, S, FS, FR>(
    api: &Api<K>,
    observed: &K,
    desired: S,
    status_of: FS,
    reconcile: FR,
) -> Result<(), kube::Error>
where
    K: Resource + Clone + Serialize + DeserializeOwned + Debug,
    S: Clone,
    FS: Fn(&mut K) -> &mut Option<S>,
    FR: Fn(S, Option<&S>) -> Option<S>,
{
    let name = observed.name_any();
    let mut object = observed.clone();

    for attempt in 0..=CONFLICT_RETRIES {
        let Some(final_status) = reconcile(desired.clone(), status_of(&mut object).as_ref()) else {
            return Ok(()); // semantically equal — nothing to write
        };
        *status_of(&mut object) = Some(final_status);

        match api
            .replace_status(&name, &PostParams::default(), &object)
            .await
        {
            Ok(_) => {
                tracing::info!(name, "status written");
                return Ok(());
            }
            Err(kube::Error::Api(ae)) if ae.code == 409 && attempt < CONFLICT_RETRIES => {
                // Our cached resourceVersion was stale; re-read and
                // re-reconcile against what is actually there.
                object = api.get(&name).await?;
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!("loop returns on success, equality, or error");
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use gateway_api::apis::standard::gateways::{GatewaySpec, GatewayStatus};
    use http_body_util::BodyExt;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
    use kube::api::ObjectMeta;
    use kube::client::Body;

    fn t(secs: i64) -> Time {
        Time(k8s_openapi::jiff::Timestamp::from_second(secs).unwrap())
    }

    fn cond(status: &str, now: &Time) -> Condition {
        Condition {
            type_: "Programmed".into(),
            status: status.into(),
            reason: "Programmed".into(),
            message: "test".into(),
            observed_generation: Some(1),
            last_transition_time: now.clone(),
        }
    }

    fn gw_status(status: &str, now: &Time) -> GatewayStatus {
        GatewayStatus {
            conditions: Some(vec![cond(status, now)]),
            ..Default::default()
        }
    }

    fn gw(status: Option<GatewayStatus>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some("gw".into()),
                resource_version: Some("1".into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "zd".into(),
                ..Default::default()
            },
            status,
        }
    }

    /// Scripted responses, popped per request; `Echo` returns the
    /// request body (what a successful write does).
    enum Scripted {
        Echo,
        Status(u16),
        Object(Vec<u8>),
    }

    fn mock_client(requests: Arc<Mutex<Vec<String>>>, script: Vec<Scripted>) -> Client {
        let script = Arc::new(Mutex::new(VecDeque::from(script)));
        let (service, mut handle) =
            tower_test::mock::pair::<http::Request<Body>, http::Response<Body>>();
        tokio::spawn(async move {
            while let Some((req, respond)) = handle.next_request().await {
                requests
                    .lock()
                    .unwrap()
                    .push(format!("{} {}", req.method(), req.uri().path()));
                let action = script.lock().unwrap().pop_front().unwrap_or(Scripted::Echo);
                let response = match action {
                    Scripted::Echo => {
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        http::Response::builder()
                            .status(200)
                            .header("content-type", "application/json")
                            .body(Body::from(body.to_vec()))
                            .unwrap()
                    }
                    Scripted::Status(code) => http::Response::builder()
                        .status(code)
                        .header("content-type", "application/json")
                        .body(Body::from(
                            serde_json::to_vec(&serde_json::json!({
                                "kind": "Status",
                                "apiVersion": "v1",
                                "metadata": {},
                                "status": "Failure",
                                "message": "scripted",
                                "reason": if code == 409 { "Conflict" } else { "Invalid" },
                                "code": code,
                            }))
                            .unwrap(),
                        ))
                        .unwrap(),
                    Scripted::Object(bytes) => http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(Body::from(bytes))
                        .unwrap(),
                };
                respond.send_response(response);
            }
        });
        Client::new(service, "default")
    }

    #[tokio::test]
    async fn writes_changed_objects_and_skips_equal_ones() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let client = mock_client(requests.clone(), vec![Scripted::Echo, Scripted::Echo]);

        let gc = GatewayClass {
            metadata: ObjectMeta {
                name: Some("zd".into()),
                resource_version: Some("1".into()),
                ..Default::default()
            },
            spec: gateway_api::apis::standard::gatewayclasses::GatewayClassSpec {
                controller_name: "gateway.buoyant.io/controller".into(),
                ..Default::default()
            },
            status: None,
        };
        let gc_desired = gateway_api::apis::standard::gatewayclasses::GatewayClassStatus {
            conditions: Some(vec![cond("True", &t(200))]),
            supported_features: None,
        };
        let mut changed = gw(None);
        changed.metadata.name = Some("gw2".into());

        let work = StatusWork {
            gateway_classes: vec![(gc, gc_desired)],
            gateways: vec![
                // Same conditions on an older clock: semantically
                // equal, must produce no request at all.
                (
                    gw(Some(gw_status("True", &t(100)))),
                    gw_status("True", &t(200)),
                ),
                // No status yet: written once.
                (changed, gw_status("True", &t(200))),
            ],
            gateway_backends: vec![],
            backend_bindings: vec![],
        };
        write_all(&client, &work).await.unwrap();

        assert_eq!(
            requests.lock().unwrap().clone(),
            vec![
                "PUT /apis/gateway.networking.k8s.io/v1/gatewayclasses/zd/status".to_string(),
                "PUT /apis/gateway.networking.k8s.io/v1/namespaces/demo/gateways/gw2/status"
                    .to_string(),
            ],
            "exactly one write per changed object; the equal gateway never hits the wire"
        );
    }

    #[tokio::test]
    async fn conflict_rereads_then_retries_or_skips() {
        // Ending one: the fresh object still differs -> second PUT.
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut fresh = gw(Some(gw_status("False", &t(50))));
        fresh.metadata.resource_version = Some("2".into());
        let client = mock_client(
            requests.clone(),
            vec![
                Scripted::Status(409),
                Scripted::Object(serde_json::to_vec(&fresh).unwrap()),
                Scripted::Echo,
            ],
        );
        let work = StatusWork {
            gateway_classes: vec![],
            gateways: vec![(gw(None), gw_status("True", &t(200)))],
            gateway_backends: vec![],
            backend_bindings: vec![],
        };
        write_all(&client, &work).await.unwrap();
        let seen = requests.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert!(
            seen[0].starts_with("PUT") && seen[1].starts_with("GET") && seen[2].starts_with("PUT")
        );

        // Ending two: the fresh object already matches -> no retry PUT.
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut fresh = gw(Some(gw_status("True", &t(50))));
        fresh.metadata.resource_version = Some("2".into());
        let client = mock_client(
            requests.clone(),
            vec![
                Scripted::Status(409),
                Scripted::Object(serde_json::to_vec(&fresh).unwrap()),
            ],
        );
        write_all(&client, &work).await.unwrap();
        let seen = requests.lock().unwrap().clone();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(seen[1].starts_with("GET"));
    }

    #[tokio::test]
    async fn failing_object_does_not_block_the_rest() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        // First gateway's write is rejected outright (422); the
        // second still writes; the pass reports the error.
        let client = mock_client(
            requests.clone(),
            vec![Scripted::Status(422), Scripted::Echo],
        );

        let mut other = gw(None);
        other.metadata.name = Some("gw2".into());
        let work = StatusWork {
            gateway_classes: vec![],
            gateways: vec![
                (gw(None), gw_status("True", &t(200))),
                (other, gw_status("True", &t(200))),
            ],
            gateway_backends: vec![],
            backend_bindings: vec![],
        };
        let result = write_all(&client, &work).await;
        assert!(result.is_err(), "the failed write must surface for retry");

        let seen = requests.lock().unwrap().clone();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(seen[1].contains("/gateways/gw2/status"));
    }
}
