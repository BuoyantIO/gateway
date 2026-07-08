//! Data-plane provisioner lifecycle: what the CP creates for an
//! owned `Gateway`, how it repairs drift, what it refuses to touch,
//! and what deleting the Gateway leaves behind. No traffic is driven
//! here — the routing suite already covers provisioned data paths.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_e2e::fixtures::apply_gateway;
use gateway_e2e::{Scope, gateway};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Service, ServiceAccount, ServicePort, ServiceSpec};
use kube::api::{Api, DeleteParams, ObjectMeta, PostParams};
use kube::{Client, ResourceExt};

const POLL: Duration = Duration::from_millis(250);
const DEADLINE: Duration = Duration::from_mins(1);

/// Poll `api` until `name` exists and satisfies `pred`.
async fn wait_for<K, F>(api: &Api<K>, name: &str, what: &str, pred: F) -> Result<K>
where
    K: Clone + std::fmt::Debug + serde::de::DeserializeOwned,
    F: Fn(&K) -> bool,
{
    let deadline = std::time::Instant::now() + DEADLINE;
    loop {
        if let Some(obj) = api.get_opt(name).await?
            && pred(&obj)
        {
            return Ok(obj);
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(POLL).await;
    }
}

/// Poll `api` until `name` is gone.
async fn wait_gone<K>(api: &Api<K>, name: &str, what: &str) -> Result<()>
where
    K: Clone + std::fmt::Debug + serde::de::DeserializeOwned,
{
    let deadline = std::time::Instant::now() + DEADLINE;
    loop {
        if api.get_opt(name).await?.is_none() {
            return Ok(());
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what} to be deleted"
        );
        tokio::time::sleep(POLL).await;
    }
}

fn assert_managed(meta: &kube::api::ObjectMeta, gw_name: &str) {
    let labels = meta.labels.as_ref().expect("labels present");
    assert_eq!(
        labels
            .get("app.kubernetes.io/managed-by")
            .map(String::as_str),
        Some("gateway.buoyant.io")
    );
    assert_eq!(
        labels
            .get("gateway.networking.k8s.io/gateway-name")
            .map(String::as_str),
        Some(gw_name)
    );
    let owner = &meta.owner_references.as_ref().expect("owner refs")[0];
    assert_eq!(owner.kind, "Gateway");
    assert_eq!(owner.name, gw_name);
    assert_eq!(owner.controller, Some(true));
}

fn apis(client: &Client, ns: &str) -> (Api<ServiceAccount>, Api<Service>, Api<Deployment>) {
    (
        Api::namespaced(client.clone(), ns),
        Api::namespaced(client.clone(), ns),
        Api::namespaced(client.clone(), ns),
    )
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn gateway_provisions_ready_dp_and_gc_cleans_up() -> Result<()> {
    let scope = Scope::new("prov-life").await?;
    let ns = scope.name();
    let client = scope.client();
    let (sa_api, svc_api, dep_api) = apis(client, ns);

    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;

    // The Deployment converges to an available replica — this walks
    // the whole chain: provisioning, image, config bootstrap, and
    // the readiness probe flipping the pod Ready.
    let deployment = wait_for(&dep_api, "gw-gatewayd", "DP deployment available", |d| {
        d.status.as_ref().and_then(|s| s.available_replicas) == Some(1)
    })
    .await?;
    assert_managed(&deployment.metadata, "gw");

    let service = wait_for(&svc_api, "gw-gatewayd", "provisioned service", |_| true).await?;
    assert_managed(&service.metadata, "gw");
    let spec = service.spec.as_ref().expect("service spec");
    // The provisioner's default Service type.
    assert_eq!(spec.type_.as_deref(), Some("LoadBalancer"));
    let ports: Vec<i32> = spec.ports.iter().flatten().map(|p| p.port).collect();
    assert_eq!(ports, vec![80]);

    let sa = wait_for(
        &sa_api,
        "gw-gatewayd",
        "provisioned service account",
        |_| true,
    )
    .await?;
    assert_managed(&sa.metadata, "gw");

    // Deleting the Gateway garbage-collects the whole set: the
    // provisioner has no delete path by design.
    Api::<Gateway>::namespaced(client.clone(), ns)
        .delete("gw", &DeleteParams::default())
        .await?;
    wait_gone(&dep_api, "gw-gatewayd", "DP deployment").await?;
    wait_gone(&svc_api, "gw-gatewayd", "provisioned service").await?;
    wait_gone(&sa_api, "gw-gatewayd", "provisioned service account").await?;

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn deleted_managed_service_is_recreated() -> Result<()> {
    let scope = Scope::new("prov-drift").await?;
    let ns = scope.name();
    let client = scope.client();
    let svc_api: Api<Service> = Api::namespaced(client.clone(), ns);

    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let before = wait_for(&svc_api, "gw-gatewayd", "provisioned service", |_| true).await?;
    let old_uid = before.uid().expect("uid");

    svc_api
        .delete("gw-gatewayd", &DeleteParams::default())
        .await?;

    // The writer watches its managed children; the delete event
    // triggers a reconcile that recreates the Service (new uid).
    wait_for(
        &svc_api,
        "gw-gatewayd",
        "service recreated after drift",
        |s| s.uid().is_some_and(|u| u != old_uid),
    )
    .await?;

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn self_managed_gateway_provisions_nothing() -> Result<()> {
    let scope = Scope::new("prov-optout").await?;
    let ns = scope.name();
    let client = scope.client();
    let (sa_api, svc_api, dep_api) = apis(client, ns);

    let mut gw = gateway(ns, "gw", 80, None);
    gw.metadata
        .annotations
        .get_or_insert_with(BTreeMap::new)
        .insert(
            "gateway.buoyant.io/provisioning".to_owned(),
            "disabled".to_owned(),
        );
    apply_gateway(client, &gw).await?;

    // Negative check: give the CP ample time to (wrongly) act — it
    // reacts to events within milliseconds, so 10s is generous.
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(dep_api.get_opt("gw-gatewayd").await?.is_none());
    assert!(svc_api.get_opt("gw-gatewayd").await?.is_none());
    assert!(sa_api.get_opt("gw-gatewayd").await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn squatted_service_is_refused_but_siblings_apply() -> Result<()> {
    let scope = Scope::new("prov-squat").await?;
    let ns = scope.name();
    let client = scope.client();
    let (sa_api, svc_api, dep_api) = apis(client, ns);

    // A user Service already owns the name the provisioner wants —
    // no managed-by label, no owner ref, a recognizable port.
    let squatter = Service {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some("gw-gatewayd".into()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            ports: Some(vec![ServicePort {
                port: 9999,
                ..Default::default()
            }]),
            ..Default::default()
        }),
        status: None,
    };
    svc_api.create(&PostParams::default(), &squatter).await?;

    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;

    // The siblings still provision...
    wait_for(&dep_api, "gw-gatewayd", "DP deployment", |_| true).await?;
    wait_for(
        &sa_api,
        "gw-gatewayd",
        "provisioned service account",
        |_| true,
    )
    .await?;

    // ...while the squatted Service is refused, never applied over.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let untouched = svc_api.get("gw-gatewayd").await?;
    let ports: Vec<i32> = untouched
        .spec
        .as_ref()
        .and_then(|s| s.ports.as_ref())
        .map(|p| p.iter().map(|p| p.port).collect())
        .unwrap_or_default();
    assert_eq!(ports, vec![9999], "squatted Service must not be modified");
    assert!(
        untouched
            .labels()
            .get("app.kubernetes.io/managed-by")
            .is_none(),
        "squatted Service must not be adopted"
    );

    Ok(())
}
