//! Gateway status writeback, end to end: the exact reads the
//! benchmark harnesses perform. No traffic is driven — the routing
//! suite covers data paths; this covers what `kubectl get gtw`
//! reports.

use std::time::Duration;

use anyhow::Result;
use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_e2e::fixtures::{apply_gateway, apply_http_route};
use gateway_e2e::{Scope, gateway, http_route};
use kube::ResourceExt;
use kube::api::{Api, DeleteParams};

const POLL: Duration = Duration::from_millis(250);
const DEADLINE: Duration = Duration::from_mins(1);

/// Poll until the Gateway's status satisfies `pred`.
async fn wait_for_status<F>(api: &Api<Gateway>, name: &str, what: &str, pred: F) -> Result<Gateway>
where
    F: Fn(&Gateway) -> bool,
{
    let deadline = std::time::Instant::now() + DEADLINE;
    loop {
        if let Some(gw) = api.get_opt(name).await?
            && pred(&gw)
        {
            return Ok(gw);
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(POLL).await;
    }
}

fn attached_routes(gw: &Gateway) -> Option<i32> {
    Some(
        gw.status
            .as_ref()?
            .listeners
            .as_ref()?
            .first()?
            .attached_routes,
    )
}

fn condition_true(gw: &Gateway, type_: &str) -> bool {
    gw.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .is_some_and(|c| c.iter().any(|c| c.type_ == type_ && c.status == "True"))
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn gateway_status_reflects_the_world() -> Result<()> {
    let scope = Scope::new("status").await?;
    let ns = scope.name();
    let client = scope.client();
    let gw_api: Api<Gateway> = Api::namespaced(client.clone(), ns);

    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;

    // Fresh gateway: accepted, programmed, addressed (the managed
    // Service's ClusterIP), listeners present with zero routes.
    let gw = wait_for_status(&gw_api, "gw", "fresh gateway status", |gw| {
        condition_true(gw, "Accepted")
            && condition_true(gw, "Programmed")
            && gw
                .status
                .as_ref()
                .and_then(|s| s.addresses.as_ref())
                .is_some_and(|a| !a.is_empty())
            && attached_routes(gw) == Some(0)
    })
    .await?;
    let address = gw.status.as_ref().unwrap().addresses.as_ref().unwrap()[0].clone();
    assert_eq!(address.r#type.as_deref(), Some("IPAddress"));

    // The class we own is accepted.
    let class_api: Api<GatewayClass> = Api::all(client.clone());
    let class = class_api.get("buoyant-gateway").await?;
    assert!(
        class
            .status
            .as_ref()
            .and_then(|s| s.conditions.as_ref())
            .is_some_and(|c| c
                .iter()
                .any(|c| c.type_ == "Accepted" && c.status == "True")),
        "GatewayClass must be Accepted"
    );

    // attachedRoutes tracks route churn: 0 -> 2 -> 0. The backend
    // doesn't need to exist — attachment ignores backend validity.
    for name in ["route-a", "route-b"] {
        apply_http_route(
            client,
            &http_route(ns, "gw", name)
                .path_prefix("/")
                .backend("echo", 8080)
                .build(),
        )
        .await?;
    }
    wait_for_status(&gw_api, "gw", "attachedRoutes == 2", |gw| {
        attached_routes(gw) == Some(2)
    })
    .await?;

    let route_api: Api<gateway_api::apis::standard::httproutes::HTTPRoute> =
        Api::namespaced(client.clone(), ns);
    for name in ["route-a", "route-b"] {
        route_api.delete(name, &DeleteParams::default()).await?;
    }
    let gw = wait_for_status(&gw_api, "gw", "attachedRoutes == 0", |gw| {
        attached_routes(gw) == Some(0)
    })
    .await?;

    // No flapping: an idle gateway must not be rewritten.
    let rv = gw.resource_version();
    tokio::time::sleep(Duration::from_secs(10)).await;
    let after = gw_api.get("gw").await?;
    assert_eq!(
        rv,
        after.resource_version(),
        "status writer must not touch an unchanged gateway"
    );

    Ok(())
}
