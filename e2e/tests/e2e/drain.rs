//! Data-plane graceful drain: deleting the DP pod must let in-flight
//! requests finish (the request rides a connection into the old pod,
//! which drains before exiting), and the pod must actually honor
//! SIGTERM — terminating in seconds, not riding out the grace period
//! to SIGKILL.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use gateway_e2e::fixtures::{apply_gateway, apply_http_route};
use gateway_e2e::{Scope, deploy_echo, gateway, gateway_address, http_route, wait_until_routed};
use http::StatusCode;
use k8s_openapi::api::core::v1::Pod;
use kube::Api;
use kube::api::{DeleteParams, ListParams};

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn in_flight_request_survives_dp_pod_deletion() -> Result<()> {
    let scope = Scope::new("drain").await?;
    let ns = scope.name();
    let client = scope.client();

    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .path_prefix("/")
            .backend("echo", 8080)
            .build(),
    )
    .await?;
    wait_until_routed(&addr, "any.example", "/", StatusCode::OK).await?;

    // A request the echo backend holds open for 4s; long enough for
    // the pod deletion below to land under it.
    let slow = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let url = format!("http://{addr}/?delay-ms=4000");
    let in_flight = tokio::spawn(
        slow.get(url)
            .header("host", "any.example")
            .header("connection", "close")
            .send(),
    );

    // Let it get in flight, then delete the DP pod (default grace:
    // SIGTERM, which the DP must handle by draining).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    let dp_pods = pods
        .list(&ListParams::default().labels("gateway.networking.k8s.io/gateway-name=gw"))
        .await?;
    let dp_pod = dp_pods
        .items
        .first()
        .and_then(|p| p.metadata.name.clone())
        .context("no DP pod found")?;
    let deleted_at = Instant::now();
    pods.delete(&dp_pod, &DeleteParams::default()).await?;

    // The in-flight request completes despite the deletion.
    let resp = in_flight.await?.context("in-flight request failed")?;
    ensure!(
        resp.status() == StatusCode::OK,
        "in-flight request got {}",
        resp.status()
    );

    // SIGTERM is honored: the old pod is gone well before the 30s
    // grace period a SIGKILL-only shutdown would ride out.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match pods.get_opt(&dp_pod).await? {
            None => break,
            Some(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Some(_) => anyhow::bail!(
                "DP pod still present {:?} after delete",
                deleted_at.elapsed()
            ),
        }
    }

    // The replacement pod serves.
    wait_until_routed(&addr, "any.example", "/", StatusCode::OK).await?;
    Ok(())
}
