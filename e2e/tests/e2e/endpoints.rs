//! Per-pod endpoint tests: the CP resolves backends from
//! `EndpointSlice`s, so scaling the backing Deployment changes the
//! endpoint set the data plane balances across. The echo backend
//! reports the serving pod in `x-echo-pod`.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::Result;
use gateway_e2e::fixtures::{apply_gateway, apply_http_route};
use gateway_e2e::{
    Driver, Scope, deploy_echo, gateway, gateway_address, http_route, scale_deployment,
    wait_until_routed,
};
use http::StatusCode;
use k8s_openapi::api::core::v1::Pod;
use kube::Api;
use kube::api::ListParams;
use reqwest::header::HeaderMap;

const HOST: &str = "app.example";

/// Generous: scaling up pays image pull + pod start + slice update +
/// CP pass before the last pod can serve.
const CONVERGE_DEADLINE: Duration = Duration::from_mins(2);

async fn serving_pod(driver: &Driver) -> Result<(StatusCode, String)> {
    let resp = driver.get(HOST, "/", HeaderMap::new()).await?;
    let status = resp.status();
    let pod = resp
        .headers()
        .get("x-echo-pod")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    Ok((status, pod))
}

/// Names of the non-terminating `app=<name>` pods.
async fn backend_pods(client: &kube::Client, ns: &str, name: &str) -> Result<HashSet<String>> {
    let pods = Api::<Pod>::namespaced(client.clone(), ns)
        .list(&ListParams::default().labels(&format!("app={name}")))
        .await?;
    Ok(pods
        .items
        .into_iter()
        .filter(|p| p.metadata.deletion_timestamp.is_none())
        .filter_map(|p| p.metadata.name)
        .collect())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn scaling_spreads_traffic_across_pods() -> Result<()> {
    let scope = Scope::new("endpoints-spread").await?;
    let ns = scope.name();
    let client = scope.client();

    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames([HOST])
            .path_prefix("/")
            .backend("echo", 8080)
            .build(),
    )
    .await?;
    wait_until_routed(&addr, HOST, "/", StatusCode::OK).await?;

    scale_deployment(client, ns, "echo", 5).await?;

    // Poll until every replica has served at least once: the slice
    // updates and the CP pushes the grown endpoint set without any
    // route or gateway change.
    let driver = Driver::new(&addr);
    let deadline = Instant::now() + CONVERGE_DEADLINE;
    let mut seen: HashSet<String> = HashSet::new();
    while seen.len() < 5 {
        let (status, pod) = serving_pod(&driver).await?;
        if status == StatusCode::OK && !pod.is_empty() {
            seen.insert(pod);
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "timed out waiting for 5 distinct pods; saw {seen:?}"
        );
    }

    // Steady state: the picker keeps spreading (P2C-EWMA is
    // intentionally uneven, so assert coverage, not uniformity) and
    // nothing errors.
    let mut spread: HashSet<String> = HashSet::new();
    for _ in 0..200 {
        let (status, pod) = serving_pod(&driver).await?;
        anyhow::ensure!(
            status == StatusCode::OK,
            "non-200 in steady state: {status}"
        );
        spread.insert(pod);
    }
    assert_eq!(spread.len(), 5, "expected all 5 pods to serve: {spread:?}");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn scale_down_removes_endpoints() -> Result<()> {
    let scope = Scope::new("endpoints-down").await?;
    let ns = scope.name();
    let client = scope.client();

    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames([HOST])
            .path_prefix("/")
            .backend("echo", 8080)
            .build(),
    )
    .await?;
    wait_until_routed(&addr, HOST, "/", StatusCode::OK).await?;

    scale_deployment(client, ns, "echo", 3).await?;
    let driver = Driver::new(&addr);
    let deadline = Instant::now() + CONVERGE_DEADLINE;
    let mut seen: HashSet<String> = HashSet::new();
    while seen.len() < 3 {
        let (status, pod) = serving_pod(&driver).await?;
        if status == StatusCode::OK && !pod.is_empty() {
            seen.insert(pod);
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "timed out waiting for 3 distinct pods; saw {seen:?}"
        );
    }

    // Scale down and learn the survivors from the API server.
    scale_deployment(client, ns, "echo", 1).await?;
    let survivors = loop {
        let pods = backend_pods(client, ns, "echo").await?;
        if pods.len() == 1 {
            break pods;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "timed out waiting for scale-down; pods {pods:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };

    // The removed pods leave the endpoint set within one slice
    // update: after convergence every response comes from the
    // survivor with no errors. Converged = 30 consecutive responses
    // from survivors only.
    let mut streak = 0;
    let mut last = String::new();
    while streak < 30 {
        // A transport error mid-drain (connection into a dying pod)
        // resets the streak instead of failing the test.
        match serving_pod(&driver).await {
            Ok((status, pod)) if status == StatusCode::OK && survivors.contains(&pod) => {
                streak += 1;
            }
            Ok((status, pod)) => {
                streak = 0;
                last = format!("{status} from {pod:?}");
            }
            Err(e) => {
                streak = 0;
                last = format!("{e:#}");
            }
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "timed out converging on survivors {survivors:?}; last: {last}"
        );
    }

    Ok(())
}
