//! Data-plane request metrics: drives traffic through a routed
//! Gateway, then scrapes the DP admin server's `/metrics` through
//! the apiserver pod proxy and asserts on the rendered series.

use anyhow::Result;
use gateway_e2e::fixtures::{apply_gateway, apply_http_route};
use gateway_e2e::{
    Driver, Scope, deploy_echo, dp_admin_get, gateway, gateway_address, http_route,
    wait_until_routed,
};
use http::StatusCode;
use reqwest::header::HeaderMap;

/// The line for a metric+labels, asserted by substring so the label
/// order stays an encoding detail.
fn series_line<'a>(body: &'a str, metric: &str, labels: &[&str]) -> Option<&'a str> {
    body.lines()
        .find(|l| l.starts_with(metric) && labels.iter().all(|part| l.contains(part)))
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn request_metrics_exported() -> Result<()> {
    let scope = Scope::new("metrics-req").await?;
    let ns = scope.name();
    let client = scope.client();

    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route-a")
            .hostnames(["metrics.example"])
            .path_prefix("/")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    let addr = gateway_address(client, ns, "gw").await?;
    wait_until_routed(&addr, "metrics.example", "/", StatusCode::OK).await?;
    // One request for a host no listener/route covers: counts as
    // 404/no_route with unknown identity.
    let resp = Driver::new(&addr)
        .get("nowhere.example", "/", HeaderMap::new())
        .await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    let body = dp_admin_get(client, ns, "gw", "/metrics").await?;

    // The route label is the store's qualified route key
    // (`{ns}/{name}/rule{N}`), so match the HTTPRoute name within it.
    let ok = series_line(
        &body,
        "gateway_requests_total",
        &[
            "route-a",
            "status=\"200\"",
            "reason=\"ok\"",
            "listener=\"http\"",
        ],
    )
    .unwrap_or_else(|| panic!("no ok-request series in:\n{body}"));
    let count: f64 = ok.rsplit(' ').next().unwrap_or("0").parse()?;
    assert!(count >= 1.0, "expected at least one ok request: {ok}");

    assert!(
        series_line(
            &body,
            "gateway_requests_total",
            &[
                "route=\"unknown\"",
                "listener=\"unknown\"",
                "status=\"404\"",
                "reason=\"no_route\"",
            ],
        )
        .is_some(),
        "no unrouted-request series in:\n{body}"
    );

    let duration = series_line(
        &body,
        "gateway_request_duration_seconds_count",
        &["route-a"],
    )
    .unwrap_or_else(|| panic!("no duration series in:\n{body}"));
    let observed: f64 = duration.rsplit(' ').next().unwrap_or("0").parse()?;
    assert!(observed >= 1.0, "histogram never observed: {duration}");
    // Policy: the histogram carries identity labels only.
    assert!(!duration.contains("status="), "{duration}");
    assert!(!duration.contains("reason="), "{duration}");

    Ok(())
}
