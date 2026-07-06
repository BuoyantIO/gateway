//! Routing tests: hostname isolation, exact-beats-prefix path
//! match, and regex path match.
//!
//! Each test:
//! - Creates a per-test namespace (auto-deleted on scope drop).
//! - Applies a `Gateway` (the CP provisions the data plane from it),
//!   an `HTTPRoute` (or multiple), the `NodePort` exposure `Service`,
//!   and one or more echo backends.
//! - Polls the data path until the gateway routes (status
//!   writeback isn't wired yet, so we probe directly).
//! - Drives requests through `127.0.0.1:30080` and asserts on the
//!   echoed response.

use anyhow::Result;
use gateway_e2e::fixtures::{apply_gateway, apply_http_route};
use gateway_e2e::{Scope, deploy_echo, expose_dp, gateway, http_route, wait_until_routed};
use http::StatusCode;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn hostname_routes_isolate_traffic() -> Result<()> {
    let scope = Scope::new("routing-host").await?;
    let ns = scope.name();
    let client = scope.client();

    expose_dp(client, ns, "gw").await?;
    deploy_echo(client, ns, "echo", None).await?;

    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;

    apply_http_route(
        client,
        &http_route(ns, "gw", "route-a")
            .hostnames(["a.example"])
            .path_prefix("/")
            .filter_request_header_add("x-test-route", "a")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    apply_http_route(
        client,
        &http_route(ns, "gw", "route-b")
            .hostnames(["b.example"])
            .path_prefix("/")
            .filter_request_header_add("x-test-route", "b")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    let resp_a = wait_until_routed("a.example", "/", StatusCode::OK).await?;
    assert_eq!(resp_a.headers().get("x-echo-route").unwrap(), "a");

    let resp_b = wait_until_routed("b.example", "/", StatusCode::OK).await?;
    assert_eq!(resp_b.headers().get("x-echo-route").unwrap(), "b");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn exact_beats_prefix() -> Result<()> {
    let scope = Scope::new("routing-exact").await?;
    let ns = scope.name();
    let client = scope.client();

    expose_dp(client, ns, "gw").await?;
    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;

    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_exact("/healthz")
            .filter_request_header_add("x-test-rule", "exact")
            .backend("echo", 8080)
            .add_rule()
            .path_prefix("/")
            .filter_request_header_add("x-test-rule", "prefix")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    let exact = wait_until_routed("app.example", "/healthz", StatusCode::OK).await?;
    assert_eq!(exact.headers().get("x-echo-rule").unwrap(), "exact");

    let prefix = wait_until_routed("app.example", "/healthzz", StatusCode::OK).await?;
    assert_eq!(prefix.headers().get("x-echo-rule").unwrap(), "prefix");

    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn regex_path_matches() -> Result<()> {
    let scope = Scope::new("routing-regex").await?;
    let ns = scope.name();
    let client = scope.client();

    expose_dp(client, ns, "gw").await?;
    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;

    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_regex("^/api/v[0-9]+$")
            .filter_request_header_add("x-test-rule", "regex")
            .backend("echo", 8080)
            .add_rule()
            .path_prefix("/")
            .filter_request_header_add("x-test-rule", "prefix")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    let matched = wait_until_routed("app.example", "/api/v1", StatusCode::OK).await?;
    assert_eq!(matched.headers().get("x-echo-rule").unwrap(), "regex");

    let unmatched = wait_until_routed("app.example", "/api/v", StatusCode::OK).await?;
    assert_eq!(unmatched.headers().get("x-echo-rule").unwrap(), "prefix");

    Ok(())
}
