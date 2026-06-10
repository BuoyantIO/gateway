//! Match-dimension tests — `HTTPRoute` method, header, and
//! query-param matches.

use anyhow::Result;
use gateway_api::apis::standard::httproutes::HttpRouteRulesMatchesMethod;
use gateway_e2e::fixtures::{apply_gateway, apply_http_route};
use gateway_e2e::{Driver, Scope, deploy_dp, deploy_echo, gateway, http_route, wait_until_routed};
use http::StatusCode;
use reqwest::header::HeaderMap;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn method_and_header_match() -> Result<()> {
    let scope = Scope::new("matches").await?;
    let ns = scope.name();
    let client = scope.client();

    deploy_dp(client, ns, "gw").await?;
    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;

    // Rule A: POST + x-channel: web   -> tag=specific
    // Rule B: catch-all PathPrefix /  -> tag=catchall
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .method(HttpRouteRulesMatchesMethod::Post)
            .header_exact("x-channel", "web")
            .filter_request_header_add("x-test-rule", "specific")
            .backend("echo", 8080)
            .add_rule()
            .path_prefix("/")
            .filter_request_header_add("x-test-rule", "catchall")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    // Establish that the gateway is up at all.
    let _ = wait_until_routed("app.example", "/", StatusCode::OK).await?;

    let driver = Driver::new();

    // POST + x-channel: web -> specific.
    let mut h = HeaderMap::new();
    h.insert("x-channel", "web".parse().unwrap());
    let r = driver
        .request(reqwest::Method::POST, "app.example", "/", h)
        .await?;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers().get("x-echo-rule").unwrap(), "specific");

    // GET -> catchall (method missed).
    let r = driver
        .request(reqwest::Method::GET, "app.example", "/", HeaderMap::new())
        .await?;
    assert_eq!(r.headers().get("x-echo-rule").unwrap(), "catchall");

    // POST without x-channel -> catchall (header missed).
    let r = driver
        .request(reqwest::Method::POST, "app.example", "/", HeaderMap::new())
        .await?;
    assert_eq!(r.headers().get("x-echo-rule").unwrap(), "catchall");

    Ok(())
}
