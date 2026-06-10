//! Filter tests — `RequestHeaderModifier` and
//! `ResponseHeaderModifier`.

use anyhow::Result;
use gateway_e2e::fixtures::{apply_gateway, apply_http_route};
use gateway_e2e::{Scope, deploy_dp, deploy_echo, gateway, http_route, wait_until_routed};
use http::StatusCode;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn request_and_response_modifiers() -> Result<()> {
    let scope = Scope::new("filters").await?;
    let ns = scope.name();
    let client = scope.client();

    deploy_dp(client, ns, "gw").await?;
    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;

    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            // Request side: tag with x-test-added=hello. Echo
            // reflects x-test-* as x-echo-* on the response, so the
            // client sees x-echo-added=hello.
            .filter_request_header_add("x-test-added", "hello")
            // Response side: add CSP, remove the server-version
            // header the echo emits.
            .filter_response_header_add("x-csp", "default-src 'self'")
            .filter_response_header_remove("x-server-version")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    let resp = wait_until_routed("app.example", "/", StatusCode::OK).await?;

    // Request-side filter took effect (request was tagged, echo
    // reflected it back).
    assert_eq!(
        resp.headers().get("x-echo-added").unwrap(),
        "hello",
        "request filter should have added x-test-added on the way out"
    );

    // Response-side add.
    assert_eq!(
        resp.headers().get("x-csp").unwrap(),
        "default-src 'self'",
        "response filter should have added x-csp"
    );

    // Response-side remove. The echo always emits x-server-version;
    // confirm the filter stripped it.
    assert!(
        resp.headers().get("x-server-version").is_none(),
        "response filter should have removed x-server-version, got headers: {:?}",
        resp.headers()
    );

    Ok(())
}
