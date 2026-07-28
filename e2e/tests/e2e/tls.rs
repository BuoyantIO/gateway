//! TLS termination e2e: a real HTTPS client handshakes with the data
//! plane, which terminates TLS using a `kubernetes.io/tls` Secret and
//! forwards plaintext to the echo backend.
//!
//! Same shape as the other suites — a per-test namespace, a DP, an
//! echo backend, a `Gateway` + `HTTPRoute` — plus a `Secret` and an
//! HTTPS listener. The request is driven over TLS, with the gateway
//! hostname as SNI, through `127.0.0.1:30080`.

use anyhow::Result;
use gateway_e2e::fixtures::{TEST_CERT_PEM, TEST_KEY_PEM, apply_gateway, apply_http_route};
use gateway_e2e::{
    Scope, deploy_echo, deploy_tls_secret, gateway_address, gateway_https,
    gateway_https_with_cert_ns, http_route, wait_until_routed_tls,
};
use http::StatusCode;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn https_listener_terminates_and_routes() -> Result<()> {
    let scope = Scope::new("tls-term").await?;
    let ns = scope.name();
    let client = scope.client();

    deploy_echo(client, ns, "echo", None).await?;
    deploy_tls_secret(client, ns, "app-tls", TEST_CERT_PEM, TEST_KEY_PEM).await?;

    // HTTPS listener on the DP's port (80): the data plane terminates
    // TLS there and forwards plaintext to the echo backend.
    apply_gateway(
        client,
        &gateway_https(ns, "gw", 80, Some("app.example"), "app-tls"),
    )
    .await?;
    let addr = gateway_address(client, ns, "gw").await?;

    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    let resp = wait_until_routed_tls(&addr, "app.example", "/", StatusCode::OK).await?;
    assert_eq!(resp.text().await?, "GET /");
    Ok(())
}

/// A listener's certificateRef reaching into another namespace: the
/// secret lives in its own namespace (the cert-manager-owns-the-cert
/// arrangement) and the gateway terminates with it. Accepted
/// permissively until `ReferenceGrant` enforcement lands.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn cross_namespace_certificate_terminates_tls() -> Result<()> {
    let app = Scope::new("tls-xns-app").await?;
    let certs = Scope::new("tls-xns-certs").await?;
    let ns = app.name();
    let client = app.client();

    deploy_echo(client, ns, "echo", None).await?;
    deploy_tls_secret(
        client,
        certs.name(),
        "shared-tls",
        TEST_CERT_PEM,
        TEST_KEY_PEM,
    )
    .await?;

    apply_gateway(
        client,
        &gateway_https_with_cert_ns(
            ns,
            "gw",
            80,
            Some("app.example"),
            Some(certs.name()),
            "shared-tls",
        ),
    )
    .await?;
    let addr = gateway_address(client, ns, "gw").await?;

    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    let resp = wait_until_routed_tls(&addr, "app.example", "/", StatusCode::OK).await?;
    assert_eq!(resp.text().await?, "GET /");
    Ok(())
}
