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
    Scope, deploy_echo, deploy_tls_secret, expose_dp, gateway_https, http_route,
    wait_until_routed_tls,
};
use http::StatusCode;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn https_listener_terminates_and_routes() -> Result<()> {
    let scope = Scope::new("tls-term").await?;
    let ns = scope.name();
    let client = scope.client();

    expose_dp(client, ns, "gw").await?;
    deploy_echo(client, ns, "echo", None).await?;
    deploy_tls_secret(client, ns, "app-tls", TEST_CERT_PEM, TEST_KEY_PEM).await?;

    // HTTPS listener on the DP's port (80): the data plane terminates
    // TLS there and forwards plaintext to the echo backend.
    apply_gateway(
        client,
        &gateway_https(ns, "gw", 80, Some("app.example"), "app-tls"),
    )
    .await?;

    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    let resp = wait_until_routed_tls("app.example", "/", StatusCode::OK).await?;
    assert_eq!(resp.text().await?, "GET /");
    Ok(())
}
