//! Backend-protocol test — `Service.appProtocol` maps to
//! `BackendProtocol::Http2` and the upstream is dialed h2c.

use anyhow::Result;
use gateway_e2e::fixtures::{apply_gateway, apply_http_route};
use gateway_e2e::{Scope, deploy_echo, gateway, gateway_address, http_route, wait_until_routed};
use http::StatusCode;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn h2c_backend() -> Result<()> {
    let scope = Scope::new("backend-h2c").await?;
    let ns = scope.name();
    let client = scope.client();

    // appProtocol: h2c — the translator should recognize this and
    // emit BackendProtocol::Http2. The gateway then dials the echo
    // backend over h2c (HTTP/2 prior-knowledge). The echo's
    // hyper_util auto::Builder serves both H1 and H2.
    deploy_echo(client, ns, "echo", Some("h2c")).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
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

    // Drive over HTTP/1.1 client-side. The gateway speaks H2 to the
    // backend regardless — the echo's reflected x-server-version
    // header tells us which wire version it received.
    let resp = wait_until_routed(&addr, "app.example", "/hello", StatusCode::OK).await?;

    let server_version = resp
        .headers()
        .get("x-server-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        server_version.contains("HTTP/2"),
        "backend should have received HTTP/2 (h2c), got x-server-version={server_version:?}"
    );

    let body = resp.text().await?;
    assert_eq!(body, "GET /hello");

    Ok(())
}
