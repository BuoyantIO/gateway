//! `RequestRedirect` filter e2e: an HTTP listener whose route carries a
//! redirect filter answers with a 3xx + `Location` and never proxies —
//! so the route needs no backend at all.

use anyhow::Result;
use gateway_e2e::fixtures::{apply_gateway, apply_http_route};
use gateway_e2e::{Scope, gateway, gateway_address, http_route, wait_until_redirected};
use http::StatusCode;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn request_redirect_answers_301_to_https() -> Result<()> {
    let scope = Scope::new("redirect").await?;
    let ns = scope.name();
    let client = scope.client();

    // Just a data plane and a Gateway with a plaintext listener — no
    // echo backend, since the redirect short-circuits.
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;

    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .filter_request_redirect("https", 301)
            .build(),
    )
    .await?;

    let resp = wait_until_redirected(
        &addr,
        "app.example",
        "/foo?x=1",
        StatusCode::MOVED_PERMANENTLY,
    )
    .await?;
    let location = resp
        .headers()
        .get(http::header::LOCATION)
        .expect("Location header present")
        .to_str()?;
    assert_eq!(location, "https://app.example/foo?x=1");
    Ok(())
}
