//! Extension object lifecycle — CRD to wire to data plane. A route's
//! `ExtensionRef` filter resolves against an `Extension` object whose
//! class is the built-in `request_header_modifier`; the header ops
//! ride in the object's opaque `config`.

use anyhow::Result;
use gateway_e2e::fixtures::{
    apply_extension, apply_gateway, apply_http_route, delete_extension, extension,
};
use gateway_e2e::{Scope, deploy_echo, gateway, gateway_address, http_route, wait_until_routed};
use http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn extension_ref_lifecycle() -> Result<()> {
    let scope = Scope::new("extensions").await?;
    let ns = scope.name();
    let client = scope.client();

    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;

    apply_extension(
        client,
        &extension(
            ns,
            "tagger",
            "request_header_modifier",
            json!({ "add": [{ "name": "x-test-added", "value": "via-extension" }] }),
        ),
    )
    .await?;

    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .filter_extension_ref("tagger")
            .backend("echo", 8080)
            .build(),
    )
    .await?;

    // The object's config took effect: the echo reflects x-test-* as
    // x-echo-* on the response.
    let resp = wait_until_routed(&addr, "app.example", "/", StatusCode::OK).await?;
    assert_eq!(
        resp.headers().get("x-echo-added").unwrap(),
        "via-extension",
        "extension config should have added x-test-added on the way out"
    );

    // Delete the object. The route keeps the ref; with the object
    // gone the DP fails the route closed.
    delete_extension(client, ns, "tagger").await?;
    wait_until_routed(&addr, "app.example", "/", StatusCode::INTERNAL_SERVER_ERROR).await?;

    // Re-apply and recover.
    apply_extension(
        client,
        &extension(
            ns,
            "tagger",
            "request_header_modifier",
            json!({ "add": [{ "name": "x-test-added", "value": "via-extension" }] }),
        ),
    )
    .await?;
    let resp = wait_until_routed(&addr, "app.example", "/", StatusCode::OK).await?;
    assert_eq!(
        resp.headers().get("x-echo-added").unwrap(),
        "via-extension",
        "recovery should re-apply the extension config"
    );

    Ok(())
}
