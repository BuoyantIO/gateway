//! `GatewayBackend` lifecycle — CRD to wire to data plane. A route's
//! `backendRefs` names a `GatewayBackend` instead of a Service, and
//! the gateway dials the host in its `baseURL` by name, joins the
//! URL's path ahead of the request path, and presents the credential
//! its auth block names.
//!
//! The upstream here is the echo backend reached through its cluster
//! DNS name, which is what makes it a *dialable* backend rather than
//! an endpoint set: nothing resolves it to pod addresses, and the
//! echo reflects both the path it was asked for and the credential
//! header it received. TLS origination has its own coverage in
//! `crates/gateway-runtime/tests/tls_origination.rs`; what is new
//! here is the trip through the control plane.

use std::time::Duration;

use anyhow::Result;
use gateway_cp::crd::GatewayBackend;
use gateway_e2e::fixtures::{
    apply_gateway, apply_gateway_backend, apply_http_route, delete_secret,
    deploy_credential_secret, gateway_backend, gateway_backend_with_api_key,
};
use gateway_e2e::{Scope, deploy_echo, gateway, gateway_address, http_route, wait_until_routed};
use http::StatusCode;
use kube::Api;

const POLL: Duration = Duration::from_millis(250);
const DEADLINE: Duration = Duration::from_mins(1);

/// Poll until the `GatewayBackend`'s status carries `type_` with
/// `status`, and return its message.
async fn wait_for_condition(
    api: &Api<GatewayBackend>,
    name: &str,
    type_: &str,
    status: &str,
) -> Result<String> {
    let deadline = std::time::Instant::now() + DEADLINE;
    let mut last: Option<String> = None;
    loop {
        if let Some(object) = api.get_opt(name).await? {
            let condition = object
                .status
                .as_ref()
                .and_then(|s| s.conditions.iter().find(|c| c.type_ == type_).cloned());
            if let Some(c) = condition {
                if c.status == status {
                    return Ok(c.message);
                }
                last = Some(format!("{}: {}", c.status, c.message));
            }
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {name} {type_}={status}, last seen {last:?}"
        );
        tokio::time::sleep(POLL).await;
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn dialable_backend_carries_the_url_and_the_credential() -> Result<()> {
    let scope = Scope::new("egress").await?;
    let ns = scope.name();
    let client = scope.client();
    let backends: Api<GatewayBackend> = Api::namespaced(client.clone(), ns);

    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;

    // The credential the gateway presents upstream. `x-test-` so the
    // echo reflects it back as `x-echo-`, which is how the test sees
    // what the upstream actually received.
    deploy_credential_secret(client, ns, "provider-key", "apiKey", "s3cr3t").await?;
    apply_gateway_backend(
        client,
        &gateway_backend_with_api_key(
            ns,
            "provider",
            &format!("http://echo.{ns}.svc.cluster.local:8080/v1"),
            "provider-key",
            "apiKey",
            "x-test-credential",
        ),
    )
    .await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .dialable_backend("provider")
            .build(),
    )
    .await?;

    wait_for_condition(&backends, "provider", "Accepted", "True").await?;
    wait_for_condition(&backends, "provider", "ResolvedRefs", "True").await?;

    let resp = wait_until_routed(&addr, "app.example", "/chat", StatusCode::OK).await?;
    assert_eq!(
        resp.headers().get("x-echo-credential").unwrap(),
        "Bearer s3cr3t",
        "the upstream should receive the configured header with the default prefix"
    );
    assert_eq!(
        resp.text().await?,
        "GET /v1/chat",
        "the baseURL path should be joined ahead of the request path"
    );

    Ok(())
}

/// The other half of the acceptance criterion: break the secret and
/// the status says so while requests fail visibly.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn a_broken_credential_shows_in_status_and_fails_requests() -> Result<()> {
    let scope = Scope::new("egress-broken").await?;
    let ns = scope.name();
    let client = scope.client();
    let backends: Api<GatewayBackend> = Api::namespaced(client.clone(), ns);

    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;

    deploy_credential_secret(client, ns, "provider-key", "apiKey", "s3cr3t").await?;
    apply_gateway_backend(
        client,
        &gateway_backend_with_api_key(
            ns,
            "provider",
            &format!("http://echo.{ns}.svc.cluster.local:8080"),
            "provider-key",
            "apiKey",
            "x-test-credential",
        ),
    )
    .await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .dialable_backend("provider")
            .build(),
    )
    .await?;
    wait_until_routed(&addr, "app.example", "/", StatusCode::OK).await?;

    // Take the credential away. The object is still accepted — the
    // spec is fine — but its references no longer resolve, and the
    // request path has no credential to present.
    delete_secret(client, ns, "provider-key").await?;
    let message = wait_for_condition(&backends, "provider", "ResolvedRefs", "False").await?;
    assert!(
        message.contains("provider-key"),
        "the message should name the reference: {message}"
    );
    assert!(
        !message.contains("s3cr3t"),
        "and never its contents: {message}"
    );
    wait_for_condition(&backends, "provider", "Accepted", "True").await?;
    wait_until_routed(&addr, "app.example", "/", StatusCode::INTERNAL_SERVER_ERROR).await?;

    // Put it back: the backend recovers without the object changing.
    deploy_credential_secret(client, ns, "provider-key", "apiKey", "s3cr3t").await?;
    wait_for_condition(&backends, "provider", "ResolvedRefs", "True").await?;
    wait_until_routed(&addr, "app.example", "/", StatusCode::OK).await?;

    Ok(())
}

/// A spec that cannot name a destination publishes nothing, and says
/// why on the object rather than anywhere else.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn an_invalid_base_url_is_reported_on_the_object() -> Result<()> {
    let scope = Scope::new("egress-invalid").await?;
    let ns = scope.name();
    let client = scope.client();
    let backends: Api<GatewayBackend> = Api::namespaced(client.clone(), ns);

    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;

    // Well-formed enough for the CRD's own pattern check, and still
    // not a URL that names a host.
    apply_gateway_backend(client, &gateway_backend(ns, "provider", "https://")).await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .dialable_backend("provider")
            .build(),
    )
    .await?;

    let message = wait_for_condition(&backends, "provider", "Accepted", "False").await?;
    assert!(
        message.contains("baseURL"),
        "the message should name the field: {message}"
    );
    // The route keeps the ref, so traffic aimed at it gets a 500
    // rather than silence.
    wait_until_routed(&addr, "app.example", "/", StatusCode::INTERNAL_SERVER_ERROR).await?;

    Ok(())
}
