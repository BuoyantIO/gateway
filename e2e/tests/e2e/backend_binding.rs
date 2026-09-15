//! `BackendBinding` — CRD to control-plane state to traffic. A
//! binding claims a backendRef kind the gateway has no schema for
//! and states what it resolves to: a route referencing the claimed
//! kind serves through the binding's backends with the binding's
//! extensions in the chain, an unclaimed foreign ref answers 500,
//! and duplicate claims resolve nothing.

use std::time::Duration;

use anyhow::Result;
use gateway_cp::crd::BackendBinding;
use gateway_e2e::fixtures::{
    apply_backend_binding, apply_extension, apply_gateway, apply_http_route, backend_binding,
    delete_backend_binding, extension, update_backend_binding_spec,
};
use gateway_e2e::{Scope, deploy_echo, gateway, gateway_address, http_route, wait_until_routed};
use http::StatusCode;
use kube::Api;
use serde_json::json;

const CLAIM: (&str, &str, &str) = ("kinference.buoyant.io", "InferencePool", "pool");

const POLL: Duration = Duration::from_millis(250);
const DEADLINE: Duration = Duration::from_mins(1);

/// Poll until the `BackendBinding`'s status carries `type_` with
/// `status`, and return its reason.
async fn wait_for_condition(
    api: &Api<BackendBinding>,
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
                    return Ok(c.reason);
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
async fn a_valid_binding_is_accepted_on_status() -> Result<()> {
    let scope = Scope::new("binding").await?;
    let ns = scope.name();
    let client = scope.client();
    let bindings: Api<BackendBinding> = Api::namespaced(client.clone(), ns);

    // The claimed kind is made up and the claimed object does not
    // exist; acceptance must not depend on either.
    apply_backend_binding(
        client,
        &backend_binding(ns, "pool", CLAIM, &[("workers", "workers-svc", 8000)], &[]),
    )
    .await?;

    let reason = wait_for_condition(&bindings, "pool", "Accepted", "True").await?;
    assert_eq!(reason, "Accepted");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn a_binding_with_no_refs_is_rejected_on_status() -> Result<()> {
    let scope = Scope::new("binding").await?;
    let ns = scope.name();
    let client = scope.client();
    let bindings: Api<BackendBinding> = Api::namespaced(client.clone(), ns);

    apply_backend_binding(client, &backend_binding(ns, "empty", CLAIM, &[], &[])).await?;

    let reason = wait_for_condition(&bindings, "empty", "Accepted", "False").await?;
    assert_eq!(reason, "NoBackendRefs");
    Ok(())
}

/// The whole pattern end to end: a route references a kind the
/// gateway has no schema for, the binding answers for it, and the
/// request serves through the binding's Service with the binding's
/// extension in the chain.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn a_claimed_ref_serves_traffic_through_the_binding() -> Result<()> {
    let scope = Scope::new("binding").await?;
    let ns = scope.name();
    let client = scope.client();

    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;

    // The echo reflects request headers `x-test-*` back as
    // `x-echo-*`, so the added header proves the extension ran.
    apply_extension(
        client,
        &extension(
            ns,
            "mark",
            "request_header_modifier",
            json!({ "add": [{ "name": "x-test-bound", "value": "via-binding" }] }),
        ),
    )
    .await?;
    apply_backend_binding(
        client,
        &backend_binding(ns, "pool", CLAIM, &[("workers", "echo", 8080)], &["mark"]),
    )
    .await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .foreign_backend(CLAIM.0, CLAIM.1, CLAIM.2)
            .build(),
    )
    .await?;

    let resp = wait_until_routed(&addr, "app.example", "/hello", StatusCode::OK).await?;
    assert_eq!(
        resp.headers().get("x-echo-bound").unwrap(),
        "via-binding",
        "the binding's extension must run ahead of the rule"
    );
    Ok(())
}

/// A foreign ref nothing claims keeps its share and answers 500 —
/// visible misconfiguration, not silently redistributed traffic.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn an_unclaimed_foreign_ref_answers_500() -> Result<()> {
    let scope = Scope::new("binding").await?;
    let ns = scope.name();
    let client = scope.client();

    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .foreign_backend(CLAIM.0, CLAIM.1, CLAIM.2)
            .build(),
    )
    .await?;

    wait_until_routed(&addr, "app.example", "/", StatusCode::INTERNAL_SERVER_ERROR).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn conflicting_claims_show_on_both_bindings() -> Result<()> {
    let scope = Scope::new("binding").await?;
    let ns = scope.name();
    let client = scope.client();
    let bindings: Api<BackendBinding> = Api::namespaced(client.clone(), ns);

    apply_backend_binding(
        client,
        &backend_binding(ns, "first", CLAIM, &[("w", "svc", 8000)], &[]),
    )
    .await?;
    apply_backend_binding(
        client,
        &backend_binding(ns, "second", CLAIM, &[("w", "svc", 8000)], &[]),
    )
    .await?;

    let reason = wait_for_condition(&bindings, "first", "Accepted", "False").await?;
    assert_eq!(reason, "Conflicted");
    let reason = wait_for_condition(&bindings, "second", "Accepted", "False").await?;
    assert_eq!(reason, "Conflicted");
    Ok(())
}

// ----- lifecycle: objects arrive and leave in any order -----

/// The route-first arrival order: the foreign ref answers 500 while
/// nothing claims it, and heals once the binding lands.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn a_binding_created_after_the_route_heals_traffic() -> Result<()> {
    let scope = Scope::new("binding").await?;
    let ns = scope.name();
    let client = scope.client();

    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .foreign_backend(CLAIM.0, CLAIM.1, CLAIM.2)
            .build(),
    )
    .await?;

    wait_until_routed(&addr, "app.example", "/", StatusCode::INTERNAL_SERVER_ERROR).await?;

    apply_backend_binding(
        client,
        &backend_binding(ns, "pool", CLAIM, &[("workers", "echo", 8080)], &[]),
    )
    .await?;
    wait_until_routed(&addr, "app.example", "/", StatusCode::OK).await?;
    Ok(())
}

/// One spec edit shifts both the targets and the chain: the binding
/// starts accepted but aimed at a Service that does not exist (500),
/// and after the update serves through the echo with the new
/// extension's header.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn a_binding_update_shifts_traffic_and_the_chain() -> Result<()> {
    let scope = Scope::new("binding").await?;
    let ns = scope.name();
    let client = scope.client();
    let bindings: Api<BackendBinding> = Api::namespaced(client.clone(), ns);

    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;
    for (name, value) in [("mark-a", "via-a"), ("mark-b", "via-b")] {
        apply_extension(
            client,
            &extension(
                ns,
                name,
                "request_header_modifier",
                json!({ "add": [{ "name": "x-test-bound", "value": value }] }),
            ),
        )
        .await?;
    }
    apply_backend_binding(
        client,
        &backend_binding(ns, "pool", CLAIM, &[("workers", "gone", 8080)], &["mark-a"]),
    )
    .await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .foreign_backend(CLAIM.0, CLAIM.1, CLAIM.2)
            .build(),
    )
    .await?;

    // Accepted, but the target does not exist: the substituted ref
    // rides unresolved and its share answers 500.
    let reason = wait_for_condition(&bindings, "pool", "Accepted", "True").await?;
    assert_eq!(reason, "Accepted");
    wait_until_routed(&addr, "app.example", "/", StatusCode::INTERNAL_SERVER_ERROR).await?;

    let updated = backend_binding(ns, "pool", CLAIM, &[("workers", "echo", 8080)], &["mark-b"]);
    update_backend_binding_spec(client, ns, "pool", &updated.spec).await?;

    let resp = wait_until_routed(&addr, "app.example", "/", StatusCode::OK).await?;
    assert_eq!(
        resp.headers().get("x-echo-bound").unwrap(),
        "via-b",
        "the updated chain must run, not the original"
    );
    Ok(())
}

/// Deleting the binding degrades the route to the unclaimed 500 —
/// garbage collection is just deletion — and restoring it heals.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test-e2e`"]
async fn a_deleted_binding_degrades_and_restores() -> Result<()> {
    let scope = Scope::new("binding").await?;
    let ns = scope.name();
    let client = scope.client();

    deploy_echo(client, ns, "echo", None).await?;
    apply_gateway(client, &gateway(ns, "gw", 80, None)).await?;
    let addr = gateway_address(client, ns, "gw").await?;
    let binding = backend_binding(ns, "pool", CLAIM, &[("workers", "echo", 8080)], &[]);
    apply_backend_binding(client, &binding).await?;
    apply_http_route(
        client,
        &http_route(ns, "gw", "route")
            .hostnames(["app.example"])
            .path_prefix("/")
            .foreign_backend(CLAIM.0, CLAIM.1, CLAIM.2)
            .build(),
    )
    .await?;
    wait_until_routed(&addr, "app.example", "/", StatusCode::OK).await?;

    delete_backend_binding(client, ns, "pool").await?;
    wait_until_routed(&addr, "app.example", "/", StatusCode::INTERNAL_SERVER_ERROR).await?;

    apply_backend_binding(client, &binding).await?;
    wait_until_routed(&addr, "app.example", "/", StatusCode::OK).await?;
    Ok(())
}
