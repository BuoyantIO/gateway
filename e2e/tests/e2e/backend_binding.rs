//! `BackendBinding` lifecycle — CRD to control-plane state. A binding
//! claims a backendRef kind the gateway has no schema for and states
//! what it resolves to. Nothing routes through it yet; what this
//! covers is the watch round-trip and the acceptance decision showing
//! up on status.

use std::time::Duration;

use anyhow::Result;
use gateway_cp::crd::BackendBinding;
use gateway_e2e::Scope;
use gateway_e2e::fixtures::{apply_backend_binding, backend_binding};
use kube::Api;

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
        &backend_binding(
            ns,
            "pool",
            ("inference-d.io", "InferencePool", "pool"),
            &[("workers", "workers-svc", 8000)],
        ),
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

    apply_backend_binding(
        client,
        &backend_binding(
            ns,
            "empty",
            ("inference-d.io", "InferencePool", "pool"),
            &[],
        ),
    )
    .await?;

    let reason = wait_for_condition(&bindings, "empty", "Accepted", "False").await?;
    assert_eq!(reason, "NoBackendRefs");
    Ok(())
}
