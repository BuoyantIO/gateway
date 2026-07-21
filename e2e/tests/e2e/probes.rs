//! Control-plane probes: with readiness wired to reflector sync,
//! every CP replica must report Ready — so `ready_replicas` reaching
//! the spec count proves the pods answered `/healthz/ready`, not
//! just that their processes started.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use gateway_e2e::kube_client;
use k8s_openapi::api::apps::v1::Deployment;
use kube::Api;

const CP_NAMESPACE: &str = "gateway-system";

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn control_plane_replicas_report_ready() -> Result<()> {
    let client = kube_client().await?;
    let deployments: Api<Deployment> = Api::namespaced(client, CP_NAMESPACE);

    let deadline = Instant::now() + Duration::from_mins(1);
    loop {
        let dep = deployments
            .get("gateway-cp")
            .await
            .context("reading gateway-cp deployment")?;
        let want = dep.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0);
        let ready = dep
            .status
            .as_ref()
            .and_then(|s| s.ready_replicas)
            .unwrap_or(0);
        ensure!(want > 0, "gateway-cp deployment has no replicas");
        if ready == want {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "timed out: {ready}/{want} CP replicas ready"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
