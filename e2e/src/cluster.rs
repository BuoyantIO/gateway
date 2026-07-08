//! Cluster connection and per-test namespace lifecycle.
//!
//! Every test starts with `Scope::new("...")`. The scope creates a
//! uniquely-named namespace and holds a `kube::Client`. When the scope
//! is dropped — including on `panic!` from a failed assertion — the
//! namespace is deleted in the background, which GCs every resource
//! the test created under it.

use std::time::Duration;

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{DeleteParams, ObjectMeta, PostParams};
use kube::{Api, Client};
use rand::Rng;
use rand::distributions::Alphanumeric;

/// Connect to the cluster.
///
/// # Errors
/// Returns an error if no kube context is reachable.
pub async fn kube_client() -> Result<Client> {
    Client::try_default()
        .await
        .context("connecting to kube cluster")
}

/// Per-test namespace + client handle. The namespace is deleted on
/// `Drop`.
pub struct Scope {
    client: Client,
    name: String,
}

impl Scope {
    /// Create a fresh namespace named `"{prefix}-{6 random chars}"`.
    ///
    /// # Errors
    /// Returns an error if namespace creation fails.
    pub async fn new(prefix: &str) -> Result<Self> {
        let client = kube_client().await?;
        let name = unique_name(prefix);
        let ns_api: Api<Namespace> = Api::all(client.clone());
        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                ..Default::default()
            },
            ..Default::default()
        };
        ns_api
            .create(&PostParams::default(), &ns)
            .await
            .with_context(|| format!("creating namespace {name}"))?;

        Ok(Self { client, name })
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        // Synchronously delete the namespace and wait until it's
        // fully gone, keeping the cluster quiet between tests.
        // Parallel e2e (and async teardown) is tracked separately.
        let name = std::mem::take(&mut self.name);
        let handle = std::thread::Builder::new()
            .name(format!("ns-drop-{name}"))
            .spawn(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                rt.block_on(delete_namespace(name));
            });
        if let Ok(h) = handle {
            let _ = h.join();
        }
    }
}

/// Delete `name` and poll until the apiserver returns 404 (i.e. the
/// namespace plus all its resources are fully GC'd). Bounded at 60 s.
async fn delete_namespace(name: String) {
    let Ok(client) = Client::try_default().await else {
        return;
    };
    let api: Api<Namespace> = Api::all(client);
    let _ = api.delete(&name, &DeleteParams::default()).await;
    let deadline = std::time::Instant::now() + Duration::from_mins(1);
    while std::time::Instant::now() < deadline {
        match api.get_opt(&name).await {
            Ok(None) => return,
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
}

fn unique_name(prefix: &str) -> String {
    let suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(|c| (c as char).to_ascii_lowercase())
        .collect();
    format!("{prefix}-{suffix}")
}
