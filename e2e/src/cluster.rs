//! Cluster connection and per-test namespace lifecycle.
//!
//! Every test starts with `Scope::new("...")`. The scope creates a
//! uniquely-named namespace and holds a `kube::Client`. When the scope
//! is dropped — including on `panic!` from a failed assertion — the
//! namespace is deleted in the background, which GCs every resource
//! the test created under it.
//!
//! Deleting the namespace also deletes the only copy of its pods' logs,
//! so with `E2E_LOG_DIR` set the scope first saves every container's
//! log and the namespace's events under `$E2E_LOG_DIR/<namespace>/`.
//! A scope can't tell whether its test failed (a test returning `Err`
//! drops it like any other), so it saves them for every test; CI
//! uploads the directory only when the suite fails.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::{Event, Namespace, Pod};
use kube::api::{DeleteParams, ListParams, LogParams, ObjectMeta, PostParams};
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
        // fully gone. Tests run in parallel; the sync wait bounds this
        // test's namespace lifetime so its teardown never leaks into a
        // concurrent test's world — the blocked thread only idles its
        // own test slot.
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

/// Environment variable naming the directory a scope saves its
/// namespace's logs and events to before deleting it.
const LOG_DIR_ENV: &str = "E2E_LOG_DIR";

/// Delete `name` and poll until the apiserver returns 404 (i.e. the
/// namespace plus all its resources are fully GC'd). Bounded at 60 s.
async fn delete_namespace(name: String) {
    let Ok(client) = Client::try_default().await else {
        return;
    };
    if let Some(dir) = std::env::var_os(LOG_DIR_ENV) {
        save_namespace(&client, &name, &PathBuf::from(dir).join(&name)).await;
    }
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

/// Save every container's log (and its previous instance's, if it
/// restarted) plus the namespace's events into `dir`. Best effort: a
/// failure here must never stop the namespace from being deleted.
async fn save_namespace(client: &Client, ns: &str, dir: &Path) {
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    if let Ok(list) = pods.list(&ListParams::default()).await {
        for pod in list {
            let pod_name = pod.metadata.name.unwrap_or_default();
            let statuses = pod
                .status
                .and_then(|s| s.container_statuses)
                .unwrap_or_default();
            for status in statuses {
                let mut params = LogParams {
                    container: Some(status.name.clone()),
                    timestamps: true,
                    ..LogParams::default()
                };
                if let Ok(log) = pods.logs(&pod_name, &params).await {
                    let _ =
                        std::fs::write(dir.join(format!("{pod_name}.{}.log", status.name)), log);
                }
                if status.restart_count > 0 {
                    params.previous = true;
                    if let Ok(log) = pods.logs(&pod_name, &params).await {
                        let file = format!("{pod_name}.{}.previous.log", status.name);
                        let _ = std::fs::write(dir.join(file), log);
                    }
                }
            }
        }
    }

    let events: Api<Event> = Api::namespaced(client.clone(), ns);
    if let Ok(list) = events.list(&ListParams::default()).await {
        let mut lines: Vec<(String, String)> = list
            .into_iter()
            .map(|e| {
                let at = e
                    .last_timestamp
                    .or(e.first_timestamp)
                    .map(|t| t.0.to_string())
                    .or_else(|| e.event_time.map(|t| t.0.to_string()))
                    .unwrap_or_default();
                let line = format!(
                    "{at} {} {} {}/{} x{}: {}",
                    e.type_.unwrap_or_default(),
                    e.reason.unwrap_or_default(),
                    e.involved_object.kind.unwrap_or_default(),
                    e.involved_object.name.unwrap_or_default(),
                    e.count.unwrap_or(1),
                    e.message.unwrap_or_default(),
                );
                (at, line)
            })
            .collect();
        lines.sort();
        let text: String = lines.into_iter().map(|(_, l)| l + "\n").collect();
        let _ = std::fs::write(dir.join("events.txt"), text);
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
