//! Control-plane high availability: exactly one of the two CP
//! replicas holds the leader lease, and killing the holder hands
//! over to the survivor, which then drives the full pipeline
//! (provisioning, config push, status) on its own. Throughout and
//! after the handover, no two replicas act as leader at once.
use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use gateway_e2e::fixtures::{apply_gateway, apply_http_route};
use gateway_e2e::{
    Scope, deploy_echo, gateway, gateway_address, http_route, kube_client, wait_until_routed,
};
use http::StatusCode;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::Pod;
use kube::Client;
use kube::api::{Api, DeleteParams, ListParams};

const CP_NAMESPACE: &str = "gateway-system";
const LEASE_NAME: &str = "gateway-cp-leader";
/// Crash handover budget: lease duration (15s) plus renew cadence
/// slack; generous against apiserver jitter.
const HANDOVER_DEADLINE: Duration = Duration::from_secs(45);
/// How long after the handover to keep checking that at most one
/// replica acts as leader: several lease durations, so a stale
/// holder whose renewal hangs has time to show up as a second
/// leader.
const SINGLE_LEADER_WINDOW: Duration = Duration::from_secs(60);
/// The CP admin port, which serves `/leader`.
const CP_ADMIN_PORT: u16 = 15021;
/// How long a running CP replica may go without answering `/leader`
/// before the check fails: enough for a replacement pod to start its
/// admin server or a brief proxy hiccup, short of hiding a broken
/// endpoint for the whole window.
const UNANSWERED_LIMIT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires kind cluster — run via `just test`"]
async fn leader_election_single_writer_and_failover() -> Result<()> {
    let client = kube_client().await?;
    let pods: Api<Pod> = Api::namespaced(client.clone(), CP_NAMESPACE);
    let leases: Api<Lease> = Api::namespaced(client.clone(), CP_NAMESPACE);

    let cp_pods: Vec<String> = pods
        .list(&ListParams::default().labels("app=gateway-cp"))
        .await?
        .items
        .into_iter()
        .filter_map(|p| p.metadata.name)
        .collect();
    ensure!(
        cp_pods.len() >= 2,
        "expected >= 2 CP replicas, found {cp_pods:?}"
    );

    // The holder is one of the replicas and doesn't flap: same
    // identity across several lease-renewal cycles.
    let leader = wait_for_holder(&leases, |h| cp_pods.iter().any(|p| p == h)).await?;
    for _ in 0..6 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let holder = holder(&leases).await?.unwrap_or_default();
        ensure!(
            holder == leader,
            "lease flapped from {leader} to {holder} with both replicas healthy"
        );
    }

    // Kill the leader without grace: the crash path, where nothing
    // vacates the lease and the survivor must wait out its expiry.
    pods.delete(&leader, &DeleteParams::default().grace_period(0))
        .await
        .context("deleting leader pod")?;

    // The next holder is whichever healthy replica wins the claim
    // race: the original survivor or the Deployment's replacement
    // pod — both are correct, only the dead leader is not.
    let new_leader = wait_for_holder(&leases, |h| h != leader).await?;
    let live: Vec<String> = pods
        .list(&ListParams::default().labels("app=gateway-cp"))
        .await?
        .items
        .into_iter()
        .filter_map(|p| p.metadata.name)
        .collect();
    ensure!(
        live.iter().any(|p| p == &new_leader),
        "lease holder {new_leader} is not a live CP pod ({live:?})"
    );

    // The survivor drives the whole pipeline: provision a fresh
    // Gateway, push config, answer traffic, write status (the
    // address read below comes from status). Meanwhile, and for a
    // while after, no two replicas may act as leader.
    let pipeline = async {
        let scope = Scope::new("ha-failover").await?;
        let ns = scope.name();
        let sc = scope.client();
        deploy_echo(sc, ns, "echo", None).await?;
        apply_gateway(sc, &gateway(ns, "gw", 80, None)).await?;
        let addr = gateway_address(sc, ns, "gw").await?;
        apply_http_route(
            sc,
            &http_route(ns, "gw", "route")
                .path_prefix("/")
                .backend("echo", 8080)
                .build(),
        )
        .await?;
        wait_until_routed(&addr, "any.example", "/", StatusCode::OK).await
    };
    tokio::try_join!(pipeline, at_most_one_leader(&client, SINGLE_LEADER_WINDOW))?;

    Ok(())
}

/// For `window`, repeatedly ask every running CP replica whether it
/// acts as leader, failing if two ever say yes in the same sample.
/// A legitimate handover can't trip this: the old holder steps down
/// before its lease expires, and only then may a rival claim.
///
/// A replica that doesn't answer (starting, briefly unreachable) is
/// skipped for that sample, but only for [`UNANSWERED_LIMIT`] in a
/// row. And at least one sample must hear from every running replica
/// with exactly one leader among them, so the check can't pass
/// without having observed anything.
async fn at_most_one_leader(client: &Client, window: Duration) -> Result<()> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), CP_NAMESPACE);
    let deadline = Instant::now() + window;
    // Per pod: when its current run of unanswered samples began.
    let mut unanswered_since: HashMap<String, Instant> = HashMap::new();
    let mut confirmed = false;
    while Instant::now() < deadline {
        let running: Vec<String> = pods
            .list(&ListParams::default().labels("app=gateway-cp"))
            .await?
            .items
            .into_iter()
            .filter(|p| {
                p.metadata.deletion_timestamp.is_none()
                    && p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running")
            })
            .filter_map(|p| p.metadata.name)
            .collect();
        let answers =
            futures::future::join_all(running.iter().map(|pod| is_leader(client, pod))).await;
        let now = Instant::now();
        unanswered_since.retain(|pod, _| running.contains(pod));
        let mut leaders: Vec<&String> = Vec::new();
        let mut all_answered = true;
        for (pod, answer) in running.iter().zip(answers) {
            match answer {
                Ok(leader) => {
                    unanswered_since.remove(pod);
                    if leader {
                        leaders.push(pod);
                    }
                }
                Err(e) => {
                    all_answered = false;
                    let since = *unanswered_since.entry(pod.clone()).or_insert(now);
                    ensure!(
                        now.duration_since(since) < UNANSWERED_LIMIT,
                        "CP replica {pod} hasn't answered /leader for {UNANSWERED_LIMIT:?}: {e:#}"
                    );
                }
            }
        }
        ensure!(
            leaders.len() <= 1,
            "more than one CP replica acts as leader: {leaders:?}"
        );
        confirmed |= all_answered && !running.is_empty() && leaders.len() == 1;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    ensure!(
        confirmed,
        "no sample heard from every CP replica with exactly one leader"
    );
    Ok(())
}

/// Ask one CP pod's admin server (through the apiserver pod proxy)
/// whether it currently acts as leader. Non-2xx responses are errors
/// (`request_text` maps them to `kube::Error::Api`), and so is any
/// body other than the two the endpoint defines.
async fn is_leader(client: &Client, pod: &str) -> Result<bool> {
    let uri = format!("/api/v1/namespaces/{CP_NAMESPACE}/pods/{pod}:{CP_ADMIN_PORT}/proxy/leader");
    let req = http::Request::get(&uri)
        .body(Vec::new())
        .context("building pod proxy request")?;
    let body = client
        .request_text(req)
        .await
        .with_context(|| format!("GET {uri}"))?;
    match body.trim() {
        "leader" => Ok(true),
        "follower" => Ok(false),
        other => anyhow::bail!("GET {uri}: unexpected body {other:?}"),
    }
}

/// Current `holderIdentity`, if the lease exists and one is set.
async fn holder(leases: &Api<Lease>) -> Result<Option<String>> {
    Ok(leases
        .get_opt(LEASE_NAME)
        .await?
        .and_then(|l| l.spec)
        .and_then(|s| s.holder_identity)
        .filter(|h| !h.is_empty()))
}

/// Poll until the lease has a holder satisfying `pred`.
async fn wait_for_holder(leases: &Api<Lease>, pred: impl Fn(&str) -> bool) -> Result<String> {
    let deadline = Instant::now() + HANDOVER_DEADLINE;
    loop {
        if let Some(h) = holder(leases).await?
            && pred(&h)
        {
            return Ok(h);
        }
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for a lease holder"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
