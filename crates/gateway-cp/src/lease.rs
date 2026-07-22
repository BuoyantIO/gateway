//! Leader election over a `coordination.k8s.io/v1` Lease.
//!
//! Exactly one replica may write status and reconcile infra; every
//! replica still translates and serves data planes. The claiming
//! rules: the holder renews inside a grace window before expiry, a
//! rival waits out the current claim's expiry before trying,
//! takeovers bump `leaseTransitions`, and a
//! clean shutdown vacates the lease so the peer takes over
//! immediately. Writes are optimistic-concurrency replaces (the
//! `resourceVersion` of the last-seen lease rides along), so two
//! replicas racing for the same claim cannot both win: the loser
//! gets a conflict, re-reads, and backs off.

use std::time::Duration;

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, ObjectMeta, PostParams};
use tokio::sync::watch;

/// Lease object name; lives in the control plane's own namespace.
pub const LEASE_NAME: &str = "gateway-cp-leader";

/// How long a claim is valid without renewal.
const LEASE_DURATION: Duration = Duration::from_secs(15);
/// Renew once inside this window before expiry (so a healthy holder
/// renews roughly every `LEASE_DURATION - RENEW_GRACE` seconds).
const RENEW_GRACE: Duration = Duration::from_secs(10);
/// Delay before re-deciding after an apiserver error or conflict.
const RETRY: Duration = Duration::from_secs(2);

/// What the elector should do next, decided from the last-known
/// lease state. Pure so the claiming rules are unit-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    /// Write a claim now (free, expired, malformed, or ours and due
    /// for renewal).
    Claim,
    /// Sleep until this instant, then re-decide (someone else's
    /// claim is current, or ours doesn't need renewing yet).
    WaitUntil(Timestamp),
}

/// Run the elector until `shutdown` resolves, publishing leadership
/// transitions on `tx`. Apiserver errors are retried forever; if our
/// own claim lapses meanwhile the channel demotes to follower.
pub async fn run(
    client: kube::Client,
    namespace: &str,
    identity: String,
    tx: watch::Sender<bool>,
    shutdown: impl Future<Output = ()>,
) {
    let api: Api<Lease> = Api::namespaced(client, namespace);
    let mut shutdown = std::pin::pin!(shutdown);
    let mut known: Option<Lease> = None;

    loop {
        if known.is_none() {
            known = fetch_or_create(&api, namespace).await;
        }

        let now = Timestamp::now();
        let wait = match next_action(now, spec_of(known.as_ref()), &identity) {
            Action::Claim => match known.take() {
                // Fetch failed above: retry it.
                None => RETRY,
                Some(prev) => match claim(&api, &identity, prev, now).await {
                    Ok(lease) => {
                        known = Some(lease);
                        // Successful claims re-decide immediately and
                        // land in WaitUntil; rejections re-read first.
                        Duration::ZERO
                    }
                    Err(e) => {
                        if !is_conflict(&e) {
                            tracing::warn!(error = %e, "lease claim failed; retrying");
                        }
                        RETRY
                    }
                },
            },
            Action::WaitUntil(t) => {
                // Wake just past the boundary so the re-decide lands
                // on the other side of it.
                millis_until(now, t) + Duration::from_millis(100)
            }
        };

        publish(&tx, spec_of(known.as_ref()), &identity, Timestamp::now());

        if !wait.is_zero() {
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                () = tokio::time::sleep(wait) => {}
            }
            // A rival's claim may have been renewed (or vacated)
            // while we slept; never claim from a stale view.
            if !is_current_holder(spec_of(known.as_ref()), &identity, Timestamp::now()) {
                known = None;
            }
        }
    }

    // Held at shutdown: vacate so the peer claims immediately
    // instead of waiting out our expiry.
    if is_current_holder(spec_of(known.as_ref()), &identity, Timestamp::now())
        && let Some(lease) = known
        && let Err(e) = vacate(&api, lease).await
    {
        tracing::warn!(error = %e, "failed to vacate lease on shutdown");
    }
    let _ = tx.send(false);
}

/// Get the lease, creating it empty on first contact. `None` only on
/// apiserver errors (the caller retries).
async fn fetch_or_create(api: &Api<Lease>, namespace: &str) -> Option<Lease> {
    match api.get(LEASE_NAME).await {
        Ok(lease) => Some(lease),
        Err(kube::Error::Api(ae)) if ae.code == 404 => {
            let lease = Lease {
                metadata: ObjectMeta {
                    name: Some(LEASE_NAME.to_string()),
                    namespace: Some(namespace.to_string()),
                    ..Default::default()
                },
                spec: None,
            };
            match api.create(&PostParams::default(), &lease).await {
                Ok(lease) => Some(lease),
                // Lost the create race to the peer: read theirs.
                Err(kube::Error::Api(ae)) if ae.code == 409 => api.get(LEASE_NAME).await.ok(),
                Err(e) => {
                    tracing::warn!(error = %e, "failed to create lease; retrying");
                    None
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to read lease; retrying");
            None
        }
    }
}

/// Decide from the last-known lease state.
fn next_action(now: Timestamp, spec: Option<&LeaseSpec>, identity: &str) -> Action {
    let Some(spec) = spec else {
        return Action::Claim;
    };
    let Some(holder) = spec.holder_identity.as_deref().filter(|h| !h.is_empty()) else {
        return Action::Claim;
    };
    // A claim without renew time or duration can't be honored.
    let Some(expiry) = expiry_of(spec) else {
        return Action::Claim;
    };
    if now >= expiry {
        return Action::Claim;
    }
    if holder != identity {
        return Action::WaitUntil(expiry);
    }
    let renew_at = expiry - RENEW_GRACE;
    if now >= renew_at {
        Action::Claim
    } else {
        Action::WaitUntil(renew_at)
    }
}

/// Write a claim over `prev` (optimistic concurrency via `prev`'s
/// `resourceVersion`). Taking over from another/expired holder bumps
/// `leaseTransitions` and stamps a fresh `acquireTime`; a renewal
/// carries both forward.
async fn claim(
    api: &Api<Lease>,
    identity: &str,
    mut prev: Lease,
    now: Timestamp,
) -> Result<Lease, kube::Error> {
    let prev_spec = prev.spec.take().unwrap_or_default();
    let renewal = prev_spec.holder_identity.as_deref() == Some(identity);
    let transitions = prev_spec.lease_transitions.unwrap_or(0);
    prev.spec = Some(LeaseSpec {
        holder_identity: Some(identity.to_string()),
        lease_duration_seconds: Some(LEASE_DURATION.as_secs().try_into().unwrap_or(i32::MAX)),
        acquire_time: if renewal {
            prev_spec.acquire_time.or(Some(MicroTime(now)))
        } else {
            Some(MicroTime(now))
        },
        renew_time: Some(MicroTime(now)),
        lease_transitions: Some(if renewal {
            transitions
        } else {
            transitions + 1
        }),
        ..Default::default()
    });
    api.replace(LEASE_NAME, &PostParams::default(), &prev).await
}

/// Clear the holder fields (keeping the transition counter) so the
/// peer's next decision is `Claim`.
async fn vacate(api: &Api<Lease>, mut lease: Lease) -> Result<(), kube::Error> {
    let transitions = lease.spec.take().and_then(|s| s.lease_transitions);
    lease.spec = Some(LeaseSpec {
        lease_transitions: transitions,
        ..Default::default()
    });
    api.replace(LEASE_NAME, &PostParams::default(), &lease)
        .await?;
    Ok(())
}

fn publish(tx: &watch::Sender<bool>, spec: Option<&LeaseSpec>, identity: &str, now: Timestamp) {
    let leader = is_current_holder(spec, identity, now);
    tx.send_if_modified(|v| {
        if *v == leader {
            false
        } else {
            tracing::info!(leader, "leadership changed");
            *v = leader;
            true
        }
    });
}

fn is_current_holder(spec: Option<&LeaseSpec>, identity: &str, now: Timestamp) -> bool {
    spec.is_some_and(|s| {
        s.holder_identity.as_deref() == Some(identity)
            && expiry_of(s).is_some_and(|expiry| now < expiry)
    })
}

fn expiry_of(spec: &LeaseSpec) -> Option<Timestamp> {
    let MicroTime(renewed) = spec.renew_time.as_ref()?;
    let secs = spec.lease_duration_seconds?;
    Timestamp::from_millisecond(renewed.as_millisecond() + i64::from(secs) * 1000).ok()
}

fn spec_of(lease: Option<&Lease>) -> Option<&LeaseSpec> {
    lease.and_then(|l| l.spec.as_ref())
}

fn millis_until(now: Timestamp, target: Timestamp) -> Duration {
    u64::try_from(target.as_millisecond() - now.as_millisecond())
        .map_or(Duration::ZERO, Duration::from_millis)
}

fn is_conflict(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(ae) if ae.code == 409)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "cp-0";
    const OTHER: &str = "cp-1";

    fn ts(secs: i64) -> Timestamp {
        Timestamp::from_second(secs).unwrap()
    }

    fn spec(holder: &str, renewed_at: i64) -> LeaseSpec {
        LeaseSpec {
            holder_identity: Some(holder.to_string()),
            lease_duration_seconds: Some(15),
            renew_time: Some(MicroTime(ts(renewed_at))),
            acquire_time: Some(MicroTime(ts(renewed_at))),
            lease_transitions: Some(1),
            ..Default::default()
        }
    }

    #[test]
    fn unseen_lease_is_claimed() {
        assert_eq!(next_action(ts(100), None, ME), Action::Claim);
    }

    #[test]
    fn free_lease_is_claimed() {
        let s = LeaseSpec::default();
        assert_eq!(next_action(ts(100), Some(&s), ME), Action::Claim);
        let empty_holder = LeaseSpec {
            holder_identity: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(next_action(ts(100), Some(&empty_holder), ME), Action::Claim);
    }

    #[test]
    fn malformed_claim_is_claimed() {
        // Holder set but no renew time / duration: unenforceable.
        let s = LeaseSpec {
            holder_identity: Some(OTHER.to_string()),
            ..Default::default()
        };
        assert_eq!(next_action(ts(100), Some(&s), ME), Action::Claim);
    }

    #[test]
    fn rivals_current_claim_waits_out_its_expiry() {
        // Renewed at t=100, 15s duration: expires at t=115.
        let s = spec(OTHER, 100);
        assert_eq!(
            next_action(ts(100), Some(&s), ME),
            Action::WaitUntil(ts(115))
        );
        assert_eq!(next_action(ts(115), Some(&s), ME), Action::Claim);
        assert_eq!(next_action(ts(200), Some(&s), ME), Action::Claim);
    }

    #[test]
    fn own_fresh_claim_waits_until_renew_point() {
        // Expires at t=115, grace 10s: renew from t=105.
        let s = spec(ME, 100);
        assert_eq!(
            next_action(ts(100), Some(&s), ME),
            Action::WaitUntil(ts(105))
        );
    }

    #[test]
    fn own_claim_inside_grace_is_renewed() {
        let s = spec(ME, 100);
        assert_eq!(next_action(ts(105), Some(&s), ME), Action::Claim);
        assert_eq!(next_action(ts(114), Some(&s), ME), Action::Claim);
        // Even past expiry it's still ours to re-take.
        assert_eq!(next_action(ts(120), Some(&s), ME), Action::Claim);
    }

    #[test]
    fn holder_currency_respects_expiry() {
        let s = spec(ME, 100);
        assert!(is_current_holder(Some(&s), ME, ts(110)));
        assert!(!is_current_holder(Some(&s), ME, ts(115)));
        assert!(!is_current_holder(Some(&s), OTHER, ts(110)));
        assert!(!is_current_holder(None, ME, ts(110)));
    }
}
