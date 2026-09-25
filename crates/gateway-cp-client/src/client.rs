//! gRPC stream loop with reconnect. On each `sync_complete`, hand
//! the bootstrap key set to `Store::retain`.

use std::future::Future;
use std::pin::pin;
use std::time::Duration;

use gateway_cp_proto::v1 as pb;
use gateway_cp_proto::v1::config_stream_client::ConfigStreamClient;
use gateway_state::{RegisteredKeys, Store};
use rand::Rng;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Endpoint;

use crate::apply::{Affected, apply_update};
use crate::error::Error;

const BACKOFF_INITIAL: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Two ceilings because disconnection costs different things in the
/// two states. Before the first sync the store is empty and every
/// request is refused, so each second of backoff is a second of
/// downtime — retry hard. After it, the store keeps serving the last
/// config and a slow reconnect only delays updates, so the full
/// ceiling is fine.
const BACKOFF_MAX_COLD: Duration = Duration::from_secs(2);
const BACKOFF_FACTOR: u32 = 2;
const BACKOFF_JITTER: f64 = 0.2;
const REQUEST_CHANNEL_CAPACITY: usize = 4;

// Keepalive. The config stream is idle whenever the cluster is quiet,
// and an idle connection that dies without a FIN or an RST (a dropped
// conntrack entry, an LB idle timeout, a node that vanished under the
// control plane) is invisible to the reader: the next `message()`
// parks forever, the session never errors, and the data plane serves
// its last config while believing it is connected. The ping is what
// turns that into a transport error the reconnect loop can act on,
// which is why it has to be sent while idle.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Connect bound, so a dial into a black hole fails into the backoff
/// loop instead of hanging the way an established stream would.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// The control-plane channel, configured.
///
/// Callers build their endpoint through this rather than from the URL
/// directly: the keepalive settings above are the only thing that
/// makes a dead stream observable, and an endpoint assembled
/// elsewhere loses them silently; the data plane keeps serving, so
/// nothing reports the loss until someone notices stale config.
///
/// # Errors
/// `url` is not a valid gRPC endpoint.
pub fn endpoint(url: String) -> Result<Endpoint, Error> {
    Ok(Endpoint::try_from(url)?
        .connect_timeout(CONNECT_TIMEOUT)
        .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
        .keep_alive_timeout(KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true))
}

/// Run until `shutdown` resolves. Transient gRPC failures drop the
/// stream and reconnect; only a non-recoverable startup error escapes
/// as `Err`.
///
/// `client_id` is `"{namespace}/{gateway-name}"`; the CP filters
/// every `ConfigUpdate` on this stream to that one Gateway.
///
/// `ready` latches to `true` once the first `sync_complete` batch
/// has been applied. It is never set back to `false`: on reconnect
/// the store keeps serving its last state while the stream resyncs.
///
/// # Errors
/// Non-recoverable startup error before the backoff loop engages.
pub async fn run(
    endpoint: Endpoint,
    client_id: String,
    store: Store,
    ready: watch::Sender<bool>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    let mut shutdown = pin!(shutdown);
    let mut backoff = Backoff::new();

    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => return Ok(()),
            res = run_session(&endpoint, &client_id, &store, &ready) => {
                match res {
                    Ok(()) => {
                        tracing::info!("control-plane stream closed; reconnecting");
                        backoff.reset();
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "control-plane stream ended");
                    }
                }
            }
        }
        let mut delay = backoff.next();
        if !*ready.borrow() {
            delay = delay.min(BACKOFF_MAX_COLD);
        }
        tracing::debug!(?delay, "backing off before reconnect");
        tokio::select! {
            biased;
            () = &mut shutdown => return Ok(()),
            () = sleep(delay) => {}
        }
    }
}

async fn run_session(
    endpoint: &Endpoint,
    client_id: &str,
    store: &Store,
    ready: &watch::Sender<bool>,
) -> Result<(), Error> {
    let channel = endpoint.connect().await?;
    let mut client = ConfigStreamClient::new(channel);

    let (tx, rx) = mpsc::channel(REQUEST_CHANNEL_CAPACITY);
    let _ = tx
        .send(pb::ConfigRequest {
            kind: Some(pb::config_request::Kind::Hello(pb::Hello {
                client_id: client_id.to_string(),
            })),
        })
        .await;

    let response = client.watch(ReceiverStream::new(rx)).await?;
    let mut stream = response.into_inner();

    // Keys upserted before `sync_complete`. Used once, then dropped.
    let mut bootstrap_seen: Option<RegisteredKeys> = Some(RegisteredKeys::default());

    while let Some(update) = stream.message().await? {
        let sync_complete = update.sync_complete;

        let outcome = match apply_update(store, update) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(error = %e, "apply failed; CP push will retry");
                continue;
            }
        };

        if let Some(seen) = bootstrap_seen.as_mut() {
            accumulate(seen, &outcome.upserted);
        }

        if sync_complete {
            if let Some(seen) = bootstrap_seen.take() {
                store.retain(&seen);
            }
            ready.send_replace(true);
            tracing::info!("control-plane sync complete");
        }
    }
    Ok(())
}

// ==================== Backoff ====================

struct Backoff {
    current: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self {
            current: BACKOFF_INITIAL,
        }
    }

    fn reset(&mut self) {
        self.current = BACKOFF_INITIAL;
    }

    // Jitter math; delays are bounded seconds, casts are fine.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn next(&mut self) -> Duration {
        let base_ms = self.current.as_millis() as f64;
        let jitter_window = base_ms * BACKOFF_JITTER;
        let jitter = rand::rng().random_range(-jitter_window..=jitter_window);
        let with_jitter = (base_ms + jitter).max(0.0) as u64;
        let delay = Duration::from_millis(with_jitter);
        self.current = (self.current * BACKOFF_FACTOR).min(BACKOFF_MAX);
        delay
    }
}

/// Record every upserted key into the bootstrap keep-set. Every kind
/// must be listed: a kind missing here is purged by `Store::retain`
/// the moment the bootstrap completes.
fn accumulate(seen: &mut RegisteredKeys, upserted: &Affected) {
    for k in &upserted.binds {
        seen.binds.insert(k.clone());
    }
    for k in &upserted.listeners {
        seen.listeners.insert(k.clone());
    }
    for k in &upserted.routes {
        seen.routes.insert(k.clone());
    }
    for k in &upserted.backends {
        seen.backends.insert(k.clone());
    }
    for k in &upserted.secrets {
        seen.secrets.insert(k.clone());
    }
    for k in &upserted.extensions {
        seen.extensions.insert(k.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_then_caps() {
        let mut b = Backoff::new();
        let d1 = b.next();
        let d2 = b.next();
        let d3 = b.next();
        assert!(d2 >= d1);
        assert!(d3 >= d2);
        for _ in 0..20 {
            let _ = b.next();
        }
        assert!(b.next() <= BACKOFF_MAX * 2);
    }

    #[test]
    fn backoff_reset_returns_to_initial() {
        let mut b = Backoff::new();
        let _ = b.next();
        let _ = b.next();
        let _ = b.next();
        b.reset();
        let d = b.next();
        assert!(d <= BACKOFF_INITIAL * 2, "{d:?} should be ~initial");
    }

    #[test]
    fn accumulate_records_every_kind() {
        use gateway_state::{BackendKey, BindKey, ExtensionKey, ListenerKey, RouteKey, SecretKey};
        let upserted = Affected {
            binds: vec![BindKey::new("b")],
            listeners: vec![ListenerKey::new(BindKey::new("b"), "l")],
            routes: vec![RouteKey::new(ListenerKey::new(BindKey::new("b"), "l"), "r")],
            backends: vec![BackendKey::new("be")],
            secrets: vec![SecretKey::local("s")],
            extensions: vec![ExtensionKey::local("e")],
        };
        let mut seen = RegisteredKeys::default();
        accumulate(&mut seen, &upserted);
        assert_eq!(seen.binds.len(), 1);
        assert_eq!(seen.listeners.len(), 1);
        assert_eq!(seen.routes.len(), 1);
        assert_eq!(seen.backends.len(), 1);
        assert_eq!(seen.secrets.len(), 1);
        assert_eq!(
            seen.extensions.len(),
            1,
            "extensions must survive the bootstrap purge"
        );
    }
}
