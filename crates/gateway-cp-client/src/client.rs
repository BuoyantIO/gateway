//! gRPC stream loop with reconnect. On each `sync_complete`, hand
//! the bootstrap key set to `Store::retain`.

use std::future::Future;
use std::pin::pin;
use std::time::Duration;

use gateway_cp_proto::v1 as pb;
use gateway_cp_proto::v1::config_stream_client::ConfigStreamClient;
use gateway_state::{RegisteredKeys, Store};
use rand::Rng;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Endpoint;

use crate::apply::apply_update;
use crate::error::Error;

const BACKOFF_INITIAL: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
const BACKOFF_FACTOR: u32 = 2;
const BACKOFF_JITTER: f64 = 0.2;
const REQUEST_CHANNEL_CAPACITY: usize = 4;

/// Run until `shutdown` resolves. Transient gRPC failures drop the
/// stream and reconnect; only a non-recoverable startup error escapes
/// as `Err`.
///
/// `client_id` is `"{namespace}/{gateway-name}"`; the CP filters
/// every `ConfigUpdate` on this stream to that one Gateway.
///
/// # Errors
/// Non-recoverable startup error before the backoff loop engages.
pub async fn run(
    endpoint: Endpoint,
    client_id: String,
    store: Store,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    let mut shutdown = pin!(shutdown);
    let mut backoff = Backoff::new();

    loop {
        tokio::select! {
            biased;
            () = &mut shutdown => return Ok(()),
            res = run_session(&endpoint, &client_id, &store) => {
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
        let delay = backoff.next();
        tracing::debug!(?delay, "backing off before reconnect");
        tokio::select! {
            biased;
            () = &mut shutdown => return Ok(()),
            () = sleep(delay) => {}
        }
    }
}

async fn run_session(endpoint: &Endpoint, client_id: &str, store: &Store) -> Result<(), Error> {
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
            for k in &outcome.upserted.binds {
                seen.binds.insert(k.clone());
            }
            for k in &outcome.upserted.listeners {
                seen.listeners.insert(k.clone());
            }
            for k in &outcome.upserted.routes {
                seen.routes.insert(k.clone());
            }
            for k in &outcome.upserted.backends {
                seen.backends.insert(k.clone());
            }
            for k in &outcome.upserted.secrets {
                seen.secrets.insert(k.clone());
            }
        }

        if sync_complete {
            if let Some(seen) = bootstrap_seen.take() {
                store.retain(&seen);
            }
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
}
