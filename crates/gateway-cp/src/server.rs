//! gRPC server.
//!
//! `ServerState` is the shared mutable surface: it holds the last
//! translated world (a map of per-Gateway snapshots) and a broadcast
//! channel per Gateway. The kube-watch driven loop calls
//! [`ServerState::publish`] on each translate-and-diff pass; per-DP
//! gRPC handlers call [`ServerState::subscribe`] then read the
//! bootstrap.
//!
//! Flow when a DP connects:
//! 1. Receive `Hello`, parse `client_id` as `{ns}/{name}`.
//! 2. Subscribe to that Gateway's broadcast channel **before** reading
//!    the world, so any concurrent `publish` is delivered as a delta
//!    rather than lost.
//! 3. Read the world's slice for the Gateway, send it as one
//!    bootstrap `ConfigUpdate` with `sync_complete = true`. If no
//!    slice exists yet (unknown Gateway), the bootstrap is empty.
//! 4. Forward broadcast items until the stream closes.

use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;

use gateway_cp_proto::v1 as pb;
use gateway_cp_proto::v1::config_stream_server::ConfigStream;
use parking_lot::RwLock;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::diff::diff;
use crate::snapshot::{GatewayId, Snapshot};

const BROADCAST_CAPACITY: usize = 64;
const CLIENT_QUEUE_CAPACITY: usize = 16;

/// State shared between the translator-driven publish loop and the
/// per-DP gRPC handlers.
#[derive(Default)]
pub struct ServerState {
    world: RwLock<HashMap<GatewayId, Snapshot>>,
    channels: RwLock<HashMap<GatewayId, broadcast::Sender<pb::ConfigUpdate>>>,
}

impl ServerState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically swap in `next` and broadcast a per-Gateway diff
    /// against the previous world. Channels are created lazily for
    /// Gateways that didn't exist before. Sends to channels with no
    /// receivers are dropped silently.
    pub fn publish(&self, next: &HashMap<GatewayId, Snapshot>) {
        let prev = {
            let mut world = self.world.write();
            std::mem::replace(&mut *world, next.clone())
        };

        let mut ids: HashSet<&GatewayId> = HashSet::new();
        ids.extend(prev.keys());
        ids.extend(next.keys());

        let empty = Snapshot::default();
        for id in ids {
            let prev_slice = prev.get(id).unwrap_or(&empty);
            let next_slice = next.get(id).unwrap_or(&empty);
            let Some(batch) = diff(prev_slice, next_slice) else {
                continue;
            };
            let sender = self.channel_for(id);
            // Err means no live receivers; the next subscribe will
            // bootstrap from `world` and catch up.
            let _ = sender.send(batch);
        }
    }

    /// Subscribe to a Gateway's delta stream. Always called BEFORE
    /// reading the bootstrap so no in-flight delta is lost.
    fn subscribe(&self, gw_id: &GatewayId) -> broadcast::Receiver<pb::ConfigUpdate> {
        self.channel_for(gw_id).subscribe()
    }

    /// Build a bootstrap `ConfigUpdate` for `gw_id`. If the world has
    /// no slice for it, returns an empty `sync_complete = true`
    /// message so the DP knows to stop waiting on initial state.
    fn bootstrap(&self, gw_id: &GatewayId) -> pb::ConfigUpdate {
        let world = self.world.read();
        match world.get(gw_id) {
            Some(snap) => snapshot_to_bootstrap(snap),
            None => pb::ConfigUpdate {
                upserts: Vec::new(),
                removes: Vec::new(),
                sync_complete: true,
            },
        }
    }

    fn channel_for(&self, gw_id: &GatewayId) -> broadcast::Sender<pb::ConfigUpdate> {
        if let Some(s) = self.channels.read().get(gw_id) {
            return s.clone();
        }
        let mut channels = self.channels.write();
        channels
            .entry(gw_id.clone())
            .or_insert_with(|| broadcast::channel(BROADCAST_CAPACITY).0)
            .clone()
    }
}

/// The gRPC service wrapper.
pub struct ConfigStreamService {
    state: Arc<ServerState>,
}

impl ConfigStreamService {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl ConfigStream for ConfigStreamService {
    type WatchStream =
        Pin<Box<dyn tokio_stream::Stream<Item = Result<pb::ConfigUpdate, Status>> + Send>>;

    async fn watch(
        &self,
        request: Request<Streaming<pb::ConfigRequest>>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let state = self.state.clone();
        let mut req_stream = request.into_inner();

        let gw_id = read_hello(&mut req_stream).await?;
        tracing::info!(?gw_id, "data plane connected");

        // Subscribe BEFORE reading the bootstrap so any concurrent
        // publish lands as a delta we'll forward, not a lost update.
        let rx = state.subscribe(&gw_id);
        let bootstrap = state.bootstrap(&gw_id);

        let (tx, rx_out) = mpsc::channel::<Result<pb::ConfigUpdate, Status>>(CLIENT_QUEUE_CAPACITY);

        // Push the bootstrap first.
        if tx.send(Ok(bootstrap)).await.is_err() {
            // Client hung up; nothing more to do.
            return Ok(Response::new(Box::pin(ReceiverStream::new(rx_out))));
        }

        tokio::spawn(forward_deltas(rx, tx));

        Ok(Response::new(Box::pin(ReceiverStream::new(rx_out))))
    }
}

/// Pump broadcast deltas into the client mpsc until either side
/// closes.
///
/// `Lagged` is the interesting case: a slow client fell behind the
/// broadcast capacity and dropped intermediate diffs. Because each
/// delta is *incremental* relative to the DP's known state, silently
/// continuing would let the DP's view drift from the CP's world. The
/// fix is to terminate the stream — the DP's `run` loop reconnects,
/// re-bootstraps from the current `world`, and its reconnect-purge
/// drops anything stale.
async fn forward_deltas(
    mut rx: broadcast::Receiver<pb::ConfigUpdate>,
    tx: mpsc::Sender<Result<pb::ConfigUpdate, Status>>,
) {
    loop {
        match rx.recv().await {
            // Normal delta. `tx.send` Err means the client hung up.
            Ok(update) => {
                if tx.send(Ok(update)).await.is_err() {
                    return;
                }
            }
            // Slow consumer: surface `DataLoss` so the DP knows why
            // it's being kicked, then exit (dropping tx closes the
            // stream). DP-side: stream returns Err -> reconnect.
            Err(broadcast::error::RecvError::Lagged(missed)) => {
                tracing::warn!(
                    missed,
                    "data plane lagged; closing stream to force re-bootstrap"
                );
                let _ = tx
                    .send(Err(Status::data_loss(format!(
                        "missed {missed} updates; reconnect to re-bootstrap"
                    ))))
                    .await;
                return;
            }
            // Sender (and all clones) dropped — graceful shutdown.
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

// ==================== helpers ====================

async fn read_hello(stream: &mut Streaming<pb::ConfigRequest>) -> Result<GatewayId, Status> {
    let first = stream
        .message()
        .await?
        .ok_or_else(|| Status::cancelled("stream closed before Hello"))?;
    let Some(pb::config_request::Kind::Hello(hello)) = first.kind else {
        return Err(Status::invalid_argument("expected Hello as first message"));
    };
    parse_client_id(&hello.client_id)
}

fn parse_client_id(s: &str) -> Result<GatewayId, Status> {
    let (ns, name) = s.split_once('/').ok_or_else(|| {
        Status::invalid_argument(format!(
            "client_id must be '{{namespace}}/{{name}}', got: {s:?}"
        ))
    })?;
    if ns.is_empty() || name.is_empty() {
        return Err(Status::invalid_argument(format!(
            "client_id has empty namespace or name: {s:?}"
        )));
    }
    Ok((ns.to_string(), name.to_string()))
}

/// Flatten a `Snapshot` into a single bootstrap `ConfigUpdate`.
/// Order: Bind → Backend → Secret → Listener → `HttpRoute` —
/// convention only; the Store handles ordering via its stashing model.
fn snapshot_to_bootstrap(snap: &Snapshot) -> pb::ConfigUpdate {
    let mut upserts = Vec::with_capacity(
        snap.binds.len()
            + snap.backends.len()
            + snap.secrets.len()
            + snap.listeners.len()
            + snap.routes.len(),
    );
    for b in snap.binds.values() {
        upserts.push(pb::Upsert {
            body: Some(pb::upsert::Body::Bind(b.clone())),
        });
    }
    for b in snap.backends.values() {
        upserts.push(pb::Upsert {
            body: Some(pb::upsert::Body::Backend(b.clone())),
        });
    }
    for s in snap.secrets.values() {
        upserts.push(pb::Upsert {
            body: Some(pb::upsert::Body::Secret(s.clone())),
        });
    }
    for l in snap.listeners.values() {
        upserts.push(pb::Upsert {
            body: Some(pb::upsert::Body::Listener(l.clone())),
        });
    }
    for r in snap.routes.values() {
        upserts.push(pb::Upsert {
            body: Some(pb::upsert::Body::HttpRoute(r.clone())),
        });
    }
    pb::ConfigUpdate {
        upserts,
        removes: Vec::new(),
        sync_complete: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_state::{BackendKey, BindKey, ListenerKey, RouteKey, SecretKey};

    fn bind_upsert(name: &str, port: u32) -> pb::BindUpsert {
        pb::BindUpsert {
            name: name.into(),
            address: "0.0.0.0".into(),
            port,
            bind_protocol: pb::BindProtocol::Http as i32,
        }
    }

    fn slice_with_bind(name: &str, port: u32) -> Snapshot {
        let mut snap = Snapshot::default();
        snap.binds
            .insert(BindKey::new(name), bind_upsert(name, port));
        snap
    }

    /// A slice holding exactly one of every entity kind, for asserting
    /// the bootstrap flattens all of them.
    fn slice_with_every_entity() -> Snapshot {
        let mut snap = slice_with_bind("b", 443);
        snap.backends.insert(
            BackendKey::new("be"),
            pb::BackendUpsert {
                name: "be".into(),
                endpoints: vec![],
                protocol: pb::BackendProtocol::Http1 as i32,
            },
        );
        snap.secrets.insert(
            SecretKey::new("demo", "tls"),
            pb::SecretUpsert {
                namespace: "demo".into(),
                name: "tls".into(),
                cert_pem: "cert".into(),
                key_pem: "key".into(),
            },
        );
        snap.listeners.insert(
            ListenerKey::new(BindKey::new("b"), "l"),
            pb::ListenerUpsert {
                key: Some(pb::ListenerKey {
                    bind: "b".into(),
                    name: "l".into(),
                }),
                hostname: String::new(),
                has_hostname: false,
                tls: None,
            },
        );
        snap.routes.insert(
            RouteKey::new(ListenerKey::new(BindKey::new("b"), "l"), "r"),
            pb::HttpRouteUpsert {
                key: Some(pb::RouteKey {
                    bind: "b".into(),
                    listener: "l".into(),
                    name: "r".into(),
                }),
                matches: vec![],
                backend_refs: vec![],
                filters: vec![],
            },
        );
        snap
    }

    // --- parse_client_id ---

    #[test]
    fn parse_client_id_accepts_valid() {
        let id = parse_client_id("demo/api").unwrap();
        assert_eq!(id, ("demo".to_string(), "api".to_string()));
    }

    #[test]
    fn parse_client_id_rejects_missing_slash() {
        let err = parse_client_id("nope").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn parse_client_id_rejects_empty_namespace() {
        let err = parse_client_id("/api").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn parse_client_id_rejects_empty_name() {
        let err = parse_client_id("demo/").unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // --- bootstrap ---

    #[test]
    fn bootstrap_for_unknown_gateway_is_empty_sync_complete() {
        let state = ServerState::new();
        let update = state.bootstrap(&("ns".into(), "missing".into()));
        assert!(update.upserts.is_empty());
        assert!(update.removes.is_empty());
        assert!(update.sync_complete);
    }

    #[test]
    fn bootstrap_carries_every_entity_in_the_slice() {
        // One of every entity kind must survive the bootstrap flatten.
        // Guards against silently dropping a kind — the missing-Secret
        // bug being the motivating case (an HTTPS listener would stash
        // forever with no cert on the wire).
        let state = ServerState::new();
        let mut next = HashMap::new();
        next.insert(
            ("demo".to_string(), "api".to_string()),
            slice_with_every_entity(),
        );
        state.publish(&next);

        let update = state.bootstrap(&("demo".into(), "api".into()));
        assert!(update.removes.is_empty());
        assert!(update.sync_complete);

        let has = |pred: fn(&pb::upsert::Body) -> bool| {
            update
                .upserts
                .iter()
                .filter_map(|u| u.body.as_ref())
                .any(pred)
        };
        assert_eq!(update.upserts.len(), 5, "one upsert per entity kind");
        assert!(has(|b| matches!(b, pb::upsert::Body::Bind(_))), "bind");
        assert!(
            has(|b| matches!(b, pb::upsert::Body::Backend(_))),
            "backend"
        );
        assert!(has(|b| matches!(b, pb::upsert::Body::Secret(_))), "secret");
        assert!(
            has(|b| matches!(b, pb::upsert::Body::Listener(_))),
            "listener"
        );
        assert!(
            has(|b| matches!(b, pb::upsert::Body::HttpRoute(_))),
            "route"
        );
    }

    // --- publish + subscribe ---

    #[tokio::test]
    async fn publish_emits_diff_to_existing_subscriber() {
        let state = ServerState::new();
        let gw_id = ("demo".to_string(), "api".to_string());
        let mut rx = state.subscribe(&gw_id);

        let mut next = HashMap::new();
        next.insert(gw_id.clone(), slice_with_bind("b", 80));
        state.publish(&next);

        let delta = rx.recv().await.expect("delta received");
        assert_eq!(delta.upserts.len(), 1);
        assert!(!delta.sync_complete);
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_does_not_fail() {
        let state = ServerState::new();
        let mut next = HashMap::new();
        next.insert(
            ("demo".to_string(), "api".to_string()),
            slice_with_bind("b", 80),
        );
        // Should not panic even though nothing is subscribed.
        state.publish(&next);
    }

    #[tokio::test]
    async fn gateway_disappearance_emits_all_removes() {
        let state = ServerState::new();
        let gw_id = ("demo".to_string(), "api".to_string());

        // Publish a Gateway, then publish without it.
        let mut next = HashMap::new();
        next.insert(gw_id.clone(), slice_with_bind("b", 80));
        state.publish(&next);

        let mut rx = state.subscribe(&gw_id);

        // Empty world: Gateway disappeared.
        state.publish(&HashMap::new());

        let delta = rx.recv().await.expect("delta received");
        assert!(delta.upserts.is_empty());
        assert_eq!(delta.removes.len(), 1);
    }

    #[tokio::test]
    async fn changed_value_yields_upsert_delta() {
        let state = ServerState::new();
        let gw_id = ("demo".to_string(), "api".to_string());

        let mut first = HashMap::new();
        first.insert(gw_id.clone(), slice_with_bind("b", 80));
        state.publish(&first);

        let mut rx = state.subscribe(&gw_id);

        let mut second = HashMap::new();
        second.insert(gw_id.clone(), slice_with_bind("b", 81));
        state.publish(&second);

        let delta = rx.recv().await.expect("delta received");
        assert_eq!(delta.upserts.len(), 1);
        assert!(delta.removes.is_empty());
    }

    #[tokio::test]
    async fn forward_deltas_closes_with_data_loss_on_lag() {
        use std::time::Duration;

        // Drive Lagged deterministically: capacity-2 broadcast,
        // 10 messages published BEFORE the forwarder polls. The
        // receiver starts at position 0; the buffer only holds the
        // last 2, so the first recv() returns Lagged(8).
        let (sender, rx) = broadcast::channel::<pb::ConfigUpdate>(2);
        let (tx, mut consumer) = mpsc::channel::<Result<pb::ConfigUpdate, Status>>(16);

        for _ in 0..10 {
            let _ = sender.send(pb::ConfigUpdate {
                upserts: Vec::new(),
                removes: Vec::new(),
                sync_complete: false,
            });
        }

        let handle = tokio::spawn(forward_deltas(rx, tx));

        // Expect: a single DataLoss status, then the stream closes.
        let msg = tokio::time::timeout(Duration::from_secs(1), consumer.recv())
            .await
            .expect("got a message in time")
            .expect("channel still open");
        let status = msg.expect_err("expected Err(Status)");
        assert_eq!(status.code(), tonic::Code::DataLoss);

        let closed = tokio::time::timeout(Duration::from_secs(1), consumer.recv())
            .await
            .expect("recv resolves");
        assert!(closed.is_none(), "stream should close after DataLoss");

        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("forwarder exits")
            .expect("no panic");
    }

    #[tokio::test]
    async fn subscribe_before_publish_avoids_missing_delta() {
        let state = ServerState::new();
        let gw_id = ("demo".to_string(), "api".to_string());

        let mut rx = state.subscribe(&gw_id);
        let mut next = HashMap::new();
        next.insert(gw_id.clone(), slice_with_bind("b", 80));
        state.publish(&next);

        // bootstrap captures the new state...
        let bootstrap = state.bootstrap(&gw_id);
        assert_eq!(bootstrap.upserts.len(), 1);
        // ...AND the delta is on the channel.
        let delta = rx.recv().await.expect("delta received");
        assert_eq!(delta.upserts.len(), 1);
        // DP side applies both; upserts are idempotent so the
        // resulting Store state is correct either way.
    }
}
