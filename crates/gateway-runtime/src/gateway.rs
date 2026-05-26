use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;

use gateway_config::bind::BindProtocol;
use gateway_state::{BindEvent, BindKey, Store};
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;

use crate::accept;
use crate::error::RuntimeError;
use crate::lb::{EndpointStateConfig, LoadBalancer, P2cEwma};
use crate::proxy::http::HttpClient;

/// The gateway data-plane runtime. Subscribes to `BindEvent`s from a
/// `Store` and manages one accept task per active bind.
pub struct Gateway {
    /// Configuration store. Source of truth for binds, listeners,
    /// routes, and backends. Read briefly per dispatch via a `parking_lot`
    /// read lock; never held across awaits.
    pub(crate) store: Store,
    /// Load-balancer envelope: the picker plus its per-endpoint state.
    /// `Arc`-cloned into every per-connection task.
    pub(crate) lb: Arc<LoadBalancer>,
    /// Process-wide HTTP client used to dial upstreams from HTTP binds.
    /// Hyper's connection pool lives inside the client; it is `Clone`
    /// and every per-connection future shares the same pool.
    ///
    /// TODO: replace hyper's default pool with a destination-keyed
    /// pool (see proxy/http.rs for the full rationale).
    pub(crate) http_client: HttpClient,
}

impl Gateway {
    /// Default gateway: P2C-EWMA picker with default scoring + state policy.
    pub fn new(store: Store) -> Self {
        let lb =
            LoadBalancer::with_picker(Arc::new(P2cEwma::default()), EndpointStateConfig::default());
        Self::with_lb(store, lb)
    }

    /// Custom load balancer (caller-constructed picker + state policy).
    pub fn with_lb(store: Store, lb: LoadBalancer) -> Self {
        Self {
            store,
            lb: Arc::new(lb),
            http_client: HttpClient::default(),
        }
    }

    /// Run until `shutdown` resolves. Spawns accept tasks for every bind
    /// currently in the store, then drives the bind-event loop.
    ///
    /// On shutdown, all per-bind tasks are aborted; in-flight connections
    /// are dropped without drain.
    ///
    /// # Errors
    /// Returns `RuntimeError` if the event channel closes unexpectedly.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), RuntimeError> {
        let mut rx = self.store.subscribe();
        // One BindSession per active bind: the spawned accept task plus
        // the address it's listening on. Dropping a session aborts its
        // task; replacing the entry with `insert(...)` swaps in a new
        // session and drops the old one (aborting the old task).
        let mut sessions: HashMap<BindKey, BindSession> = HashMap::new();

        // Seed: spawn an accept task for every currently-active bind.
        let initial: Vec<_> = self.store.read().binds().collect();
        for bind in initial {
            if let Some(s) = self.spawn_session(&bind.key) {
                sessions.insert(bind.key.clone(), s);
            }
        }

        let mut shutdown = pin!(shutdown);
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                evt = rx.recv() => match evt {
                    Ok(BindEvent::Added(k) | BindEvent::Updated(k)) => {
                        let snapshot = self.store.read().bind(&k)
                            .map(|b| (SocketAddr::new(b.address, b.port), b.bind_protocol));
                        match snapshot {
                            Some((new_addr, new_proto)) => {
                                // Respawn only when the listening
                                // address OR protocol actually changed;
                                // if only route/backend state under the
                                // bind changed, the running task re-reads
                                // the store on its next accept.
                                let unchanged = sessions.get(&k).is_some_and(|s| {
                                    s.listening_addr == new_addr && s.bind_protocol == new_proto
                                });
                                if !unchanged {
                                    if let Some(s) = self.spawn_session(&k) {
                                        sessions.insert(k, s); // drops & aborts the old one if any
                                    } else {
                                        sessions.remove(&k);
                                    }
                                }
                            }
                            None => {
                                sessions.remove(&k);
                            }
                        }
                    }
                    Ok(BindEvent::Removed(k)) => {
                        sessions.remove(&k);
                    }
                    Err(RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "bind event channel lagged; resyncing");
                        sessions.clear();
                        let snapshot: Vec<_> = self.store.read().binds().collect();
                        for bind in snapshot {
                            if let Some(s) = self.spawn_session(&bind.key) {
                                sessions.insert(bind.key.clone(), s);
                            }
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }

        // Drop all remaining sessions → all accept tasks aborted.
        drop(sessions);
        Ok(())
    }

    fn spawn_session(&self, key: &BindKey) -> Option<BindSession> {
        let bind = self.store.read().bind(key)?;
        let addr = SocketAddr::new(bind.address, bind.port);
        let bind_protocol = bind.bind_protocol;
        let store = self.store.clone();
        let lb = Arc::clone(&self.lb);
        let http_client = self.http_client.clone();
        let bind_key = key.clone();
        let task = tokio::spawn(async move {
            accept::run_bind(store, bind_key, addr, bind_protocol, lb, http_client).await;
        });
        Some(BindSession {
            task,
            listening_addr: addr,
            bind_protocol,
        })
    }
}

/// A running per-bind accept task, paired with the socket address it's
/// listening on and the bind's protocol family. Dropping the session
/// aborts the task.
/// TODO: Handle proper draining of in-flight connections.
struct BindSession {
    task: JoinHandle<()>,
    listening_addr: SocketAddr,
    bind_protocol: BindProtocol,
}

impl Drop for BindSession {
    fn drop(&mut self) {
        self.task.abort();
    }
}
