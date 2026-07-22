use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;

use gateway_state::{BindEvent, BindKey, Store};
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;

use crate::accept;
use crate::drain;
use crate::error::RuntimeError;
use crate::lb::{EndpointStateConfig, LoadBalancer, P2cEwma};
use crate::proxy::http::HttpClient;

/// The gateway data-plane runtime. Subscribes to `BindEvent`s from a
/// `Store` and manages one accept task per active bind.
pub struct Gateway {
    /// Configuration store. Source of truth for binds, listeners,
    /// routes, and backends.
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

    /// Run until `drain` fires — the drain watch doubles as the
    /// shutdown signal. Spawns accept tasks for every bind
    /// currently in the store, then drives the bind-event loop.
    ///
    /// Every accepted connection watches the process drain merged
    /// with its own bind's drain: either one makes it close
    /// gracefully — `Connection: close` on HTTP/1, GOAWAY on HTTP/2 —
    /// after finishing in-flight work. Bind teardown is RAII:
    /// dropping a session drops its `Signal`, which fires its
    /// connections' watches. The caller owns the process barrier:
    /// after this returns, `Signal::drain` resolves once every
    /// connection has finished (bound it with a timeout).
    ///
    /// # Errors
    /// Returns `RuntimeError` if the event channel closes unexpectedly.
    pub async fn run(self, drain: drain::Watch) -> Result<(), RuntimeError> {
        let mut rx = self.store.subscribe();
        // One BindSession per active bind: the spawned accept task,
        // the address it listens on, and the drain signal for its
        // connections. Dropping a session aborts the accept task and
        // fires the signal; replacing an entry with `insert` tears
        // down the old one the same way.
        let mut sessions: HashMap<BindKey, BindSession> = HashMap::new();

        // Seed: spawn an accept task for every currently-active bind.
        let initial: Vec<_> = self.store.read().binds().collect();
        for bind in initial {
            if let Some(s) = self.spawn_session(&bind.key, &drain) {
                sessions.insert(bind.key.clone(), s);
            }
        }

        let mut stop = pin!(drain.clone().signaled());
        loop {
            tokio::select! {
                biased;
                _release = &mut stop => break,
                evt = rx.recv() => match evt {
                    Ok(BindEvent::Added(k) | BindEvent::Updated(k)) => {
                        let new_addr = self.store.read().bind(&k)
                            .map(|b| SocketAddr::new(b.address, b.port));
                        match new_addr {
                            Some(new) => {
                                // Respawn only when the listening
                                // address actually changed; route /
                                // backend changes are picked up by
                                // the running task on its next accept.
                                let unchanged = sessions.get(&k)
                                    .is_some_and(|s| s.listening_addr == new);
                                if !unchanged {
                                    if let Some(s) = self.spawn_session(&k, &drain) {
                                        sessions.insert(k, s);
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
                            if let Some(s) = self.spawn_session(&bind.key, &drain) {
                                sessions.insert(bind.key.clone(), s);
                            }
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }

        // Drop every session: accept tasks abort, bind signals fire,
        // connections close gracefully under the caller's barrier.
        drop(sessions);
        Ok(())
    }

    fn spawn_session(&self, key: &BindKey, process_drain: &drain::Watch) -> Option<BindSession> {
        let bind = self.store.read().bind(key)?;
        let addr = SocketAddr::new(bind.address, bind.port);
        let protocol = bind.bind_protocol;
        let store = self.store.clone();
        let lb = Arc::clone(&self.lb);
        let http_client = self.http_client.clone();
        let bind_key = key.clone();
        let (bind_signal, bind_drain) = drain::channel();
        // One merged watch per bind: connections fire on process
        // shutdown OR this bind's teardown through a single future.
        let conn_drain = process_drain.clone().merge(bind_drain);
        let task = tokio::spawn(async move {
            accept::run_bind(store, bind_key, addr, protocol, lb, http_client, conn_drain).await;
        });
        Some(BindSession {
            task,
            listening_addr: addr,
            _signal: bind_signal,
        })
    }
}

/// A running per-bind accept task, paired with the socket address it's
/// listening on and the drain signal for its connections. Teardown is
/// the `Drop`: the accept task aborts (stopping new connections) and
/// the signal drops, which fires the drain watch every connection of
/// this bind holds.
struct BindSession {
    task: JoinHandle<()>,
    listening_addr: SocketAddr,
    _signal: drain::Signal,
}

impl Drop for BindSession {
    fn drop(&mut self) {
        self.task.abort();
    }
}
