use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::pin;

use gateway_state::{BindEvent, BindKey, Store};
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;

use crate::accept;
use crate::error::RuntimeError;

/// The gateway data-plane runtime. Subscribes to `BindEvent`s from a
/// `Store` and manages one accept task per active bind.
pub struct Gateway {
    store: Store,
}

impl Gateway {
    #[must_use]
    pub fn new(store: Store) -> Self {
        Self { store }
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
        let mut tasks: HashMap<BindKey, JoinHandle<()>> = HashMap::new();
        let mut addr_for: HashMap<BindKey, SocketAddr> = HashMap::new();

        // Seed: spawn an accept task for every currently-active bind.
        let initial: Vec<_> = self.store.read().binds().collect();
        for bind in initial {
            spawn_for_bind(&self.store, &bind.key, &mut tasks, &mut addr_for);
        }

        let mut shutdown = pin!(shutdown);
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => break,
                evt = rx.recv() => match evt {
                    Ok(BindEvent::Added(k) | BindEvent::Updated(k)) => {
                        // Look up the current state of this bind.
                        let new_addr = self.store.read().bind(&k)
                            .map(|b| SocketAddr::new(b.address, b.port));
                        if let Some(new) = new_addr {
                            let respawn = addr_for.get(&k) != Some(&new);
                            if respawn {
                                if let Some(h) = tasks.remove(&k) {
                                    h.abort();
                                }
                                spawn_for_bind(&self.store, &k, &mut tasks, &mut addr_for);
                            }
                            // If address unchanged, the running accept loop will
                            // see fresh route/backend state on its next accept.
                        } else {
                            if let Some(h) = tasks.remove(&k) {
                                h.abort();
                            }
                            addr_for.remove(&k);
                        }
                    }
                    Ok(BindEvent::Removed(k)) => {
                        if let Some(h) = tasks.remove(&k) {
                            h.abort();
                        }
                        addr_for.remove(&k);
                    }
                    Err(RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "bind event channel lagged; resyncing");
                        for (_, h) in tasks.drain() {
                            h.abort();
                        }
                        addr_for.clear();
                        let snapshot: Vec<_> = self.store.read().binds().collect();
                        for bind in snapshot {
                            spawn_for_bind(&self.store, &bind.key, &mut tasks, &mut addr_for);
                        }
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        }

        for (_, h) in tasks {
            h.abort();
        }
        Ok(())
    }
}

fn spawn_for_bind(
    store: &Store,
    key: &BindKey,
    tasks: &mut HashMap<BindKey, JoinHandle<()>>,
    addr_for: &mut HashMap<BindKey, SocketAddr>,
) {
    let Some(bind) = store.read().bind(key) else {
        return;
    };
    let addr = SocketAddr::new(bind.address, bind.port);
    let store = store.clone();
    let bind_key = key.clone();
    let handle = tokio::spawn(async move {
        accept::run_bind(store, bind_key, addr).await;
    });
    tasks.insert(key.clone(), handle);
    addr_for.insert(key.clone(), addr);
}
