//! Connection drain signalling.
//!
//! A watch channel broadcasts "start draining" and a bounded mpsc
//! channel of an uninhabited type acts as a drop-counting barrier —
//! [`Signal::drain`] completes only once every [`Watch`] and
//! [`ReleaseShutdown`] clone has been dropped, i.e. every in-flight
//! connection has finished.
//!
//! Dropping a `Signal` without draining also fires its watchers —
//! an owner that vanished means "drain now" — so owning a `Signal`
//! gives RAII teardown for free.
//!
//! Usage shape: each connection task holds a `Watch` clone and
//! races serving the connection against `watch.signaled()`. When the
//! signal fires, the task tells the connection to close gracefully
//! (HTTP/1 `Connection: close`, HTTP/2 GOAWAY), finishes it while
//! holding the returned [`ReleaseShutdown`], and only then lets the
//! barrier drop.

use tokio::sync::{mpsc, watch};

/// Uninhabited: the mpsc channel never carries a message, its
/// senders exist purely to be counted by their drop.
enum Never {}

/// Create a linked signal/watch pair.
pub fn channel() -> (Signal, Watch) {
    let (signal_tx, signal_rx) = watch::channel(false);
    let (barrier_tx, barrier_rx) = mpsc::channel::<Never>(1);
    (
        Signal {
            signal_tx,
            barrier_rx,
        },
        Watch {
            signals: vec![signal_rx],
            barriers: vec![barrier_tx],
        },
    )
}

/// The draining side: fires the signal and waits out the barrier.
pub struct Signal {
    signal_tx: watch::Sender<bool>,
    barrier_rx: mpsc::Receiver<Never>,
}

impl Signal {
    /// Start draining and resolve once every `Watch` and
    /// `ReleaseShutdown` has been dropped. With no watchers left this
    /// completes immediately.
    pub async fn drain(mut self) {
        let _ = self.signal_tx.send(true);
        // Watchers hold `barrier_tx` clones; `recv` yields `None`
        // exactly when the last one is gone (`Never` is uninhabited,
        // so no message can ever arrive first).
        let _ = self.barrier_rx.recv().await;
    }
}

/// The watching side, cloned into every connection task. Holding a
/// `Watch` (or the `ReleaseShutdown` it turns into) keeps every
/// [`Signal::drain`] it was built from pending. A watch made by
/// [`Watch::merge`] observes several signals at once: it fires when
/// any of them does, and blocks all of their barriers until released.
#[derive(Clone)]
pub struct Watch {
    signals: Vec<watch::Receiver<bool>>,
    barriers: Vec<mpsc::Sender<Never>>,
}

impl Watch {
    /// Combine two watches into one that fires when *either* signal
    /// does and holds *both* barriers until released. This is how a
    /// connection observes "process shutdown OR my bind's teardown"
    /// through a single future.
    #[must_use]
    pub fn merge(mut self, other: Watch) -> Watch {
        self.signals.extend(other.signals);
        self.barriers.extend(other.barriers);
        self
    }

    /// Resolve when draining starts on any merged signal. A `Signal`
    /// dropped without draining counts as fired — a vanished owner
    /// means "drain now" — which is what lets RAII teardown work:
    /// dropping a bind's
    /// session drops its `Signal` and its connections close. The
    /// returned handle keeps the barriers up until dropped.
    pub async fn signaled(mut self) -> ReleaseShutdown {
        {
            let mut races: Vec<_> = self
                .signals
                .iter_mut()
                .map(|rx| {
                    Box::pin(async move {
                        let _ = rx.wait_for(|v| *v).await;
                    })
                })
                .collect();
            std::future::poll_fn(|cx| {
                for race in &mut races {
                    if race.as_mut().poll(cx).is_ready() {
                        return std::task::Poll::Ready(());
                    }
                }
                std::task::Poll::Pending
            })
            .await;
        }
        ReleaseShutdown {
            _barriers: self.barriers,
        }
    }
}

/// Proof that a task observed the drain signal. Dropping it releases
/// the task's hold on every [`Signal::drain`] its watch observed.
pub struct ReleaseShutdown {
    _barriers: Vec<mpsc::Sender<Never>>,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn drain_with_no_watchers_completes_immediately() {
        let (signal, watch) = channel();
        drop(watch);
        timeout(Duration::from_secs(1), signal.drain())
            .await
            .expect("drain should complete");
    }

    #[tokio::test]
    async fn drain_blocks_while_a_watcher_holds_on() {
        let (signal, watch) = channel();
        let _held = watch.clone(); // never signaled, never dropped
        drop(watch);
        assert!(
            timeout(Duration::from_millis(100), signal.drain())
                .await
                .is_err(),
            "drain must not complete while a Watch is alive"
        );
    }

    #[tokio::test]
    async fn merged_watch_fires_on_either_signal() {
        for fire_first in [true, false] {
            let (sig_a, watch_a) = channel();
            let (sig_b, watch_b) = channel();
            let merged = watch_a.merge(watch_b);
            let held = tokio::spawn(async move {
                let release = merged.signaled().await;
                drop(release);
            });
            let (fire, keep) = if fire_first {
                (sig_a, sig_b)
            } else {
                (sig_b, sig_a)
            };
            timeout(Duration::from_secs(1), fire.drain())
                .await
                .expect("firing signal should drain once released");
            held.await.unwrap();
            drop(keep);
        }
    }

    #[tokio::test]
    async fn merged_watch_blocks_both_barriers_until_released() {
        let (sig_a, watch_a) = channel();
        let (sig_b, watch_b) = channel();
        let merged = watch_a.merge(watch_b);
        let held = tokio::spawn(async move {
            // Fired via A; B's drain must still wait for this handle.
            let release = merged.signaled().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(release);
        });
        timeout(Duration::from_secs(1), sig_a.drain())
            .await
            .expect("A should drain after release");
        // B never fired, but its barrier was held by the merged watch
        // and is free now that the release dropped.
        timeout(Duration::from_secs(1), sig_b.drain())
            .await
            .expect("B should drain immediately after release");
        held.await.unwrap();
    }

    #[tokio::test]
    async fn dropped_signal_fires_its_watchers() {
        let (signal, watch) = channel();
        let held = tokio::spawn(async move {
            let release = watch.signaled().await;
            drop(release);
        });
        // A Signal dropped without draining means "drain now".
        drop(signal);
        timeout(Duration::from_secs(1), held)
            .await
            .expect("watcher should fire on signal drop")
            .unwrap();
    }

    #[tokio::test]
    async fn multiple_watchers_all_gate_the_drain() {
        let (signal, watch) = channel();
        for delay in [10u64, 60, 120] {
            let w = watch.clone();
            tokio::spawn(async move {
                let release = w.signaled().await;
                tokio::time::sleep(Duration::from_millis(delay)).await;
                drop(release);
            });
        }
        drop(watch);
        let start = tokio::time::Instant::now();
        timeout(Duration::from_secs(1), signal.drain())
            .await
            .expect("drain should complete");
        assert!(start.elapsed() >= Duration::from_millis(120));
    }
}
