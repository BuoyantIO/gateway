use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway_state::BackendKey;
use parking_lot::{Mutex, RwLock};

#[derive(Debug, Clone, Copy)]
pub struct Ewma {
    value: f64,
    alpha: f64,
}

impl Ewma {
    pub const fn new(alpha: f64, initial: f64) -> Self {
        Self {
            value: initial,
            alpha,
        }
    }

    pub fn update(&mut self, sample: f64) {
        self.value = self.alpha * sample + (1.0 - self.alpha) * self.value;
    }

    pub fn value(&self) -> f64 {
        self.value
    }
}

#[derive(Debug)]
struct Inner {
    health: Ewma,
    latency_ms: Ewma,
    in_flight: u64,
    consecutive_failures: u64,
    evicted_until: Option<Instant>,
}

/// Single-value snapshot taken under one lock — used by pickers for
/// scoring so they pay one mutex acquisition per pick.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    pub health: f64,
    pub latency_ms: f64,
    pub in_flight: u64,
}

/// Per-endpoint runtime state — health, latency, load, eviction.
///
/// TODO: optimize the lock granularity. Today everything lives under one
/// `Mutex<Inner>` for simplicity.
#[derive(Debug)]
pub struct EndpointInfo {
    inner: Mutex<Inner>,
    failure_threshold: u64,
    eviction_duration: Duration,
}

impl EndpointInfo {
    pub fn new(ewma_alpha: f64, failure_threshold: u64, eviction_duration: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner {
                health: Ewma::new(ewma_alpha, 1.0),
                latency_ms: Ewma::new(ewma_alpha, 0.0),
                in_flight: 0,
                consecutive_failures: 0,
                evicted_until: None,
            }),
            failure_threshold,
            eviction_duration,
        }
    }

    /// One-lock snapshot of the fields a picker needs to score.
    pub fn snapshot(&self) -> Snapshot {
        let i = self.inner.lock();
        Snapshot {
            health: i.health.value(),
            latency_ms: i.latency_ms.value(),
            in_flight: i.in_flight,
        }
    }

    pub fn in_flight(&self) -> u64 {
        self.inner.lock().in_flight
    }

    pub fn is_evicted(&self, now: Instant) -> bool {
        match self.inner.lock().evicted_until {
            Some(t) => now < t,
            None => false,
        }
    }

    pub fn record_success(&self, dial_ms: f64) {
        let mut i = self.inner.lock();
        i.consecutive_failures = 0;
        i.evicted_until = None;
        i.health.update(1.0);
        i.latency_ms.update(dial_ms);
    }

    pub fn record_failure(&self) {
        let mut i = self.inner.lock();
        i.consecutive_failures += 1;
        let n = i.consecutive_failures;
        i.health.update(0.0);
        if n >= self.failure_threshold {
            i.evicted_until = Some(Instant::now() + self.eviction_duration);
        }
    }

    pub fn acquire(self: &Arc<Self>) -> ActiveHandle {
        self.inner.lock().in_flight += 1;
        ActiveHandle(Arc::clone(self))
    }
}

/// RAII guard. Construction increments `in_flight`; Drop decrements it.
pub struct ActiveHandle(Arc<EndpointInfo>);

impl Drop for ActiveHandle {
    fn drop(&mut self) {
        self.0.inner.lock().in_flight -= 1;
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct EndpointKey {
    pub backend: BackendKey,
    pub endpoint: String,
}

/// Policy applied to every new `EndpointInfo` an `EndpointStateMap` creates.
/// Picker-agnostic.
#[derive(Debug, Clone)]
pub struct EndpointStateConfig {
    /// EWMA smoothing factor for health and latency (0..1; smaller = smoother).
    pub ewma_alpha: f64,
    /// Consecutive failures that trigger eviction.
    pub failure_threshold: u64,
    /// How long an evicted endpoint stays excluded from picks.
    pub eviction_duration: Duration,
}

impl Default for EndpointStateConfig {
    fn default() -> Self {
        Self {
            ewma_alpha: 0.1,
            failure_threshold: 5,
            eviction_duration: Duration::from_secs(30),
        }
    }
}

/// Per-endpoint runtime state, keyed by `(backend, endpoint name)`.
///
/// Each entry holds the metrics the LB picker reads — health EWMA,
/// dial-latency EWMA, in-flight connection count, consecutive failures,
/// eviction deadline. Lives outside the config store because it's
/// mutable runtime data, not configuration.
///
/// Entries are created lazily on first dispatch (`get_or_create`) and
/// live for the process lifetime. The struct is cheap to `clone` —
/// every per-connection task gets its own handle that shares the
/// inner Arc'd map.
/// TODO: add eviction of old entries, either via a background sweep or
/// TTL on the inner `Arc<EndpointInfo>`.
#[derive(Clone)]
pub struct EndpointStateMap {
    inner: Arc<RwLock<HashMap<EndpointKey, Arc<EndpointInfo>>>>,
    config: EndpointStateConfig,
}

impl EndpointStateMap {
    pub fn new(config: EndpointStateConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    pub fn get_or_create(&self, key: EndpointKey) -> Arc<EndpointInfo> {
        if let Some(info) = self.inner.read().get(&key) {
            return Arc::clone(info);
        }
        let mut w = self.inner.write();
        Arc::clone(w.entry(key).or_insert_with(|| {
            Arc::new(EndpointInfo::new(
                self.config.ewma_alpha,
                self.config.failure_threshold,
                self.config.eviction_duration,
            ))
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> EndpointInfo {
        EndpointInfo::new(0.5, 3, Duration::from_millis(50))
    }

    #[test]
    fn ewma_converges() {
        let mut e = Ewma::new(0.3, 0.0);
        for _ in 0..100 {
            e.update(1.0);
        }
        assert!((e.value() - 1.0).abs() < 1e-3);
    }

    #[test]
    fn record_failure_evicts_after_threshold() {
        let i = info();
        let now = Instant::now();
        assert!(!i.is_evicted(now));
        i.record_failure();
        i.record_failure();
        assert!(!i.is_evicted(now));
        i.record_failure(); // hits threshold = 3
        assert!(i.is_evicted(now));
    }

    #[test]
    fn record_success_resets_consecutive_failures() {
        let i = info();
        i.record_failure();
        i.record_failure();
        i.record_success(10.0);
        // Two more failures should NOT evict (counter was reset).
        i.record_failure();
        i.record_failure();
        assert!(!i.is_evicted(Instant::now()));
    }

    #[test]
    fn record_success_clears_eviction() {
        let i = info();
        for _ in 0..3 {
            i.record_failure();
        }
        assert!(i.is_evicted(Instant::now()));
        i.record_success(10.0);
        assert!(!i.is_evicted(Instant::now()));
    }

    #[test]
    fn acquire_increments_and_drop_decrements() {
        let i = Arc::new(info());
        assert_eq!(i.in_flight(), 0);
        let h = i.acquire();
        assert_eq!(i.in_flight(), 1);
        let h2 = i.acquire();
        assert_eq!(i.in_flight(), 2);
        drop(h);
        assert_eq!(i.in_flight(), 1);
        drop(h2);
        assert_eq!(i.in_flight(), 0);
    }

    #[test]
    fn snapshot_is_consistent() {
        let i = Arc::new(info());
        let _h1 = i.acquire();
        let _h2 = i.acquire();
        i.record_success(5.0);
        let s = i.snapshot();
        assert_eq!(s.in_flight, 2);
        assert!((s.latency_ms - 2.5).abs() < 1e-6); // alpha=0.5, initial=0, sample=5.0
        assert!(s.health > 0.0);
    }

    #[test]
    fn endpoint_state_map_get_or_create_is_idempotent() {
        let map = EndpointStateMap::new(EndpointStateConfig {
            ewma_alpha: 0.5,
            failure_threshold: 3,
            eviction_duration: Duration::from_millis(50),
        });
        let k = EndpointKey {
            backend: BackendKey::new("b"),
            endpoint: "e".into(),
        };
        let a = map.get_or_create(k.clone());
        let b = map.get_or_create(k.clone());
        assert!(Arc::ptr_eq(&a, &b));
    }
}
