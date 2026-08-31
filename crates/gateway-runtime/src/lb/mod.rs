//! Load-balancer foundations. Picker trait, P2C-EWMA implementation,
//! per-endpoint runtime state. The picker is fed pre-built
//! `Candidate`s by the runtime; the state map is a clean seam so a
//! future dynamic-endpoint slice can swap in event-driven lifecycle
//! management without touching the picker.

pub mod p2c;
pub mod state;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use gateway_config::backend::Endpoint;
use gateway_state::ActiveBackend;

pub use p2c::{P2cConfig, P2cEwma};
pub use state::{
    ActiveHandle, EndpointInfo, EndpointKey, EndpointStateConfig, EndpointStateMap, Ewma, Snapshot,
};

/// Pre-resolved endpoint + its per-endpoint runtime state. Built by the
/// runtime per-pick and passed to the picker. Keeps the picker stateless
/// and decoupled from where `EndpointInfo` is stored.
pub struct Candidate<'a> {
    pub endpoint: &'a Endpoint,
    pub info: Arc<EndpointInfo>,
}

/// Endpoint picker. Implementations choose one candidate from the
/// slice the runtime built: the non-evicted endpoints, or — when
/// every endpoint is evicted — the evicted ones as a fail-open
/// fallback.
pub trait Picker: Send + Sync + 'static {
    /// Pick one candidate. Returns `None` only when the slice is empty.
    fn pick<'a>(&self, candidates: &'a [Candidate<'a>]) -> Option<&'a Candidate<'a>>;
}

/// Test/fallback picker that always returns the first candidate.
pub struct FirstCandidate;

impl Picker for FirstCandidate {
    fn pick<'a>(&self, candidates: &'a [Candidate<'a>]) -> Option<&'a Candidate<'a>> {
        candidates.first()
    }
}

/// Envelope: a picker plus the per-endpoint state map it scores against.
/// Picker-agnostic — the caller constructs whatever picker they want and
/// passes it in along with the state policy.
pub struct LoadBalancer {
    pub picker: Arc<dyn Picker>,
    pub endpoint_state: EndpointStateMap,
}

impl LoadBalancer {
    pub fn with_picker(picker: Arc<dyn Picker>, state_config: EndpointStateConfig) -> Self {
        Self {
            picker,
            endpoint_state: EndpointStateMap::new(state_config),
        }
    }

    /// Build candidates from `backend.endpoints()` (looking up
    /// `EndpointInfo` per endpoint) and ask the picker. Evicted
    /// endpoints are excluded while at least one non-evicted sibling
    /// exists; when every endpoint is evicted the picker runs over
    /// the evicted set instead — attempting a dial against the
    /// least-bad endpoint beats synthesizing an error, and a success
    /// clears the eviction on the spot.
    ///
    /// Returns `None` only when the backend has zero endpoints,
    /// which config validation already rejects for static backends;
    /// a dialable backend has none by construction and is not routed
    /// to through this path. The HTTP caller maps `None` to a
    /// synthesized `503 Service Unavailable`.
    pub fn pick_endpoint(
        &self,
        backend: &Arc<ActiveBackend>,
    ) -> Option<(Endpoint, Arc<EndpointInfo>)> {
        let now = Instant::now();
        let mut viable: Vec<Candidate<'_>> = Vec::new();
        let mut evicted: Vec<Candidate<'_>> = Vec::new();
        for ep in backend.endpoints() {
            let key = EndpointKey {
                backend: backend.key.clone(),
                endpoint: ep.name.clone(),
            };
            let info = self.endpoint_state.get_or_create(key);
            if info.is_evicted(now) {
                tracing::debug!(
                    endpoint = %ep.name,
                    backend = %backend.key,
                    "endpoint is evicted; skipping"
                );
                evicted.push(Candidate { endpoint: ep, info });
            } else {
                viable.push(Candidate { endpoint: ep, info });
            }
        }
        let candidates = if viable.is_empty() {
            if !evicted.is_empty() {
                tracing::debug!(
                    backend = %backend.key,
                    "all endpoints evicted; failing open over the evicted set"
                );
            }
            &evicted
        } else {
            &viable
        };
        let chosen = self.picker.pick(candidates)?;
        Some((chosen.endpoint.clone(), Arc::clone(&chosen.info)))
    }

    /// The runtime state a dialable backend accounts against: one
    /// logical endpoint keyed by the backend's own name, so its
    /// in-flight count, latency estimate and failure streak are kept
    /// exactly like an endpoint's and balanced and selected traffic
    /// account identically.
    ///
    /// There is nothing to choose between, so eviction is recorded
    /// but never consulted here — refusing to dial the only
    /// destination would fail every request for the eviction window,
    /// where an endpoint set in the same position fails open over
    /// its evicted members.
    pub fn dialable_state(&self, backend: &Arc<ActiveBackend>) -> Arc<EndpointInfo> {
        self.endpoint_state.get_or_create(EndpointKey {
            backend: backend.key.clone(),
            endpoint: backend.key.0.clone(),
        })
    }

    /// Look up the backend endpoint at `addr` and its runtime state,
    /// for a caller that chose the address itself. Returning the same
    /// pair as [`LoadBalancer::pick_endpoint`] keeps in-flight and
    /// latency accounting on one path.
    ///
    /// Eviction is not consulted: the caller has already decided, and
    /// its information about the endpoint is better than our
    /// dial-failure counters. If a backend lists one address twice,
    /// the first entry wins and its state is the one returned.
    pub fn endpoint_by_addr(
        &self,
        backend: &Arc<ActiveBackend>,
        addr: SocketAddr,
    ) -> Option<(Endpoint, Arc<EndpointInfo>)> {
        let endpoint = backend
            .endpoints()
            .iter()
            .find(|ep| ep.address == addr.ip() && ep.port == addr.port())?;
        let info = self.endpoint_state.get_or_create(EndpointKey {
            backend: backend.key.clone(),
            endpoint: endpoint.name.clone(),
        });
        Some((endpoint.clone(), info))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use gateway_config::backend::BackendProtocol;
    use gateway_state::{ActiveBackendKind, ActiveDialable, ActiveEndpointSet, BackendKey};

    fn endpoint(name: &str, port: u16) -> Endpoint {
        Endpoint {
            name: name.into(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
        }
    }

    fn backend(endpoints: Vec<Endpoint>) -> Arc<ActiveBackend> {
        Arc::new(ActiveBackend {
            key: BackendKey::new("be"),
            revision: 0,
            kind: ActiveBackendKind::Endpoints(ActiveEndpointSet {
                endpoints,
                protocol: BackendProtocol::Http1,
            }),
        })
    }

    fn dialable_backend() -> Arc<ActiveBackend> {
        Arc::new(ActiveBackend {
            key: BackendKey::new("be"),
            revision: 0,
            kind: ActiveBackendKind::Dialable(ActiveDialable {
                host: "api.example.com".into(),
                port: 443,
                path_prefix: None,
                tls: None,
            }),
        })
    }

    fn lb() -> LoadBalancer {
        LoadBalancer::with_picker(
            Arc::new(P2cEwma::default()),
            EndpointStateConfig {
                ewma_alpha: 0.5,
                failure_threshold: 1,
                eviction_duration: Duration::from_mins(1),
            },
        )
    }

    fn evict(lb: &LoadBalancer, backend: &Arc<ActiveBackend>, endpoint: &str) {
        let info = lb.endpoint_state.get_or_create(EndpointKey {
            backend: backend.key.clone(),
            endpoint: endpoint.into(),
        });
        info.record_failure(); // threshold = 1 evicts immediately
        assert!(info.is_evicted(Instant::now()));
    }

    #[test]
    fn zero_endpoints_returns_none() {
        let lb = lb();
        assert!(lb.pick_endpoint(&backend(vec![])).is_none());
    }

    #[test]
    fn dialable_backend_offers_no_endpoint() {
        let lb = lb();
        let be = dialable_backend();
        assert!(lb.pick_endpoint(&be).is_none());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        assert!(lb.endpoint_by_addr(&be, addr).is_none());
    }

    #[test]
    fn dialable_state_is_one_logical_endpoint_keyed_by_name() {
        let lb = lb();
        let be = dialable_backend();
        let info = lb.dialable_state(&be);
        // Same state on every request, and the same state the
        // endpoint map would hand out for an endpoint named after
        // the backend: balanced and selected traffic account
        // against one entry.
        assert!(Arc::ptr_eq(&info, &lb.dialable_state(&be)));
        assert!(Arc::ptr_eq(
            &info,
            &lb.endpoint_state.get_or_create(EndpointKey {
                backend: be.key.clone(),
                endpoint: be.key.0.clone(),
            })
        ));
        // Dial failures count toward eviction like any endpoint's,
        // even though nothing consults it for a dialable backend.
        info.record_failure(); // threshold = 1 evicts immediately
        assert!(info.is_evicted(Instant::now()));
    }

    #[test]
    fn all_evicted_fails_open() {
        let lb = lb();
        let be = backend(vec![endpoint("e0", 1), endpoint("e1", 2)]);
        evict(&lb, &be, "e0");
        evict(&lb, &be, "e1");
        for _ in 0..100 {
            assert!(
                lb.pick_endpoint(&be).is_some(),
                "all-evicted backend must still yield a pick"
            );
        }
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn endpoint_by_addr_finds_healthy_and_evicted_alike() {
        let lb = lb();
        let be = backend(vec![endpoint("e0", 1), endpoint("e1", 2)]);
        evict(&lb, &be, "e0");

        let (chosen, _) = lb.endpoint_by_addr(&be, addr(1)).expect("evicted is found");
        assert_eq!(chosen.name, "e0");
        let (chosen, _) = lb.endpoint_by_addr(&be, addr(2)).expect("healthy is found");
        assert_eq!(chosen.name, "e1");
    }

    #[test]
    fn endpoint_by_addr_misses_an_address_the_backend_lacks() {
        let lb = lb();
        let be = backend(vec![endpoint("e0", 1)]);
        assert!(lb.endpoint_by_addr(&be, addr(9)).is_none());
    }

    #[test]
    fn endpoint_by_addr_shares_state_with_the_picked_path() {
        let lb = lb();
        let be = backend(vec![endpoint("e0", 1)]);

        let (_, looked_up) = lb.endpoint_by_addr(&be, addr(1)).unwrap();
        let picked = lb.endpoint_state.get_or_create(EndpointKey {
            backend: be.key.clone(),
            endpoint: "e0".into(),
        });
        assert!(
            Arc::ptr_eq(&looked_up, &picked),
            "both paths must record into one state instance"
        );
    }

    #[test]
    fn evicted_endpoint_excluded_while_healthy_sibling_exists() {
        let lb = lb();
        let be = backend(vec![endpoint("e0", 1), endpoint("e1", 2)]);
        evict(&lb, &be, "e0");
        for _ in 0..100 {
            let (chosen, _) = lb.pick_endpoint(&be).unwrap();
            assert_eq!(chosen.name, "e1", "evicted endpoint must not be picked");
        }
    }
}
