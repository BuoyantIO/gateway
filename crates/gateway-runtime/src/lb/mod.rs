//! Load-balancer foundations. Picker trait, P2C-EWMA implementation,
//! per-endpoint runtime state. The picker is fed pre-built
//! `Candidate`s by the runtime; the state map is a clean seam so a
//! future dynamic-endpoint slice can swap in event-driven lifecycle
//! management without touching the picker.

pub mod p2c;
pub mod state;

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

/// Endpoint picker. Implementations choose one candidate from a slice
/// already filtered of evicted/non-viable entries by the runtime.
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

    /// Build candidates from `backend.endpoints` (looking up
    /// `EndpointInfo` per endpoint and skipping evicted entries) and
    /// ask the picker. Returns the chosen endpoint paired with its
    /// runtime info, or `None` if no viable candidate exists.
    ///
    /// The caller decides what to do with `None`:
    /// - TCP maps it to `ProxyError::NoViableEndpoint`.
    /// - HTTP synthesizes a `503 Service Unavailable`.
    ///
    /// The "backend has zero endpoints" case is the caller's concern
    /// — TCP differentiates it as `ProxyError::NoEndpoint`; HTTP
    /// catches it during route resolution. Both paths therefore call
    /// this only when at least one endpoint exists.
    pub fn pick_endpoint(
        &self,
        backend: &Arc<ActiveBackend>,
    ) -> Option<(Endpoint, Arc<EndpointInfo>)> {
        let now = Instant::now();
        let candidates: Vec<Candidate<'_>> = backend
            .endpoints
            .iter()
            .filter_map(|ep| {
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
                    None
                } else {
                    Some(Candidate { endpoint: ep, info })
                }
            })
            .collect();
        let chosen = self.picker.pick(&candidates)?;
        Some((chosen.endpoint.clone(), Arc::clone(&chosen.info)))
    }
}
