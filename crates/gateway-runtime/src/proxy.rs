use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use gateway_config::backend::Endpoint;
use gateway_config::filter::TcpFilter;
use gateway_state::{ActiveListenerKind, BindKey, Store};
use tokio::net::TcpStream;

use crate::error::ProxyError;
use crate::lb::{Candidate, EndpointInfo, EndpointKey, LoadBalancer};

#[derive(Debug)]
pub(crate) struct Resolved {
    pub endpoint: Endpoint,
    pub info: Arc<EndpointInfo>,
    pub filters: Vec<TcpFilter>,
    pub route_name: String,
}

/// Walk `bind → listener → route → backend`, build candidates (filtering
/// evicted endpoints), and ask the picker. The read lock is released
/// before the picker runs.
pub(crate) fn resolve_endpoint(
    store: &Store,
    bind_key: &BindKey,
    lb: &LoadBalancer,
) -> Result<Resolved, ProxyError> {
    // Hold the read lock just long enough to clone the backend Arc + route data.
    let (backend, filters, route_name) = {
        let read = store.read();
        let bind = read.bind(bind_key).ok_or(ProxyError::BindGone)?;
        let listener = bind.listeners.first().ok_or(ProxyError::NoListener)?;
        let ActiveListenerKind::Tcp(tcp) = &listener.kind;
        let route = &tcp.route;
        let backend_ref = route.backends.first().ok_or(ProxyError::NoBackend)?;
        (
            Arc::clone(&backend_ref.backend),
            route.filters.clone(),
            route.key.name.clone(),
        )
    };

    if backend.endpoints.is_empty() {
        return Err(ProxyError::NoEndpoint);
    }

    let now = Instant::now();
    let candidates: Vec<Candidate> = backend
        .endpoints
        .iter()
        .filter_map(|ep| {
            let key = EndpointKey {
                backend: backend.key.clone(),
                endpoint: ep.name.clone(),
            };
            let info = lb.endpoint_state.get_or_create(key);
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

    let chosen = lb
        .picker
        .pick(&candidates)
        .ok_or(ProxyError::NoViableEndpoint)?;

    Ok(Resolved {
        endpoint: chosen.endpoint.clone(),
        info: Arc::clone(&chosen.info),
        filters,
        route_name,
    })
}

pub(crate) fn apply_filters(filters: &[TcpFilter], route_name: &str, peer: SocketAddr) {
    for f in filters {
        match f {
            TcpFilter::TcpConnectionLog { name } => {
                tracing::info!(filter = %name, route = %route_name, %peer, "tcp connection log");
            }
        }
    }
}

pub(crate) async fn handle_tcp_connection(
    store: Store,
    bind_key: BindKey,
    mut downstream: TcpStream,
    peer: SocketAddr,
    lb: Arc<LoadBalancer>,
) {
    let resolved = match resolve_endpoint(&store, &bind_key, lb.as_ref()) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(bind = %bind_key, ?e, "no destination; dropping connection");
            return;
        }
    };

    apply_filters(&resolved.filters, &resolved.route_name, peer);

    tracing::info!(
        bind = %bind_key,
        %peer,
        endpoint = %resolved.endpoint.name,
        upstream = %format!("{}:{}", resolved.endpoint.address, resolved.endpoint.port),
        "tcp connection accepted"
    );

    let _active = resolved.info.acquire();
    let dial_start = Instant::now();
    let mut upstream =
        match TcpStream::connect((resolved.endpoint.address, resolved.endpoint.port)).await {
            Ok(s) => {
                let dial_ms = dial_start.elapsed().as_secs_f64() * 1000.0;
                resolved.info.record_success(dial_ms);
                s
            }
            Err(e) => {
                resolved.info.record_failure();
                tracing::warn!(error = %e, "upstream dial failed");
                return;
            }
        };

    match tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await {
        Ok((from_client, from_upstream)) => {
            tracing::debug!(from_client, from_upstream, "tcp forward complete");
        }
        Err(e) => {
            tracing::debug!(error = %e, "tcp forward terminated");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use gateway_config::backend::{Backend, BackendRef, StaticBackend};
    use gateway_config::bind::{Bind, BindProtocol};
    use gateway_config::listener::{Listener, TcpListener};
    use gateway_config::route::TcpRoute;
    use gateway_state::{BindKey, Store};

    use crate::lb::{EndpointStateConfig, FirstCandidate, LoadBalancer};

    fn lb() -> LoadBalancer {
        LoadBalancer::with_picker(Arc::new(FirstCandidate), EndpointStateConfig::default())
    }

    fn lb_with_state(cfg: EndpointStateConfig) -> LoadBalancer {
        LoadBalancer::with_picker(Arc::new(FirstCandidate), cfg)
    }

    fn store_with_full_graph() -> Store {
        let store = Store::new();
        store.upsert_backend(Backend::Static(StaticBackend {
            name: "be".into(),
            endpoints: vec![Endpoint {
                name: "e0".into(),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 9999,
            }],
        }));
        store
            .upsert_bind(Bind {
                name: "b".into(),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 5432,
                bind_protocol: BindProtocol::Tcp,
                listeners: vec![Listener::Tcp(TcpListener {
                    name: "l".into(),
                    routes: vec![TcpRoute {
                        name: "r".into(),
                        backend_refs: vec![BackendRef {
                            name: "be".into(),
                            weight: 1,
                        }],
                        filters: vec![],
                    }],
                })],
            })
            .unwrap();
        store
    }

    #[test]
    fn resolve_endpoint_happy_path() {
        let store = store_with_full_graph();
        let r = resolve_endpoint(&store, &BindKey::new("b"), &lb()).unwrap();
        assert_eq!(r.endpoint.name, "e0");
        assert_eq!(r.endpoint.port, 9999);
        assert_eq!(r.route_name, "r");
    }

    #[test]
    fn resolve_endpoint_bind_gone() {
        let store = Store::new();
        let err = resolve_endpoint(&store, &BindKey::new("nope"), &lb()).unwrap_err();
        assert!(matches!(err, ProxyError::BindGone));
    }

    #[test]
    fn resolve_endpoint_no_listener() {
        let store = Store::new();
        store
            .upsert_bind(Bind {
                name: "b".into(),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 5432,
                bind_protocol: BindProtocol::Tcp,
                listeners: vec![],
            })
            .unwrap();
        let err = resolve_endpoint(&store, &BindKey::new("b"), &lb()).unwrap_err();
        assert!(matches!(err, ProxyError::NoListener));
    }

    #[test]
    fn resolve_endpoint_no_endpoint() {
        let store = Store::new();
        store.upsert_backend(Backend::Static(StaticBackend {
            name: "be".into(),
            endpoints: vec![],
        }));
        store
            .upsert_bind(Bind {
                name: "b".into(),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 5432,
                bind_protocol: BindProtocol::Tcp,
                listeners: vec![Listener::Tcp(TcpListener {
                    name: "l".into(),
                    routes: vec![TcpRoute {
                        name: "r".into(),
                        backend_refs: vec![BackendRef {
                            name: "be".into(),
                            weight: 1,
                        }],
                        filters: vec![],
                    }],
                })],
            })
            .unwrap();
        let err = resolve_endpoint(&store, &BindKey::new("b"), &lb()).unwrap_err();
        assert!(matches!(err, ProxyError::NoEndpoint));
    }

    #[test]
    fn returns_no_viable_when_all_evicted() {
        let store = store_with_full_graph();
        let lb = lb_with_state(EndpointStateConfig {
            ewma_alpha: 1.0,
            failure_threshold: 1,
            eviction_duration: Duration::from_mins(1),
        });
        let info = lb.endpoint_state.get_or_create(EndpointKey {
            backend: gateway_state::BackendKey::new("be"),
            endpoint: "e0".into(),
        });
        info.record_failure(); // threshold=1, so this evicts.
        let err = resolve_endpoint(&store, &BindKey::new("b"), &lb).unwrap_err();
        assert!(matches!(err, ProxyError::NoViableEndpoint));
    }
}
