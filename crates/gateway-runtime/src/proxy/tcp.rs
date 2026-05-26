//! TCP-only proxy path. Walks `bind → listener → route → backend` from
//! the shared store, picks an endpoint via the load balancer, and
//! splices bytes between downstream and upstream.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use gateway_config::backend::Endpoint;
use gateway_config::filter::TcpFilter as TcpFilterConfig;
use gateway_state::{ActiveListenerKind, ActiveRouteKind, BindKey, Store};
use tokio::net::TcpStream;

use crate::error::ProxyError;
use crate::lb::{EndpointInfo, LoadBalancer};

#[derive(Debug)]
pub(crate) struct Resolved {
    pub endpoint: Endpoint,
    pub info: Arc<EndpointInfo>,
    pub filters: Vec<TcpFilterConfig>,
    pub route_name: String,
}

// =================== filter trait + impls ===================

/// Runtime-side TCP filter contract. Each
/// `gateway_config::filter::TcpFilter` variant maps to one impl of
/// this trait via [`build_tcp_filter`].
///
/// Per the architecture doc (Area 03), TCP filters run "before TLS
/// termination or any peek." For the v0 plaintext-TCP path that
/// means immediately after `resolve_endpoint` returns a matched
/// route — there is no peek, no TLS, just the freshly-accepted
/// connection.
pub(crate) trait TcpFilter: Send + Sync {
    fn on_accept(&self, ctx: &TcpFilterContext<'_>) -> TcpFilterDecision;
}

pub(crate) struct TcpFilterContext<'a> {
    pub route_name: &'a str,
    pub peer: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpFilterDecision {
    Allow,
    Deny,
}

/// Build a runtime filter trait object from a config-shaped variant.
fn build_tcp_filter(cfg: &TcpFilterConfig) -> Arc<dyn TcpFilter> {
    match cfg {
        TcpFilterConfig::TcpConnectionLog { name } => Arc::new(TcpConnectionLogFilter {
            name: name.clone(),
        }),
    }
}

struct TcpConnectionLogFilter {
    name: String,
}

impl TcpFilter for TcpConnectionLogFilter {
    fn on_accept(&self, ctx: &TcpFilterContext<'_>) -> TcpFilterDecision {
        tracing::info!(
            filter = %self.name,
            route = %ctx.route_name,
            peer = %ctx.peer,
            "tcp connection log"
        );
        TcpFilterDecision::Allow
    }
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
        let ActiveListenerKind::Tcp(tcp) = &listener.kind else {
            // The accept-loop dispatch routes TCP binds only to this
            // function, so this branch is unreachable in practice. Return
            // a typed error rather than panic so a misconfigured store
            // can't crash the data plane.
            return Err(ProxyError::NoListener);
        };
        let ActiveRouteKind::Tcp(tr) = &tcp.route.kind else {
            // The store guarantees an `ActiveTcpListener` only carries a
            // route whose kind is `Tcp`. Same logic as above — bug-resistant
            // fallback rather than a panic.
            return Err(ProxyError::NoListener);
        };
        let backend_ref = tr.backends.first().ok_or(ProxyError::NoBackend)?;
        (
            Arc::clone(&backend_ref.backend),
            tr.filters.clone(),
            tcp.route.key.name.clone(),
        )
    };

    if backend.endpoints.is_empty() {
        return Err(ProxyError::NoEndpoint);
    }

    let (endpoint, info) = lb
        .pick_endpoint(&backend)
        .ok_or(ProxyError::NoViableEndpoint)?;

    Ok(Resolved {
        endpoint,
        info,
        filters,
        route_name,
    })
}

/// Run every filter on the matched route in declaration order. The
/// aggregate decision is `Deny` if *any* filter denies; otherwise
/// `Allow`. Filters always run to completion regardless of a prior
/// `Deny` so observability filters (`TcpConnectionLog`) still get to
/// see the connection — matches the architecture doc's "filters are
/// the ordered traffic-processing surface" framing where each filter
/// is given the chance to observe even if a peer in the chain has
/// already declined.
pub(crate) fn apply_filters(
    filters: &[TcpFilterConfig],
    route_name: &str,
    peer: SocketAddr,
) -> TcpFilterDecision {
    let ctx = TcpFilterContext { route_name, peer };
    let mut decision = TcpFilterDecision::Allow;
    for cfg in filters {
        let filter = build_tcp_filter(cfg);
        if matches!(filter.on_accept(&ctx), TcpFilterDecision::Deny) {
            decision = TcpFilterDecision::Deny;
        }
    }
    decision
}

pub(crate) async fn handle_connection(
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

    if matches!(
        apply_filters(&resolved.filters, &resolved.route_name, peer),
        TcpFilterDecision::Deny
    ) {
        tracing::debug!(
            bind = %bind_key,
            %peer,
            route = %resolved.route_name,
            "tcp filter denied connection"
        );
        return;
    }

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

    use crate::lb::{EndpointKey, EndpointStateConfig, FirstCandidate, LoadBalancer};

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
        info.record_failure();
        let err = resolve_endpoint(&store, &BindKey::new("b"), &lb).unwrap_err();
        assert!(matches!(err, ProxyError::NoViableEndpoint));
    }

    // --- filter trait dispatch ---

    fn test_peer() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)
    }

    #[test]
    fn apply_filters_empty_chain_allows() {
        assert_eq!(
            apply_filters(&[], "r", test_peer()),
            TcpFilterDecision::Allow
        );
    }

    #[test]
    fn apply_filters_connection_log_allows() {
        let filters = vec![TcpFilterConfig::TcpConnectionLog {
            name: "log".into(),
        }];
        assert_eq!(
            apply_filters(&filters, "r", test_peer()),
            TcpFilterDecision::Allow
        );
    }

    /// Test-only filter that always denies. Verifies the aggregate
    /// decision flips when any filter denies, and exercises the trait
    /// dispatch independently of which config variants exist today.
    struct DenyAllFilter;

    impl TcpFilter for DenyAllFilter {
        fn on_accept(&self, _ctx: &TcpFilterContext<'_>) -> TcpFilterDecision {
            TcpFilterDecision::Deny
        }
    }

    #[test]
    fn any_deny_short_circuits_to_deny() {
        let allow: Arc<dyn TcpFilter> = Arc::new(TcpConnectionLogFilter {
            name: "log".into(),
        });
        let deny: Arc<dyn TcpFilter> = Arc::new(DenyAllFilter);
        let ctx = TcpFilterContext {
            route_name: "r",
            peer: test_peer(),
        };

        // Aggregate manually using the same rule as `apply_filters` —
        // we can't go through `apply_filters` here because it builds
        // trait objects from the config enum, and we want to exercise
        // the aggregation with a deny-capable filter.
        let mut decision = TcpFilterDecision::Allow;
        for f in [&allow, &deny] {
            if matches!(f.on_accept(&ctx), TcpFilterDecision::Deny) {
                decision = TcpFilterDecision::Deny;
            }
        }
        assert_eq!(decision, TcpFilterDecision::Deny);
    }
}
