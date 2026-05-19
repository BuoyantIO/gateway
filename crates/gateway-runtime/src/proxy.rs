use std::net::SocketAddr;

use gateway_config::backend::Endpoint;
use gateway_config::filter::TcpFilter;
use gateway_state::{ActiveListenerKind, BindKey, Store};
use tokio::net::TcpStream;

use crate::error::ProxyError;

/// Resolve the destination endpoint for a connection arriving on `bind_key`.
///
/// Walks `bind → listener → route → backend → endpoint` with the read lock
/// held briefly, clones what's needed, and drops the lock.
pub(crate) fn resolve_endpoint(
    store: &Store,
    bind_key: &BindKey,
) -> Result<(Endpoint, Vec<TcpFilter>, String), ProxyError> {
    let read = store.read();
    let bind = read.bind(bind_key).ok_or(ProxyError::BindGone)?;
    let listener = bind.listeners.first().ok_or(ProxyError::NoListener)?;
    let ActiveListenerKind::Tcp(tcp) = &listener.kind;
    let route = &tcp.route;
    let backend_ref = route.backends.first().ok_or(ProxyError::NoBackend)?;
    let endpoint = backend_ref
        .backend
        .endpoints
        .first()
        .ok_or(ProxyError::NoEndpoint)?
        .clone();
    let filters = route.filters.clone();
    let route_name = route.key.name.clone();
    Ok((endpoint, filters, route_name))
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
) {
    let (endpoint, filters, route_name) = match resolve_endpoint(&store, &bind_key) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(bind = %bind_key, ?e, "no destination; dropping connection");
            return;
        }
    };

    apply_filters(&filters, &route_name, peer);

    tracing::info!(
        bind = %bind_key,
        %peer,
        endpoint = %endpoint.name,
        upstream = %format!("{}:{}", endpoint.address, endpoint.port),
        "tcp connection accepted"
    );

    let mut upstream = match TcpStream::connect((endpoint.address, endpoint.port)).await {
        Ok(s) => s,
        Err(e) => {
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

    use gateway_config::backend::{Backend, BackendRef, StaticBackend};
    use gateway_config::bind::{Bind, BindProtocol};
    use gateway_config::listener::{Listener, TcpListener};
    use gateway_config::route::TcpRoute;
    use gateway_state::{BindKey, Store};

    fn store_with_full_graph() -> Store {
        let store = Store::new();
        store.upsert_backend(Backend::Static(StaticBackend {
            name: "be".into(),
            endpoints: vec![gateway_config::backend::Endpoint {
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
        let (ep, _, route) = resolve_endpoint(&store, &BindKey::new("b")).unwrap();
        assert_eq!(ep.name, "e0");
        assert_eq!(ep.port, 9999);
        assert_eq!(route, "r");
    }

    #[test]
    fn resolve_endpoint_bind_gone() {
        let store = Store::new();
        let err = resolve_endpoint(&store, &BindKey::new("nope")).unwrap_err();
        assert!(matches!(err, ProxyError::BindGone));
    }

    #[test]
    fn resolve_endpoint_no_listener() {
        // Bind exists but has no active listener (no route under it).
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
        let err = resolve_endpoint(&store, &BindKey::new("b")).unwrap_err();
        assert!(matches!(err, ProxyError::NoListener));
    }

    #[test]
    fn resolve_endpoint_no_endpoint() {
        let store = Store::new();
        // Backend present but with no endpoints. The schema validate
        // layer would reject this, but the state crate doesn't, so
        // we exercise the runtime's defense.
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
        let err = resolve_endpoint(&store, &BindKey::new("b")).unwrap_err();
        assert!(matches!(err, ProxyError::NoEndpoint));
    }
}
