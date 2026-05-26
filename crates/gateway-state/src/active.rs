use std::net::IpAddr;
use std::sync::Arc;

use gateway_config::backend::Endpoint;
use gateway_config::bind::BindProtocol;
use gateway_config::filter::{HttpFilter, TcpFilter};
use gateway_config::route::HttpMatch;

use crate::key::{BackendKey, BindKey, ListenerKey, RouteKey};

#[derive(Debug, Clone)]
pub struct ActiveBind {
    pub key: BindKey,
    pub address: IpAddr,
    pub port: u16,
    pub bind_protocol: BindProtocol,
    pub listeners: Vec<Arc<ActiveListener>>,
}

#[derive(Debug, Clone)]
pub struct ActiveListener {
    pub key: ListenerKey,
    pub kind: ActiveListenerKind,
}

#[derive(Debug, Clone)]
pub enum ActiveListenerKind {
    Tcp(ActiveTcpListener),
    Http(ActiveHttpListener),
}

#[derive(Debug, Clone)]
pub struct ActiveTcpListener {
    /// The single active route under this TCP listener. Invariant: the
    /// store only ever places an `ActiveRoute` whose `kind` is
    /// `ActiveRouteKind::Tcp(_)` here. The runtime asserts this with a
    /// `let-else` rather than a panic.
    pub route: Arc<ActiveRoute>,
}

/// An HTTP listener with one or more active routes. Unlike `ActiveTcpListener`,
/// an HTTP listener supports multiple routes (one per matched path / host
/// combination). Route selection happens per-request in the runtime by
/// matching against `ActiveHttpRoute::matches`.
#[derive(Debug, Clone)]
pub struct ActiveHttpListener {
    /// Optional hostname filter for this listener. When set, the request's
    /// `:authority` (HTTP/2) or `Host` (HTTP/1.1) must match. `None` means
    /// catch-all.
    pub hostname: Option<String>,
    /// Active routes under this listener. Invariant: every entry's
    /// `kind` is `ActiveRouteKind::Http(_)`. Order is by route name
    /// (deterministic from the store's placement logic); the runtime
    /// is responsible for picking the longest-prefix path match.
    pub routes: Vec<Arc<ActiveRoute>>,
}

/// A resolved route, regardless of protocol kind. The `key` is on the
/// outer wrapper so generic walkers and the store's `active_routes`
/// map can be kind-agnostic; the kind-specific data sits in the
/// `kind` variant.
#[derive(Debug, Clone)]
pub struct ActiveRoute {
    pub key: RouteKey,
    pub kind: ActiveRouteKind,
}

#[derive(Debug, Clone)]
pub enum ActiveRouteKind {
    Tcp(ActiveTcpRoute),
    Http(ActiveHttpRoute),
}

#[derive(Debug, Clone)]
pub struct ActiveTcpRoute {
    pub filters: Vec<TcpFilter>,
    pub backends: Vec<ActiveBackendRef>,
}

#[derive(Debug, Clone)]
pub struct ActiveHttpRoute {
    pub matches: Vec<HttpMatch>,
    pub filters: Vec<HttpFilter>,
    pub backends: Vec<ActiveBackendRef>,
}

#[derive(Debug, Clone)]
pub struct ActiveBackendRef {
    pub backend: Arc<ActiveBackend>,
    pub weight: u32,
}

#[derive(Debug, Clone)]
pub struct ActiveBackend {
    pub key: BackendKey,
    pub endpoints: Vec<Endpoint>,
}
