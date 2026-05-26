use std::net::IpAddr;
use std::sync::Arc;

use gateway_config::backend::Endpoint;
use gateway_config::bind::BindProtocol;
use gateway_config::filter::HttpFilter;
use gateway_config::route::HttpMatch;

use crate::key::{BackendKey, BindKey, ListenerKey, RouteKey};

#[derive(Debug, Clone)]
pub struct ActiveBind {
    pub key: BindKey,
    pub address: IpAddr,
    pub port: u16,
    /// Protocol family the operator declared for this bind. The store
    /// only accepts `Http` today, but the field stays on the data model
    /// regardless — protocol is a property of the bind, full stop.
    /// When HTTPS lands the runtime will read this for dispatch.
    pub bind_protocol: BindProtocol,
    pub listeners: Vec<Arc<ActiveHttpListener>>,
}

/// An HTTP listener with one or more active routes. Route selection
/// happens per-request in the runtime by matching against
/// `ActiveHttpRoute::matches`. Active when at least one HTTP route is
/// under it.
#[derive(Debug, Clone)]
pub struct ActiveHttpListener {
    pub key: ListenerKey,
    /// Optional hostname filter for this listener. When set, the
    /// request's `:authority` (HTTP/2) or `Host` (HTTP/1.1) must
    /// match. `None` means catch-all.
    pub hostname: Option<String>,
    /// Active routes under this listener. Order is by route name
    /// (deterministic from the store's placement logic); the runtime
    /// is responsible for picking the longest-prefix path match.
    pub routes: Vec<Arc<ActiveHttpRoute>>,
}

#[derive(Debug, Clone)]
pub struct ActiveHttpRoute {
    pub key: RouteKey,
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
