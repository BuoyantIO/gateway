use std::net::IpAddr;
use std::sync::Arc;

use gateway_config::backend::{BackendProtocol, Endpoint};
use gateway_config::bind::BindProtocol;
use gateway_config::extension::Extension;
use gateway_config::filter::HttpFilter;
use gateway_config::route::HttpMatch;
use gateway_config::secret::TlsSecret;

use crate::key::{BackendKey, BindKey, ExtensionKey, ListenerKey, RouteKey};

#[derive(Debug, Clone)]
pub struct ActiveBind {
    pub key: BindKey,
    pub address: IpAddr,
    pub port: u16,
    /// Protocol family the operator declared for this bind. The runtime
    /// dispatches the accept path on it (`Http` plaintext vs `Tls`
    /// termination).
    pub bind_protocol: BindProtocol,
    pub listeners: Vec<Arc<ActiveListener>>,
}

/// A listener with one or more active routes that serves HTTP — either
/// plaintext, or after terminating TLS (`tls.is_some()`). Route
/// selection happens per-request in the runtime by matching against
/// `ActiveHttpRoute::matches`. Active when at least one route is under
/// it (and, for TLS, its certificate secrets are present).
///
/// TLS passthrough is a different data path (no HTTP routes) and is not
/// represented here.
#[derive(Debug, Clone)]
pub struct ActiveListener {
    pub key: ListenerKey,
    /// Optional hostname filter for this listener. When set, the
    /// request's `:authority` (HTTP/2) or `Host` (HTTP/1.1) must
    /// match. `None` means catch-all.
    pub hostname: Option<String>,
    /// Active routes under this listener. Order is by route name
    /// (deterministic from the store's placement logic); the runtime
    /// is responsible for picking the longest-prefix path match.
    pub routes: Vec<Arc<ActiveHttpRoute>>,
    /// `Some` for an HTTPS (terminating) listener — the resolved
    /// certificate material the runtime builds a TLS server config
    /// from. `None` for plaintext HTTP.
    pub tls: Option<ActiveTls>,
}

/// Resolved TLS material for a terminating listener. Holds the parsed
/// secrets (cert chain + key as DER); the runtime turns these into a
/// `rustls::ServerConfig`.
#[derive(Debug, Clone)]
pub struct ActiveTls {
    pub secrets: Vec<Arc<TlsSecret>>,
}

#[derive(Debug, Clone)]
pub struct ActiveHttpRoute {
    pub key: RouteKey,
    pub revision: u64,
    pub matches: Vec<HttpMatch>,
    pub filters: Vec<HttpFilter>,
    pub backends: Vec<ActiveBackendRef>,
    /// One entry per `ExtensionRef` filter, in filter order.
    pub extensions: Vec<ActiveExtensionRef>,
}

/// One `ExtensionRef` of a route: the name from the filter, plus the
/// object it resolved to. `None` while the named `Extension` is not
/// registered — requests through this route answer 500.
#[derive(Debug, Clone)]
pub struct ActiveExtensionRef {
    pub key: ExtensionKey,
    pub object: Option<Arc<Extension>>,
}

#[derive(Debug, Clone)]
pub struct ActiveBackendRef {
    /// The backend this ref names, registered or not.
    pub key: BackendKey,
    /// `None` while the named backend is not registered — traffic
    /// destined to this ref is answered with a synthesized 500.
    pub backend: Option<Arc<ActiveBackend>>,
    pub weight: u32,
}

#[derive(Debug, Clone)]
pub struct ActiveBackend {
    pub key: BackendKey,
    pub endpoints: Vec<Endpoint>,
    /// Application protocol the gateway speaks to this backend
    /// (`Http1` default, `Http2` = h2c origination). Independent of
    /// the client-side protocol served downstream.
    pub protocol: BackendProtocol,
}
