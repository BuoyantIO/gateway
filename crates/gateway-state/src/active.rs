use std::net::IpAddr;
use std::sync::Arc;

use gateway_config::backend::{AlpnProtocol, BackendProtocol, Endpoint};
use gateway_config::bind::BindProtocol;
use gateway_config::extension::Extension;
use gateway_config::filter::HttpFilter;
use gateway_config::route::HttpMatch;
use gateway_config::secret::TlsSecret;

use crate::key::{BackendKey, BindKey, ExtensionKey, ListenerKey, RouteKey, SecretKey};

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

/// A registered backend. The key is common to both kinds; what it
/// takes to reach the backend is in [`ActiveBackendKind`].
#[derive(Debug, Clone)]
pub struct ActiveBackend {
    pub key: BackendKey,
    pub kind: ActiveBackendKind,
}

impl ActiveBackend {
    /// The endpoints to balance over. Empty for a dialable backend,
    /// which names a host instead of a set of addresses: callers
    /// that can only route to an endpoint (the balanced pick, the
    /// by-address lookup, the target listing an extension sees) get
    /// nothing to choose from, which is the same answer they already
    /// give for an endpoint set with no ready members.
    pub fn endpoints(&self) -> &[Endpoint] {
        match &self.kind {
            ActiveBackendKind::Endpoints(e) => &e.endpoints,
            ActiveBackendKind::Dialable(_) => &[],
        }
    }

    /// Application protocol the gateway speaks to this backend. A
    /// dialable backend carries no protocol setting yet, so it takes
    /// the same `Http1` default an endpoint set does.
    pub fn protocol(&self) -> BackendProtocol {
        match &self.kind {
            ActiveBackendKind::Endpoints(e) => e.protocol,
            ActiveBackendKind::Dialable(_) => BackendProtocol::default(),
        }
    }
}

/// What the request path has to do to reach a backend: pick one of a
/// set of resolved endpoints, or dial a host.
#[derive(Debug, Clone)]
pub enum ActiveBackendKind {
    Endpoints(ActiveEndpointSet),
    Dialable(ActiveDialable),
}

#[derive(Debug, Clone)]
pub struct ActiveEndpointSet {
    pub endpoints: Vec<Endpoint>,
    /// Application protocol the gateway speaks to this backend
    /// (`Http1` default, `Http2` = h2c origination). Independent of
    /// the client-side protocol served downstream.
    pub protocol: BackendProtocol,
}

/// A host the gateway resolves and dials itself. Credentials attach
/// here once they exist.
#[derive(Debug, Clone)]
pub struct ActiveDialable {
    pub host: String,
    pub port: u16,
    pub path_prefix: Option<String>,
    /// `Some` originates TLS to this host; `None` dials it in the
    /// clear.
    pub tls: Option<Arc<ActiveBackendTls>>,
}

/// A dialable backend's TLS settings, with its trust roots resolved
/// against the registered secrets.
///
/// Shared behind an `Arc` because the request path builds one client
/// per backend from it and holds on to it: two requests reading the
/// same `Arc` know they may reuse the same client and its connection
/// pool.
#[derive(Debug, Clone)]
pub struct ActiveBackendTls {
    pub roots: ActiveTrustRoots,
    pub sni: Option<String>,
    pub alpn: Vec<AlpnProtocol>,
    pub insecure_skip_verify: bool,
}

impl ActiveBackendTls {
    /// Would these two compile to the same client TLS config? Trust
    /// roots compare by secret identity: the store hands out one
    /// `Arc` per registered secret and replaces it when the secret
    /// changes, so identity is what "same material" means here — and
    /// it keeps a re-applied backend from pointlessly dropping its
    /// connection pool.
    pub fn same_config(&self, other: &Self) -> bool {
        self.sni == other.sni
            && self.alpn == other.alpn
            && self.insecure_skip_verify == other.insecure_skip_verify
            && match (&self.roots, &other.roots) {
                (ActiveTrustRoots::System, ActiveTrustRoots::System) => true,
                (
                    ActiveTrustRoots::Secret { key: a, secret: sa },
                    ActiveTrustRoots::Secret { key: b, secret: sb },
                ) => {
                    a == b
                        && match (sa, sb) {
                            (Some(sa), Some(sb)) => Arc::ptr_eq(sa, sb),
                            (None, None) => true,
                            _ => false,
                        }
                }
                _ => false,
            }
    }
}

/// Where the trust roots for an upstream chain come from, resolved.
#[derive(Debug, Clone)]
pub enum ActiveTrustRoots {
    /// The platform trust store.
    System,
    /// The CA-only secret the backend names. `secret` is `None`
    /// while that secret is not registered: the request path fails
    /// the dial rather than falling back to the system store, since
    /// trusting more than the operator asked for is the one answer
    /// that must not happen.
    Secret {
        key: SecretKey,
        secret: Option<Arc<TlsSecret>>,
    },
}
