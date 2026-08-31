use std::net::IpAddr;

use serde::Deserialize;

/// A destination a route can name. Two kinds, distinguished by what
/// the gateway has to do to reach them: a [`StaticBackend`] is a set
/// of already-resolved endpoints the request path balances over, and
/// a [`DialableBackend`] is a single host the gateway dials by name.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
pub enum Backend {
    Static(StaticBackend),
    Dialable(DialableBackend),
}

impl Backend {
    pub fn name(&self) -> &str {
        match self {
            Self::Static(b) => &b.name,
            Self::Dialable(b) => &b.name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticBackend {
    pub name: String,
    pub endpoints: Vec<Endpoint>,
    /// Application protocol the gateway speaks to this backend's
    /// endpoints. `Http1` (default) forwards over HTTP/1.1; `Http2`
    /// originates cleartext HTTP/2 (h2c, prior-knowledge) — required
    /// to reach a gRPC backend. Independent of the client-side
    /// protocol the gateway served downstream.
    #[serde(default)]
    pub protocol: BackendProtocol,
}

/// TODO: optional creds
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DialableBackend {
    pub name: String,
    /// Hostname (or literal IP) the gateway dials. Resolution
    /// happens at dial time, not here.
    pub host: String,
    pub port: u16,
    /// Prefix prepended to the request path on the way upstream, for
    /// a host that serves the API under a subpath (`/v1`). `None`
    /// forwards the path unchanged.
    #[serde(default)]
    pub path_prefix: Option<String>,
    /// `Some` originates TLS to this host; `None` dials it in the
    /// clear.
    #[serde(default)]
    pub tls: Option<BackendTls>,
}

/// Client-side TLS the gateway originates to a dialable backend.
///
/// The four settings are what an external provider needs: what to
/// trust, what name to ask for, what protocols to offer, and — for
/// development against a self-signed endpoint — nothing at all.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendTls {
    /// Certificates the upstream chain is verified against.
    #[serde(default)]
    pub ca: TrustRoots,
    /// Name sent as SNI and verified against the upstream
    /// certificate. `None` uses the backend's `host`, which is also
    /// the only thing to go on when the host is a literal IP — one
    /// that no certificate covers unless it carries an IP SAN.
    #[serde(default)]
    pub sni: Option<String>,
    /// Protocols offered in the TLS handshake, in preference order.
    /// What the server picks decides the HTTP version upstream, so
    /// the default offers both and lets the provider choose. An
    /// explicitly empty list offers no ALPN at all, which settles on
    /// HTTP/1.1.
    #[serde(default = "default_alpn")]
    pub alpn: Vec<AlpnProtocol>,
    /// Accept any certificate, from anyone, for any name. For
    /// development and integration testing against an endpoint whose
    /// chain the gateway has no way to trust — never in production,
    /// and it overrides `ca`.
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

/// Where the trust roots for an upstream chain come from.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(tag = "type")]
pub enum TrustRoots {
    /// The platform trust store, which is what a public provider
    /// chains to.
    #[default]
    System,
    /// A CA-only secret: the certificates in its chain become the
    /// only roots, replacing the system store rather than adding to
    /// it.
    Secret {
        /// Namespace of the referenced Secret. Empty for a flat
        /// local config, which has no namespaces.
        #[serde(default)]
        namespace: String,
        name: String,
    },
}

/// An ALPN protocol identifier, offered upstream and — when the
/// server selects it — deciding the HTTP version the gateway speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum AlpnProtocol {
    #[serde(rename = "h2")]
    H2,
    #[serde(rename = "http/1.1")]
    Http11,
}

impl AlpnProtocol {
    /// The identifier as it goes on the wire.
    pub fn as_wire(self) -> &'static [u8] {
        match self {
            Self::H2 => b"h2",
            Self::Http11 => b"http/1.1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BackendProtocol {
    #[default]
    Http1,
    Http2,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub name: String,
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendRef {
    pub name: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

/// Offer both and let the provider choose: HTTP/2 where it is
/// available, HTTP/1.1 everywhere else.
fn default_alpn() -> Vec<AlpnProtocol> {
    vec![AlpnProtocol::H2, AlpnProtocol::Http11]
}
