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

/// TODO: optional TLS origination and creds
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
