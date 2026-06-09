use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Backend {
    Static(StaticBackend),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BackendProtocol {
    #[default]
    Http1,
    Http2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub name: String,
    pub address: IpAddr,
    pub port: u16,
}

impl Backend {
    pub fn name(&self) -> &str {
        match self {
            Self::Static(b) => &b.name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendRef {
    pub name: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}
