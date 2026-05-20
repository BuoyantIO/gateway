use serde::{Deserialize, Serialize};

use crate::route::{HttpRoute, TcpRoute, TlsRoute};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "listenerProtocol", rename_all = "UPPERCASE")]
pub enum Listener {
    Tls(TlsListener),
    Https(HttpsListener),
    Http(HttpListener),
    Tcp(TcpListener),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsListener {
    pub name: String,
    #[serde(default)]
    pub hostname: Option<String>,
    pub tls: TlsConfig,
    #[serde(default)]
    pub routes: Vec<TlsRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpsListener {
    pub name: String,
    #[serde(default)]
    pub hostname: Option<String>,
    pub tls: TlsConfig,
    #[serde(default)]
    pub routes: Vec<HttpRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpListener {
    pub name: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub routes: Vec<HttpRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpListener {
    pub name: String,
    #[serde(default)]
    pub routes: Vec<TcpRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    pub mode: TlsMode,
    #[serde(default)]
    pub certificates: Vec<CertRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsMode {
    Terminate,
    Passthrough,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertRef {
    pub name: String,
    pub kind: String,
}

impl Listener {
    pub fn name(&self) -> &str {
        match self {
            Self::Tls(l) => &l.name,
            Self::Https(l) => &l.name,
            Self::Http(l) => &l.name,
            Self::Tcp(l) => &l.name,
        }
    }
}
