use serde::{Deserialize, Serialize};

use crate::backend::BackendRef;
use crate::filter::{HttpFilter, TlsFilter};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsRoute {
    pub name: String,
    pub matches: Vec<SniMatch>,
    pub backend_refs: Vec<BackendRef>,
    #[serde(default)]
    pub filters: Vec<TlsFilter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpRoute {
    pub name: String,
    pub matches: Vec<HttpMatch>,
    pub backend_refs: Vec<BackendRef>,
    #[serde(default)]
    pub filters: Vec<HttpFilter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcpRoute {
    pub name: String,
    pub backend_refs: Vec<BackendRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SniMatch {
    pub sni: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpMatch {
    #[serde(default)]
    pub host: Option<String>,
    pub path: PathMatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathMatch {
    #[serde(rename = "type")]
    pub kind: PathMatchKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathMatchKind {
    PathPrefix,
}
