use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HttpFilter {
    #[serde(rename_all = "camelCase")]
    RequestHeaderModifier {
        name: String,
        request_headers: RequestHeaderOps,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TlsFilter {
    TlsClientHelloLog { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TcpFilter {
    TcpConnectionLog { name: String },
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestHeaderOps {
    #[serde(default)]
    pub add: Vec<HeaderPair>,
    #[serde(default)]
    pub set: Vec<HeaderPair>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

impl HttpFilter {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::RequestHeaderModifier { name, .. } => name,
        }
    }
}

impl TlsFilter {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::TlsClientHelloLog { name } => name,
        }
    }
}

impl TcpFilter {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::TcpConnectionLog { name } => name,
        }
    }
}
