use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
pub enum HttpFilter {
    #[serde(rename_all = "camelCase")]
    RequestHeaderModifier {
        name: String,
        request_headers: HeaderOps,
    },
    #[serde(rename_all = "camelCase")]
    ResponseHeaderModifier {
        name: String,
        response_headers: HeaderOps,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
pub enum TlsFilter {
    TlsClientHelloLog { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
pub enum TcpFilter {
    TcpConnectionLog { name: String },
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
pub struct HeaderOps {
    #[serde(default)]
    pub add: Vec<HeaderPair>,
    #[serde(default)]
    pub set: Vec<HeaderPair>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HeaderPair {
    pub name: String,
    pub value: String,
}

impl HttpFilter {
    pub fn name(&self) -> &str {
        match self {
            Self::RequestHeaderModifier { name, .. }
            | Self::ResponseHeaderModifier { name, .. } => name,
        }
    }
}

impl TlsFilter {
    pub fn name(&self) -> &str {
        match self {
            Self::TlsClientHelloLog { name } => name,
        }
    }
}

impl TcpFilter {
    pub fn name(&self) -> &str {
        match self {
            Self::TcpConnectionLog { name } => name,
        }
    }
}
