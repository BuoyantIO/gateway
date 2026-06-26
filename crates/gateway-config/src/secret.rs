use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type")]
pub enum Secret {
    #[serde(rename = "TLS")]
    Tls(TlsSecret),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsSecret {
    pub name: String,
    pub cert_pem: String,
    pub key_pem: String,
}

impl Secret {
    pub fn name(&self) -> &str {
        match self {
            Self::Tls(s) => &s.name,
        }
    }
}
