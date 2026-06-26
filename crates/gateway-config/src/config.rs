use serde::Deserialize;

use crate::backend::Backend;
use crate::bind::Bind;
use crate::secret::TlsSecret;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayConfig {
    pub name: String,
    pub binds: Vec<Bind>,
    #[serde(default)]
    pub backends: Vec<Backend>,
    #[serde(default)]
    pub secrets: Vec<TlsSecret>,
}
