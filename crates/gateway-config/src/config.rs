use serde::{Deserialize, Serialize};

use crate::backend::Backend;
use crate::bind::Bind;
use crate::secret::Secret;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayConfig {
    pub name: String,
    pub binds: Vec<Bind>,
    #[serde(default)]
    pub backends: Vec<Backend>,
    #[serde(default)]
    pub secrets: Vec<Secret>,
}
