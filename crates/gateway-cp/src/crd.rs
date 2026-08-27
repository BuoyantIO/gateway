//! The `Extension` custom resource: the cluster-facing form of the
//! gateway's `Extension` config object. Typed fields are the ones the
//! gateway host acts on; `config` is opaque and belongs to the class.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.linkerd.io",
    version = "v1alpha1",
    kind = "Extension",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionSpec {
    /// The registered class that interprets `config` — e.g. the
    /// built-in `request_header_modifier`, or `bllmp_selector`.
    pub class: String,
    #[serde(default)]
    pub failure_mode: FailureMode,
    #[serde(default)]
    pub limits: Limits,
    /// Handed to the class verbatim; the gateway never reads a key
    /// inside it. The schema is the class's contract.
    #[serde(default)]
    #[schemars(schema_with = "preserve_unknown")]
    pub config: serde_json::Value,
}

/// What a hook error does to the request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum FailureMode {
    #[default]
    Closed,
    Open,
}

/// Operator ceilings clamping what the class's builder may declare.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<RequestBodyLimit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_buffer_bytes: Option<u64>,
}

/// The request-body modes an operator may grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum RequestBodyLimit {
    None,
    Stream,
    Buffer,
}

/// `config` accepts any object: `x-kubernetes-preserve-unknown-fields`.
fn preserve_unknown(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_round_trips_with_unknown_config_keys() {
        let raw = serde_json::json!({
            "class": "bllmp_selector",
            "failureMode": "Open",
            "limits": { "requestBody": "Stream" },
            "config": {
                "service": "bllmp.inference-d.svc:50051",
                "pool": { "namespace": "inference", "name": "p" },
            },
        });
        let spec: ExtensionSpec = serde_json::from_value(raw).expect("valid spec");
        assert_eq!(spec.class, "bllmp_selector");
        assert_eq!(spec.failure_mode, FailureMode::Open);
        assert_eq!(spec.limits.request_body, Some(RequestBodyLimit::Stream));
        assert_eq!(spec.config["pool"]["namespace"], "inference");
    }

    #[test]
    fn config_schema_preserves_unknown_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(ExtensionSpec)).unwrap();
        let config = &schema["properties"]["config"];
        assert_eq!(config["x-kubernetes-preserve-unknown-fields"], true);
    }
}
