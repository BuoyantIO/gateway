//! `Extension` is a filter implementation a route names. Typed fields
//! are the ones the gateway host acts on; `config` is opaque and
//! belongs to the class.
//!
//! `GatewayBackend` is a destination outside the cluster, named by a
//! route's `backendRefs` where a Service would otherwise go. It says
//! where to dial (`baseURL`), what to trust on the way, and what
//! credential to present. Everything here is the operator's stated
//! intent; what it resolves to lives in [`crate::resolve`].
//!
//! `BackendBinding` answers for a backendRef of a kind the gateway
//! has no schema for: it claims the ref's (group, kind, name) and
//! states what the ref resolves to in native kinds.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
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

/// A destination the gateway reaches by dialing a host, rather than
/// by balancing over endpoints the cluster resolves for it.
///
/// One object is one upstream: a URL, optional transport settings,
/// and at most one credential. A route names it from `backendRefs`
/// with `group: gateway.linkerd.io, kind: GatewayBackend` and no
/// `port` — the port is part of `baseURL`
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.linkerd.io",
    version = "v1alpha1",
    kind = "GatewayBackend",
    status = "GatewayBackendStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct GatewayBackendSpec {
    /// Absolute `http` or `https` URL of the upstream. The scheme
    /// decides whether the gateway originates TLS and supplies the
    /// default port (80 / 443); a path is prepended to the request
    /// path on the way upstream, for a provider that serves its API
    /// under a subpath (`/v1`).
    #[serde(rename = "baseURL")]
    pub base_url: String,
    /// Transport settings for the TLS the `https` scheme already
    /// implies. Absent means the defaults: the platform trust store,
    /// the URL's host as SNI, and both HTTP versions offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<BackendTls>,
    /// The credential the gateway presents on every request it
    /// forwards here. Absent sends none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<BackendAuth>,
}

/// Client-side TLS settings for a `GatewayBackend`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendTls {
    /// A Secret in this object's namespace carrying the CA chain
    /// under `tls.crt`, which becomes the *only* trust root. Absent
    /// uses the platform trust store, which is what a public
    /// provider chains to. A `kubernetes.io/tls` Secret has that key
    /// by construction; its private key is ignored here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<LocalSecretReference>,
    /// Name sent as SNI and verified against the upstream
    /// certificate. Absent uses the `baseURL` host, which is also
    /// the only thing to go on when that host is a literal IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Protocols offered in the handshake, in preference order, and
    /// therefore what decides the HTTP version upstream. Absent
    /// offers both; an explicitly empty list offers no ALPN at all,
    /// which settles on HTTP/1.1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<AlpnProtocol>>,
    /// Accept any certificate, from anyone, for any name. For
    /// development and integration testing against an endpoint whose
    /// chain the gateway has no way to trust; never in production,
    /// and it overrides `ca`.
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

/// An ALPN protocol identifier, as it is written in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum AlpnProtocol {
    #[serde(rename = "h2")]
    H2,
    #[serde(rename = "http/1.1")]
    Http11,
}

/// How the gateway authenticates itself to a `GatewayBackend`.
///
/// `type` names the scheme and the field of the same name carries
/// it, so what an operator wrote is a statement rather than
/// something inferred from which fields they filled in.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BackendAuth {
    pub r#type: BackendAuthType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<ApiKeyAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2: Option<OAuth2Auth>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum BackendAuthType {
    ApiKey,
    #[serde(rename = "OAuth2")]
    OAuth2,
}

/// A credential the operator provisioned, sent verbatim in one
/// header. The defaults are what most providers ask for:
/// `Authorization: Bearer <key>`.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyAuth {
    /// The Secret holding the credential, and the data key inside it.
    pub secret_ref: SecretKeyReference,
    /// Header the credential is sent in. Absent sends
    /// `Authorization`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// Prepended to the credential inside the header value. Absent
    /// sends `Bearer `; an explicitly empty string sends the
    /// credential with nothing in front of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
}

/// The `OAuth2` client-credentials grant (RFC 6749 4.4): the gateway
/// presents its own credentials to a token endpoint and sends the
/// access token it gets back to the upstream. Nothing about the
/// request being proxied takes part.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OAuth2Auth {
    /// Absolute `http` or `https` URL of the token endpoint. Often
    /// not on the backend's own host: the service that issues the
    /// token is frequently not the one that accepts it.
    #[serde(rename = "tokenURL")]
    pub token_url: String,
    /// The gateway's client identifier. Public by construction, so
    /// it is config rather than a secret reference.
    #[serde(rename = "clientID")]
    pub client_id: String,
    /// The Secret holding the client secret, and the data key inside
    /// it.
    pub client_secret_ref: SecretKeyReference,
    /// Scopes asked for. Absent asks for none, which is what a
    /// provider that scopes by client identity expects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// How the client secret is presented to the token endpoint
    /// (RFC 6749 2.3.1). Absent uses Basic, the method the RFC says
    /// a client SHOULD use and a server MUST support.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_auth_method: Option<ClientAuthMethod>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum ClientAuthMethod {
    /// HTTP Basic, with the client id as the user and the client
    /// secret as the password.
    ClientSecretBasic,
    /// `client_id` and `client_secret` as fields of the form body.
    ClientSecretPost,
}

/// A Secret in the referring object's namespace. Cross-namespace
/// references would need a `ReferenceGrant`, which this
/// implementation does not support yet.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct LocalSecretReference {
    pub name: String,
}

/// One data key inside a Secret in the referring object's namespace.
///
/// Any Secret type will do — what a secret is taken to be is decided
/// by the key named here, not by how it was provisioned — so the
/// `Opaque` Secret an operator's secret tooling produces is read as
/// it is.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct SecretKeyReference {
    pub name: String,
    /// Data key holding the credential.
    pub key: String,
}

/// Status of one `GatewayBackend`. Conditions follow the Gateway API
/// convention: `Accepted` says the object itself is usable,
/// `ResolvedRefs` says everything it names was found.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct GatewayBackendStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// The gateway's answer for a backendRef of a kind it does not know.
///
/// A route may carry a backendRef whose group/kind the gateway has no
/// schema for. The controller owning that kind writes a
/// `BackendBinding` claiming the ref's (group, kind, name); the
/// gateway substitutes the binding's own backendRefs — native kinds
/// only — for the foreign ref, and prepends the binding's extensions
/// to the using rule's filter chain. The claimed object is never
/// read and need not exist.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.linkerd.io",
    version = "v1alpha1",
    kind = "BackendBinding",
    status = "BackendBindingStatus",
    namespaced
)]
#[serde(rename_all = "camelCase")]
pub struct BackendBindingSpec {
    /// The foreign backendRef this binding answers for, matched as
    /// opaque strings against route refs in the binding's own
    /// namespace.
    pub claim: Claim,
    /// What the claimed ref resolves to.
    pub backend_refs: Vec<BindingBackendRef>,
    /// `Extension` objects in the binding's namespace, prepended in
    /// order to the filter chain of any rule whose ref this binding
    /// claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<String>,
}

/// The (group, kind, name) of a backendRef, held as opaque strings.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct Claim {
    pub group: String,
    pub kind: String,
    pub name: String,
}

/// One destination a binding resolves to.
///
/// Selection never consults `name`: a picker addresses a local
/// endpoint by ip:port and a provider by its target's
/// namespace/name.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct BindingBackendRef {
    /// Identifies the entry within the binding — in status messages,
    /// and as the stable key for anything per-entry added later.
    /// Unrelated to the target's own name.
    pub name: String,
    /// The target, in the binding's namespace. Only kinds the gateway
    /// resolves natively: a core `Service` or a `GatewayBackend`.
    #[serde(rename = "ref")]
    pub target: BindingObjectReference,
}

/// A typed reference to a native backend kind. `group` and `kind`
/// default to the core `Service`, exactly as in a route backendRef.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct BindingObjectReference {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub name: String,
    /// Namespace of the target. Absent is the binding's own.
    /// Cross-namespace consent (a `ReferenceGrant`-style check) is
    /// not enforced yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Service port the traffic goes to. A `GatewayBackend` carries
    /// its port in `baseURL` and takes none here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

/// Status of one `BackendBinding`. `Accepted` says the spec itself
/// can stand in for a ref: the claim is complete and every target is
/// of a native kind.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, Serialize, JsonSchema)]
pub struct BackendBindingStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
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
    fn binding_spec_round_trips() {
        let raw = serde_json::json!({
            "claim": { "group": "inference-d.io", "kind": "InferencePool", "name": "pool" },
            "backendRefs": [
                { "name": "workers", "ref": { "name": "bllmp-workers", "port": 8000 } },
                {
                    "name": "openai",
                    "ref": {
                        "group": "gateway.linkerd.io",
                        "kind": "GatewayBackend",
                        "name": "openai",
                        "namespace": "egress",
                    },
                },
            ],
            "extensions": ["pool-picker"],
        });
        let spec: BackendBindingSpec = serde_json::from_value(raw.clone()).expect("valid spec");
        assert_eq!(spec.claim.kind, "InferencePool");
        assert_eq!(spec.backend_refs[0].name, "workers");
        assert_eq!(spec.backend_refs[0].target.kind, None);
        assert_eq!(spec.backend_refs[0].target.port, Some(8000));
        assert_eq!(
            spec.backend_refs[1].target.kind.as_deref(),
            Some("GatewayBackend")
        );
        assert_eq!(
            spec.backend_refs[1].target.namespace.as_deref(),
            Some("egress")
        );
        assert_eq!(spec.extensions, vec!["pool-picker"]);
        assert_eq!(serde_json::to_value(&spec).unwrap(), raw);
    }

    #[test]
    fn config_schema_preserves_unknown_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(ExtensionSpec)).unwrap();
        let config = &schema["properties"]["config"];
        assert_eq!(config["x-kubernetes-preserve-unknown-fields"], true);
    }
}
