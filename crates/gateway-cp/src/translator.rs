//! Resolved graph -> per-Gateway snapshots.
//!
//! One `Gateway` = one snapshot keyed by `(namespace, name)`.
//! `HTTPRoute`s attach to multiple snapshots if they list multiple
//! parent Gateways. Services are duplicated across slices that
//! reference them.
//!
//! Every accept/reject decision is made by [`crate::resolve`]; this
//! module only maps the surviving graph onto proto messages. If you
//! are looking for classification, attachment, hostname, or
//! backend-resolution logic, it lives there.

use std::collections::{HashMap, HashSet};

use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::Gateway;
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteRulesFilters, HttpRouteRulesFiltersRequestRedirectPathType,
    HttpRouteRulesFiltersRequestRedirectScheme, HttpRouteRulesMatches,
    HttpRouteRulesMatchesHeaders, HttpRouteRulesMatchesHeadersType, HttpRouteRulesMatchesMethod,
    HttpRouteRulesMatchesPathType, HttpRouteRulesMatchesQueryParams,
    HttpRouteRulesMatchesQueryParamsType,
};
use gateway_config::filter::{
    HeaderOps, HeaderPair, RedirectConfig, RedirectPath, RedirectStatus, Scheme,
};
use gateway_cp_proto::v1 as pb;
use gateway_state::{BackendKey, BindKey, ExtensionKey, ListenerKey, RouteKey, SecretKey};
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;

use crate::crd;
use crate::resolve::{
    BackendOutcome, BackendResolution, GatewayResolution, ListenerOutcome, Resolution, RouteEdge,
    RouteResolution, resolve,
};
use crate::snapshot::{GatewayId, Snapshot};

// The hostname primitives moved to `resolve`; re-imported here for
// the test module only (`use super::*`), so the pre-refactor tests
// keep proving their behavior unchanged. Same for the listener spec
// types the test fixtures build.
#[cfg(test)]
use crate::resolve::{effective_hostnames, hostnames_overlap, wildcard_covers};
#[cfg(test)]
use gateway_api::apis::standard::gateways::GatewayListeners;

#[derive(Debug, Default)]
pub struct K8sState {
    pub gateway_classes: Vec<GatewayClass>,
    pub gateways: Vec<Gateway>,
    pub http_routes: Vec<HTTPRoute>,
    pub services: Vec<Service>,
    pub endpoint_slices: Vec<EndpointSlice>,
    pub secrets: Vec<Secret>,
    pub extensions: Vec<crate::crd::Extension>,
}

/// Build per-Gateway snapshots from a static K8s state: resolve the
/// attachment graph, then emit it.
pub fn translate(state: &K8sState, controller_name: &str) -> HashMap<GatewayId, Snapshot> {
    translate_resolution(&resolve(state, controller_name))
}

/// Map an already-resolved graph onto per-Gateway snapshots. Pure
/// emission: no decisions are made here.
pub fn translate_resolution(resolution: &Resolution<'_>) -> HashMap<GatewayId, Snapshot> {
    let mut slices: HashMap<GatewayId, Snapshot> = HashMap::new();

    for gw in &resolution.gateways {
        let snapshot = slices.entry(gw.id.clone()).or_default();
        emit_gateway_listeners(snapshot, gw);
        emit_gateway_secrets(snapshot, gw);
    }

    for route in &resolution.routes {
        let Some(id) = route.gateway_id.as_ref() else {
            continue;
        };
        let snapshot = slices.entry(id.clone()).or_default();
        for edge in &route.edges {
            emit_routes_under_edge(snapshot, id, edge, route);
        }
        // Backends referenced anywhere in this route, in this
        // Gateway's slice — independent of listener attachment.
        for rule in &route.rule_backends {
            for backend in rule {
                emit_backend(snapshot, backend);
            }
        }
        emit_route_extensions(snapshot, route);
    }

    slices
}

/// Emit one `BindUpsert` per port carrying an accepted listener plus
/// one `ListenerUpsert` per accepted listener. The first accepted
/// listener on a port establishes the bind and its protocol
/// (resolution guarantees later listeners on the port agree).
fn emit_gateway_listeners(snapshot: &mut Snapshot, gw: &GatewayResolution<'_>) {
    let (ns, name) = (gw.id.0.as_str(), gw.id.1.as_str());
    let mut bound_ports: HashSet<i32> = HashSet::new();

    for lr in &gw.listeners {
        let ListenerOutcome::Accepted {
            protocol,
            terminate_tls,
        } = lr.outcome
        else {
            continue;
        };
        let listener = lr.listener;
        let bind = bind_name(ns, name, listener.port);
        if bound_ports.insert(listener.port) {
            snapshot.binds.insert(
                BindKey::new(&bind),
                pb::BindUpsert {
                    name: bind.clone(),
                    address: "0.0.0.0".into(),
                    port: listener.port.unsigned_abs(),
                    bind_protocol: protocol as i32,
                },
            );
        }

        let tls = terminate_tls.then(|| pb::ListenerTls {
            mode: pb::TlsMode::Terminate as i32,
            certificate_refs: lr
                .cert_refs
                .iter()
                .map(|c| pb::SecretKey {
                    namespace: c.namespace.clone(),
                    name: c.name.clone(),
                })
                .collect(),
        });
        snapshot.listeners.insert(
            ListenerKey::new(BindKey::new(&bind), &listener.name),
            pb::ListenerUpsert {
                key: Some(pb::ListenerKey {
                    bind: bind.clone(),
                    name: listener.name.clone(),
                }),
                hostname: listener.hostname.clone().unwrap_or_default(),
                has_hostname: listener.hostname.is_some(),
                tls,
            },
        );
    }
}

/// Emit an `ExtensionUpsert` for each of the route's resolved
/// `extensionRef`s. A missing object warns and is not emitted — the
/// route still carries the ref, and the DP answers 500 until the
/// object arrives.
fn emit_route_extensions(snapshot: &mut Snapshot, route: &RouteResolution<'_>) {
    for ext in &route.extensions {
        let Some(object) = ext.object else {
            tracing::warn!(namespace = %ext.namespace, name = %ext.name,
                "extensionRef Extension not present yet");
            continue;
        };
        let spec = &object.spec;
        let config_yaml = if spec.config.is_null() {
            String::new()
        } else {
            match serde_yaml::to_string(&spec.config) {
                Ok(y) => y,
                Err(e) => {
                    tracing::warn!(namespace = %ext.namespace, name = %ext.name, error = %e,
                        "Extension config cannot serialize; skipping");
                    continue;
                }
            }
        };
        let limits = pb::ExtensionLimits {
            request_body: match spec.limits.request_body {
                Some(crd::RequestBodyLimit::None) => pb::RequestBodyLimit::None as i32,
                Some(crd::RequestBodyLimit::Stream) => pb::RequestBodyLimit::Stream as i32,
                Some(crd::RequestBodyLimit::Buffer) => pb::RequestBodyLimit::Buffer as i32,
                None => pb::RequestBodyLimit::Unspecified as i32,
            },
            max_buffer_bytes: spec.limits.max_buffer_bytes.unwrap_or(0),
        };
        // HashMap insert dedups an Extension referenced by several routes.
        snapshot.extensions.insert(
            ExtensionKey::new(ext.namespace.clone(), ext.name.clone()),
            pb::ExtensionUpsert {
                namespace: ext.namespace.clone(),
                name: ext.name.clone(),
                class: spec.class.clone(),
                failure_mode: match spec.failure_mode {
                    crd::FailureMode::Closed => pb::FailureMode::Closed as i32,
                    crd::FailureMode::Open => pb::FailureMode::Open as i32,
                },
                limits: Some(limits),
                config_yaml,
            },
        );
    }
}

/// Emit a `SecretUpsert` for each accepted `certificateRef` whose
/// Secret material is present. Runs over every listener regardless
/// of acceptance so the material is already published when HTTPS
/// listeners are translated.
fn emit_gateway_secrets(snapshot: &mut Snapshot, gw: &GatewayResolution<'_>) {
    for lr in &gw.listeners {
        for cert in &lr.cert_refs {
            let Some(secret) = cert.secret else {
                tracing::warn!(namespace = %cert.namespace, name = %cert.name,
                    "certificateRef Secret not present yet");
                continue;
            };
            let Some((cert_pem, key_pem)) = tls_material(secret) else {
                tracing::warn!(namespace = %cert.namespace, name = %cert.name,
                    "Secret missing or invalid tls.crt / tls.key");
                continue;
            };
            // HashMap insert dedups a Secret referenced by several listeners.
            snapshot.secrets.insert(
                SecretKey::new(cert.namespace.clone(), cert.name.clone()),
                pb::SecretUpsert {
                    namespace: cert.namespace.clone(),
                    name: cert.name.clone(),
                    cert_pem,
                    key_pem,
                },
            );
        }
    }
}

/// Pull the PEM cert chain and key out of a `kubernetes.io/tls`
/// Secret's `tls.crt` / `tls.key` data. `None` if either is absent or
/// not valid UTF-8.
fn tls_material(secret: &Secret) -> Option<(String, String)> {
    let data = secret.data.as_ref()?;
    let cert = String::from_utf8(data.get("tls.crt")?.0.clone()).ok()?;
    let key = String::from_utf8(data.get("tls.key")?.0.clone()).ok()?;
    Some((cert, key))
}

/// Emit one `HttpRouteUpsert` per rule under one emission edge,
/// fanning matches out across the edge's effective hostnames.
fn emit_routes_under_edge(
    snapshot: &mut Snapshot,
    gw_id: &GatewayId,
    edge: &RouteEdge<'_>,
    route: &RouteResolution<'_>,
) {
    let bind = bind_name(&gw_id.0, &gw_id.1, edge.port);
    let listener_key = ListenerKey::new(BindKey::new(&bind), &edge.listener.name);
    let effective = &edge.effective_hostnames;

    let rules = route.route.spec.rules.as_deref().unwrap_or(&[]);
    for (rule_idx, rule) in rules.iter().enumerate() {
        let route_full_name = format!("{}/{}/rule{rule_idx}", route.route_ns, route.route_name);
        let route_key = RouteKey::new(listener_key.clone(), &route_full_name);

        // An absent (or empty) `matches` defaults to one `PathPrefix /`
        // catch-all per the Gateway API spec — `translate_match`
        // supplies that default for an empty match entry.
        let base_matches: Vec<pb::HttpMatch> = match rule.matches.as_deref() {
            None | Some([]) => vec![translate_match(&HttpRouteRulesMatches::default())],
            Some(ms) => ms.iter().map(translate_match).collect(),
        };

        // Fan-out: one HttpMatch per (effective hostname x user
        // match). Empty `effective` means catch-all — keep the base
        // matches with `has_host: false`.
        let matches: Vec<pb::HttpMatch> = if effective.is_empty() {
            base_matches
        } else {
            effective
                .iter()
                .flat_map(|host| {
                    base_matches.iter().map(|m| pb::HttpMatch {
                        host: host.clone(),
                        has_host: true,
                        path: m.path.clone(),
                        method: m.method,
                        header_matches: m.header_matches.clone(),
                        query_param_matches: m.query_param_matches.clone(),
                    })
                })
                .collect()
        };

        let backend_refs = route
            .rule_backends
            .get(rule_idx)
            .map(|refs| refs.iter().filter_map(backend_ref_proto).collect())
            .unwrap_or_default();

        let filters = rule
            .filters
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .enumerate()
            .filter_map(|(filter_idx, f)| {
                translate_filter(
                    f,
                    route.route_ns,
                    route.route_name,
                    rule_idx,
                    filter_idx,
                    &mut snapshot.extensions,
                )
            })
            .collect();

        snapshot.routes.insert(
            route_key,
            pb::HttpRouteUpsert {
                key: Some(pb::RouteKey {
                    bind: bind.clone(),
                    listener: edge.listener.name.clone(),
                    name: route_full_name,
                }),
                matches,
                backend_refs,
                filters,
            },
        );
    }
}

/// The proto ref a rule carries for one resolved backendRef. Missing
/// and headless Services keep their ref (the DP stashes the route
/// until the backend lands); dropped refs (cross-namespace, no port)
/// emit nothing.
fn backend_ref_proto(backend: &BackendResolution<'_>) -> Option<pb::BackendRef> {
    let key = match &backend.outcome {
        BackendOutcome::Resolved { key, .. }
        | BackendOutcome::MissingService { key }
        | BackendOutcome::Headless { key } => key.clone(),
        BackendOutcome::CrossNamespace | BackendOutcome::NoPort => return None,
    };
    Some(pb::BackendRef {
        name: key,
        weight: backend.backend_ref.weight.unwrap_or(1).unsigned_abs(),
    })
}

/// Emit one `BackendUpsert` per resolved (svc, port). Idempotent —
/// the same key reached by multiple rules only produces one entry
/// per slice. Only `Resolved` outcomes emit; missing/headless
/// Services emit nothing and the DP-side Store stashes dependent
/// routes until the backend lands.
///
/// The endpoint set is the per-pod inventory resolve derived from
/// the Service's `EndpointSlice`s, already deduplicated and sorted.
/// An empty set is emitted as-is: the backend exists but has no
/// ready pods, and the DP answers 503 until one appears.
///
/// Protocol is derived from `Service.spec.ports[*].appProtocol` for
/// the port matching `backendRef.port`. Port names are intentionally
/// not inspected — the K8s API treats name as an operator-facing
/// label only; `appProtocol` is the standard hint. See
/// [`map_app_protocol`] for recognized values.
fn emit_backend(snapshot: &mut Snapshot, backend: &BackendResolution<'_>) {
    let BackendOutcome::Resolved {
        key,
        service,
        endpoints,
    } = &backend.outcome
    else {
        return;
    };
    let bk = BackendKey::new(key);
    if snapshot.backends.contains_key(&bk) {
        return;
    }
    let Some(port) = backend.backend_ref.port else {
        return;
    };
    let port_app_protocol = service
        .spec
        .as_ref()
        .and_then(|s| s.ports.as_deref())
        .unwrap_or(&[])
        .iter()
        .find(|p| p.port == port)
        .and_then(|p| p.app_protocol.as_deref());
    let protocol = map_app_protocol(port_app_protocol);
    snapshot.backends.insert(
        bk,
        pb::BackendUpsert {
            name: key.clone(),
            endpoints: endpoints
                .iter()
                .map(|e| pb::Endpoint {
                    name: e.name.clone(),
                    address: e.address.clone(),
                    port: u32::from(e.port),
                })
                .collect(),
            protocol: protocol as i32,
        },
    );
}

/// Translate one `HttpRouteRulesMatches` to the proto. Path,
/// method, headers, and queryParams are all carried. Header names
/// are deduplicated case-insensitively (first occurrence wins) and
/// query keys case-sensitively, per Gateway API spec. Regex
/// patterns are passed through as strings; compilation happens
/// downstream in `gateway-cp-client::convert`.
fn translate_match(m: &HttpRouteRulesMatches) -> pb::HttpMatch {
    // Path defaults to `PathPrefix /` if unset, per Gateway API spec.
    let path = m.path.as_ref();
    let path_msg = match path {
        None => pb::PathMatch {
            kind: pb::PathMatchKind::PathPrefix as i32,
            value: "/".into(),
        },
        Some(p) => {
            let value = p.value.clone().unwrap_or_else(|| "/".into());
            // p.r#type defaults to PathPrefix per Gateway API.
            let kind = match p.r#type {
                None | Some(HttpRouteRulesMatchesPathType::PathPrefix) => {
                    pb::PathMatchKind::PathPrefix
                }
                Some(HttpRouteRulesMatchesPathType::Exact) => pb::PathMatchKind::Exact,
                Some(HttpRouteRulesMatchesPathType::RegularExpression) => pb::PathMatchKind::Regex,
            };
            pb::PathMatch {
                kind: kind as i32,
                value,
            }
        }
    };
    let method = translate_method(m.method.as_ref());
    let header_matches = m
        .headers
        .as_deref()
        .map(translate_header_matches)
        .unwrap_or_default();
    let query_param_matches = m
        .query_params
        .as_deref()
        .map(translate_query_param_matches)
        .unwrap_or_default();
    pb::HttpMatch {
        host: String::new(),
        has_host: false,
        path: Some(path_msg),
        method: method as i32,
        header_matches,
        query_param_matches,
    }
}

fn translate_method(m: Option<&HttpRouteRulesMatchesMethod>) -> pb::HttpMethod {
    match m {
        None => pb::HttpMethod::Unspecified,
        Some(HttpRouteRulesMatchesMethod::Get) => pb::HttpMethod::Get,
        Some(HttpRouteRulesMatchesMethod::Head) => pb::HttpMethod::Head,
        Some(HttpRouteRulesMatchesMethod::Post) => pb::HttpMethod::Post,
        Some(HttpRouteRulesMatchesMethod::Put) => pb::HttpMethod::Put,
        Some(HttpRouteRulesMatchesMethod::Delete) => pb::HttpMethod::Delete,
        Some(HttpRouteRulesMatchesMethod::Connect) => pb::HttpMethod::Connect,
        Some(HttpRouteRulesMatchesMethod::Options) => pb::HttpMethod::Options,
        Some(HttpRouteRulesMatchesMethod::Trace) => pb::HttpMethod::Trace,
        Some(HttpRouteRulesMatchesMethod::Patch) => pb::HttpMethod::Patch,
    }
}

/// Dedup header matches by lowercase name (Gateway API "first entry
/// wins" rule for repeated header names) and emit proto messages.
fn translate_header_matches(headers: &[HttpRouteRulesMatchesHeaders]) -> Vec<pb::HeaderMatch> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(headers.len());
    for h in headers {
        let key = h.name.to_ascii_lowercase();
        if !seen.insert(key) {
            tracing::warn!(name = %h.name, "skipping duplicate header match name");
            continue;
        }
        let value = match h.r#type {
            None | Some(HttpRouteRulesMatchesHeadersType::Exact) => {
                pb::header_match::Value::Exact(h.value.clone())
            }
            Some(HttpRouteRulesMatchesHeadersType::RegularExpression) => {
                pb::header_match::Value::Regex(h.value.clone())
            }
        };
        out.push(pb::HeaderMatch {
            name: h.name.clone(),
            value: Some(value),
        });
    }
    out
}

/// Dedup query param matches by name (case-sensitive, per Gateway
/// API) and emit proto messages.
fn translate_query_param_matches(
    qs: &[HttpRouteRulesMatchesQueryParams],
) -> Vec<pb::QueryParamMatch> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::with_capacity(qs.len());
    for q in qs {
        if !seen.insert(q.name.clone()) {
            tracing::warn!(name = %q.name, "skipping duplicate query param match name");
            continue;
        }
        let value = match q.r#type {
            None | Some(HttpRouteRulesMatchesQueryParamsType::Exact) => {
                pb::query_param_match::Value::Exact(q.value.clone())
            }
            Some(HttpRouteRulesMatchesQueryParamsType::RegularExpression) => {
                pb::query_param_match::Value::Regex(q.value.clone())
            }
        };
        out.push(pb::QueryParamMatch {
            name: q.name.clone(),
            value: Some(value),
        });
    }
    out
}

/// Reserved class names for the built-in extensions — the wire
/// contract with the DP registry. The round-trip tests pin the
/// config shapes each class deserializes.
const REQUEST_HEADER_MODIFIER: &str = "request_header_modifier";
const RESPONSE_HEADER_MODIFIER: &str = "response_header_modifier";
const REQUEST_REDIRECT: &str = "request_redirect";

/// A core filter becomes a synthesized `Extension` object plus a ref
/// at the filter's position; a user `extensionRef` passes through.
/// The DP sees one carrier either way.
fn translate_filter(
    f: &HttpRouteRulesFilters,
    route_ns: &str,
    route_name: &str,
    rule_idx: usize,
    filter_idx: usize,
    extensions: &mut HashMap<ExtensionKey, pb::ExtensionUpsert>,
) -> Option<pb::HttpFilter> {
    let at = FilterPosition {
        route_ns,
        route_name,
        rule_idx,
        filter_idx,
    };
    if let Some(rhm) = f.request_header_modifier.as_ref() {
        let ops = header_ops(
            rhm.add
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|h| (&h.name, &h.value)),
            rhm.set
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|h| (&h.name, &h.value)),
            rhm.remove
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(String::as_str),
        );
        return synthesize(extensions, &at, REQUEST_HEADER_MODIFIER, &ops);
    }
    if let Some(rhm) = f.response_header_modifier.as_ref() {
        let ops = header_ops(
            rhm.add
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|h| (&h.name, &h.value)),
            rhm.set
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|h| (&h.name, &h.value)),
            rhm.remove
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(String::as_str),
        );
        return synthesize(extensions, &at, RESPONSE_HEADER_MODIFIER, &ops);
    }
    if let Some(rr) = f.request_redirect.as_ref() {
        let redirect = RedirectConfig {
            scheme: match rr.scheme {
                Some(HttpRouteRulesFiltersRequestRedirectScheme::Http) => Some(Scheme::Http),
                Some(HttpRouteRulesFiltersRequestRedirectScheme::Https) => Some(Scheme::Https),
                None => None,
            },
            hostname: rr.hostname.clone(),
            port: rr.port.and_then(|p| u16::try_from(p).ok()),
            status_code: match rr.status_code {
                Some(301) => RedirectStatus::MovedPermanently,
                // Gateway API's CRD enum only permits 301/302;
                // anything else (or unset) takes the 302 default.
                _ => RedirectStatus::Found,
            },
            path: rr.path.as_ref().and_then(|p| match p.r#type {
                HttpRouteRulesFiltersRequestRedirectPathType::ReplaceFullPath => p
                    .replace_full_path
                    .clone()
                    .map(RedirectPath::ReplaceFullPath),
                HttpRouteRulesFiltersRequestRedirectPathType::ReplacePrefixMatch => p
                    .replace_prefix_match
                    .clone()
                    .map(RedirectPath::ReplacePrefixMatch),
            }),
        };
        return synthesize(extensions, &at, REQUEST_REDIRECT, &redirect);
    }
    if let Some(filter) = translate_extension_ref(f, route_ns) {
        return Some(filter);
    }

    tracing::warn!(?f.r#type, "skipping unsupported HTTPRoute filter");
    None
}

/// One filter position on one route rule. The synthesized object's
/// name derives from it, so the name is stable across the route's
/// listeners and changes only when filters move.
struct FilterPosition<'a> {
    route_ns: &'a str,
    route_name: &'a str,
    rule_idx: usize,
    filter_idx: usize,
}

/// Emit the synthesized `Extension` object for one core filter and
/// return the ref that takes the filter's place. `~` is not a legal
/// Kubernetes name character, so a synthesized key can never collide
/// with a user object.
fn synthesize<T: serde::Serialize>(
    extensions: &mut HashMap<ExtensionKey, pb::ExtensionUpsert>,
    at: &FilterPosition<'_>,
    class: &str,
    config: &T,
) -> Option<pb::HttpFilter> {
    let config_yaml = match serde_yaml::to_string(config) {
        Ok(y) => y,
        Err(e) => {
            tracing::warn!(class, error = %e, "core filter config cannot serialize; dropping the filter");
            return None;
        }
    };
    let name = format!("{}~r{}~f{}", at.route_name, at.rule_idx, at.filter_idx);
    extensions.insert(
        ExtensionKey::new(at.route_ns, &name),
        pb::ExtensionUpsert {
            namespace: at.route_ns.to_string(),
            name: name.clone(),
            class: class.to_string(),
            failure_mode: pb::FailureMode::Closed as i32,
            limits: None,
            config_yaml,
        },
    );
    Some(pb::HttpFilter {
        kind: Some(pb::http_filter::Kind::ExtensionRef(pb::ExtensionRef {
            name,
            namespace: at.route_ns.to_string(),
        })),
    })
}

/// The `extensionRef` arm: only our `Extension` kind translates; a
/// foreign group/kind falls through to the unsupported-filter warn.
fn translate_extension_ref(f: &HttpRouteRulesFilters, route_ns: &str) -> Option<pb::HttpFilter> {
    let er = f.extension_ref.as_ref()?;
    if er.group != "gateway.linkerd.io" || er.kind != "Extension" {
        return None;
    }
    Some(pb::HttpFilter {
        kind: Some(pb::http_filter::Kind::ExtensionRef(pb::ExtensionRef {
            name: er.name.clone(),
            namespace: route_ns.to_string(),
        })),
    })
}

/// Shared add/set/remove translator for the request- and
/// response-side header modifiers. Builds the `gateway-config` type
/// the built-in classes deserialize, so the YAML shape cannot drift.
fn header_ops<'a, A, S, R>(add: A, set: S, remove: R) -> HeaderOps
where
    A: Iterator<Item = (&'a String, &'a String)>,
    S: Iterator<Item = (&'a String, &'a String)>,
    R: Iterator<Item = &'a str>,
{
    let to_pair = |(name, value): (&String, &String)| HeaderPair {
        name: name.clone(),
        value: value.clone(),
    };
    HeaderOps {
        add: add.map(to_pair).collect(),
        set: set.map(to_pair).collect(),
        remove: remove.map(str::to_owned).collect(),
    }
}

/// Recognized HTTP/2 indicators on `Service.spec.ports[*].appProtocol`.
///
/// `kubernetes.io/h2c` is the Kubernetes-registered value;
/// `h2c` and `grpc` are de-facto conventions widely recognized by
/// proxies. Any other value — including the websocket
/// variants `kubernetes.io/ws` / `kubernetes.io/wss` or any custom
/// `mycompany.com/...` string — maps to HTTP/1.1.
///
/// Port `name` is **not** inspected. K8s defines it as a `DNS_LABEL`
/// with no protocol semantics; if an operator names a port `grpc`
/// but doesn't set `appProtocol`, we treat it as HTTP/1.1.
fn map_app_protocol(app_protocol: Option<&str>) -> pb::BackendProtocol {
    match app_protocol {
        Some("kubernetes.io/h2c" | "h2c" | "grpc") => pb::BackendProtocol::Http2,
        _ => pb::BackendProtocol::Http1,
    }
}

// ==================== name helpers ====================

/// One Bind per (Gateway, port). The colon keeps the name visually
/// distinct from listener paths and unambiguous against a listener
/// literally named `8080`.
fn bind_name(gw_ns: &str, gw_name: &str, port: i32) -> String {
    format!("{gw_ns}/{gw_name}:{port}")
}
#[cfg(test)]
mod tests {
    use super::*;

    use gateway_api::apis::standard::gatewayclasses::GatewayClassSpec;
    use gateway_api::apis::standard::gateways::{
        GatewayListenersAllowedRoutes, GatewayListenersAllowedRoutesNamespaces,
        GatewayListenersTls, GatewayListenersTlsCertificateRefs, GatewayListenersTlsMode,
        GatewaySpec,
    };
    use gateway_api::apis::standard::httproutes::{
        HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs,
        HttpRouteRulesFiltersRequestHeaderModifier, HttpRouteRulesFiltersRequestHeaderModifierAdd,
        HttpRouteRulesFiltersRequestHeaderModifierSet, HttpRouteRulesMatchesPath, HttpRouteSpec,
    };
    use std::collections::BTreeMap;

    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::{ObjectReference, ServiceSpec};
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    use crate::diff::diff;
    use crate::resolve::SERVICE_NAME_LABEL;

    const OURS: &str = "gateway.test/controller";

    fn gc(name: &str, controller: &str) -> GatewayClass {
        GatewayClass {
            metadata: ObjectMeta {
                name: Some(name.into()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: controller.into(),
                ..Default::default()
            },
            status: None,
        }
    }

    /// An HTTPS listener terminating with the named Secret cert refs.
    /// `cert_refs` is a list of `(namespace, name)`; an empty namespace
    /// means the ref omits it (resolves to the gateway's namespace).
    fn https_listener(
        name: &str,
        port: i32,
        hostname: Option<&str>,
        cert_refs: &[(&str, &str)],
    ) -> GatewayListeners {
        GatewayListeners {
            name: name.into(),
            protocol: "HTTPS".into(),
            port,
            hostname: hostname.map(String::from),
            tls: Some(GatewayListenersTls {
                mode: None,
                options: None,
                certificate_refs: Some(
                    cert_refs
                        .iter()
                        .map(|(ns, n)| GatewayListenersTlsCertificateRefs {
                            group: None,
                            kind: Some("Secret".into()),
                            namespace: (!ns.is_empty()).then(|| (*ns).into()),
                            name: (*n).into(),
                        })
                        .collect(),
                ),
            }),
            allowed_routes: Some(GatewayListenersAllowedRoutes {
                namespaces: Some(GatewayListenersAllowedRoutesNamespaces {
                    from: None,
                    selector: None,
                }),
                kinds: None,
            }),
        }
    }

    /// A `kubernetes.io/tls` Secret carrying `tls.crt` / `tls.key`.
    fn tls_secret(ns: &str, name: &str, cert: &str, key: &str) -> Secret {
        let mut data = BTreeMap::new();
        data.insert("tls.crt".to_string(), ByteString(cert.as_bytes().to_vec()));
        data.insert("tls.key".to_string(), ByteString(key.as_bytes().to_vec()));
        Secret {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            data: Some(data),
            type_: Some("kubernetes.io/tls".into()),
            ..Default::default()
        }
    }

    fn http_listener(name: &str, port: i32, hostname: Option<&str>) -> GatewayListeners {
        GatewayListeners {
            name: name.into(),
            protocol: "HTTP".into(),
            port,
            hostname: hostname.map(String::from),
            tls: None,
            allowed_routes: Some(GatewayListenersAllowedRoutes {
                namespaces: Some(GatewayListenersAllowedRoutesNamespaces {
                    from: None,
                    selector: None,
                }),
                kinds: None,
            }),
        }
    }

    fn gw(ns: &str, name: &str, class: &str, listeners: Vec<GatewayListeners>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: class.into(),
                listeners,
                ..Default::default()
            },
            status: None,
        }
    }

    fn parent_ref(name: &str, ns: Option<&str>, section: Option<&str>) -> HttpRouteParentRefs {
        HttpRouteParentRefs {
            name: name.into(),
            namespace: ns.map(String::from),
            section_name: section.map(String::from),
            group: None,
            kind: None,
            port: None,
        }
    }

    fn backend_ref(name: &str, port: i32) -> HttpRouteRulesBackendRefs {
        HttpRouteRulesBackendRefs {
            name: name.into(),
            port: Some(port),
            namespace: None,
            group: None,
            kind: None,
            weight: None,
            filters: None,
        }
    }

    fn path_prefix(value: &str) -> HttpRouteRulesMatchesPath {
        HttpRouteRulesMatchesPath {
            r#type: None, // default = PathPrefix
            value: Some(value.into()),
        }
    }

    fn path_exact(value: &str) -> HttpRouteRulesMatchesPath {
        HttpRouteRulesMatchesPath {
            r#type: Some(HttpRouteRulesMatchesPathType::Exact),
            value: Some(value.into()),
        }
    }

    fn path_regex(value: &str) -> HttpRouteRulesMatchesPath {
        HttpRouteRulesMatchesPath {
            r#type: Some(HttpRouteRulesMatchesPathType::RegularExpression),
            value: Some(value.into()),
        }
    }

    fn rule(
        path: Option<&str>,
        backend_refs: Vec<HttpRouteRulesBackendRefs>,
        filters: Vec<HttpRouteRulesFilters>,
    ) -> HttpRouteRules {
        HttpRouteRules {
            matches: Some(vec![HttpRouteRulesMatches {
                path: path.map(path_prefix),
                headers: None,
                query_params: None,
                method: None,
            }]),
            backend_refs: Some(backend_refs),
            filters: Some(filters),
            name: None,
            timeouts: None,
        }
    }

    fn http_route(
        ns: &str,
        name: &str,
        parents: Vec<HttpRouteParentRefs>,
        rules: Vec<HttpRouteRules>,
    ) -> HTTPRoute {
        HTTPRoute {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(parents),
                rules: Some(rules),
                hostnames: None,
            },
            status: None,
        }
    }

    fn service(ns: &str, name: &str, cluster_ip: Option<&str>) -> Service {
        Service {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: cluster_ip.map(String::from),
                ..Default::default()
            }),
            status: None,
        }
    }

    /// Like `service`, but with explicit ports + per-port appProtocol.
    /// Used by the `appProtocol` translation tests; pass each port as
    /// `(port_number, Some("grpc"))` or `(port_number, None)`.
    fn service_with_ports(
        ns: &str,
        name: &str,
        cluster_ip: Option<&str>,
        ports: &[(i32, Option<&str>)],
    ) -> Service {
        use k8s_openapi::api::core::v1::ServicePort;
        Service {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: cluster_ip.map(String::from),
                ports: Some(
                    ports
                        .iter()
                        .map(|(p, ap)| ServicePort {
                            port: *p,
                            app_protocol: ap.map(String::from),
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            }),
            status: None,
        }
    }

    fn header_modifier_filter() -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type: gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersType::RequestHeaderModifier,
            request_header_modifier: Some(HttpRouteRulesFiltersRequestHeaderModifier {
                add: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierAdd {
                    name: "x-test".into(),
                    value: "yes".into(),
                }]),
                set: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierSet {
                    name: "x-set".into(),
                    value: "set-val".into(),
                }]),
                remove: Some(vec!["x-drop".into()]),
            }),
            response_header_modifier: None,
            request_redirect: None,
            url_rewrite: None,
            request_mirror: None,
            extension_ref: None,
            cors: None,
        }
    }

    fn response_header_modifier_filter() -> HttpRouteRulesFilters {
        use gateway_api::apis::standard::httproutes::{
            HttpRouteRulesFiltersResponseHeaderModifier,
            HttpRouteRulesFiltersResponseHeaderModifierAdd,
            HttpRouteRulesFiltersResponseHeaderModifierSet,
        };
        HttpRouteRulesFilters {
            r#type: gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersType::ResponseHeaderModifier,
            request_header_modifier: None,
            response_header_modifier: Some(HttpRouteRulesFiltersResponseHeaderModifier {
                add: Some(vec![HttpRouteRulesFiltersResponseHeaderModifierAdd {
                    name: "x-csp".into(),
                    value: "default-src 'self'".into(),
                }]),
                set: Some(vec![HttpRouteRulesFiltersResponseHeaderModifierSet {
                    name: "x-frame-options".into(),
                    value: "sameorigin".into(),
                }]),
                remove: Some(vec!["x-server-version".into()]),
            }),
            request_redirect: None,
            url_rewrite: None,
            request_mirror: None,
            extension_ref: None,
            cors: None,
        }
    }

    // ---------- tests ----------

    #[test]
    fn owned_gateway_emits_bind_and_listener() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, Some("app.example.com"))],
            )],
            ..Default::default()
        };

        let out = translate(&state, OURS);
        let snap = out
            .get(&("demo".to_string(), "api".to_string()))
            .expect("slice for demo/api");
        assert_eq!(snap.binds.len(), 1);
        assert_eq!(snap.listeners.len(), 1);

        let bind = snap.binds.get(&BindKey::new("demo/api:80")).expect("bind");
        assert_eq!(bind.port, 80);

        let lk = ListenerKey::new(BindKey::new("demo/api:80"), "http");
        let listener = snap.listeners.get(&lk).expect("listener");
        assert!(listener.has_hostname);
        assert_eq!(listener.hostname, "app.example.com");
    }

    // ---------- bind grouping by (gateway, port) ----------

    #[test]
    fn two_listeners_same_port_share_one_bind() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![
                    http_listener("web-a", 80, Some("a.example.com")),
                    http_listener("web-b", 80, Some("b.example.com")),
                ],
            )],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();

        assert_eq!(s.binds.len(), 1, "one bind for the shared port");
        let bind = s.binds.get(&BindKey::new("demo/api:80")).expect("bind");
        assert_eq!(bind.port, 80);
        assert_eq!(bind.bind_protocol, pb::BindProtocol::Http as i32);

        assert_eq!(s.listeners.len(), 2, "both listeners under the bind");
        for (name, host) in [("web-a", "a.example.com"), ("web-b", "b.example.com")] {
            let lk = ListenerKey::new(BindKey::new("demo/api:80"), name);
            let l = s.listeners.get(&lk).expect("listener under shared bind");
            assert_eq!(l.hostname, host);
            let key = l.key.as_ref().expect("listener key set");
            assert_eq!(key.bind, "demo/api:80");
            assert_eq!(key.name, name);
        }
    }

    #[test]
    fn listeners_on_distinct_ports_get_distinct_binds() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![
                    http_listener("web", 80, None),
                    http_listener("alt", 8080, None),
                ],
            )],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();

        assert_eq!(s.binds.len(), 2);
        assert_eq!(s.binds.get(&BindKey::new("demo/api:80")).unwrap().port, 80);
        assert_eq!(
            s.binds.get(&BindKey::new("demo/api:8080")).unwrap().port,
            8080
        );
        assert_eq!(s.listeners.len(), 2);
        assert!(
            s.listeners
                .contains_key(&ListenerKey::new(BindKey::new("demo/api:80"), "web"))
        );
        assert!(
            s.listeners
                .contains_key(&ListenerKey::new(BindKey::new("demo/api:8080"), "alt"))
        );
    }

    #[test]
    fn duplicate_hostname_on_shared_port_first_wins() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![
                    http_listener("first", 80, Some("app.example.com")),
                    http_listener("dupe", 80, Some("app.example.com")),
                ],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                // sectionName targets the conflicted listener: no
                // routes may be emitted for it.
                vec![parent_ref("api", Some("demo"), Some("dupe"))],
                vec![rule(Some("/"), vec![backend_ref("svc", 8080)], vec![])],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();

        assert_eq!(s.binds.len(), 1);
        assert_eq!(s.listeners.len(), 1, "conflicted listener dropped");
        assert!(
            s.listeners
                .contains_key(&ListenerKey::new(BindKey::new("demo/api:80"), "first"))
        );
        assert!(
            s.routes.is_empty(),
            "routes targeting the conflicted listener emit nothing"
        );
    }

    #[test]
    fn hostnameless_duplicate_on_shared_port_first_wins() {
        // Two listeners with no hostname on one port collide (None ==
        // None counts as a duplicate per listener distinctness).
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![
                    http_listener("first", 80, None),
                    http_listener("second", 80, None),
                ],
            )],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        assert_eq!(s.binds.len(), 1);
        assert_eq!(s.listeners.len(), 1);
        assert!(
            s.listeners
                .contains_key(&ListenerKey::new(BindKey::new("demo/api:80"), "first"))
        );
    }

    #[test]
    fn route_without_section_fans_out_across_listeners_on_port() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![
                    http_listener("web-a", 80, Some("a.example.com")),
                    http_listener("web-b", 80, Some("b.example.com")),
                ],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(Some("/"), vec![backend_ref("svc", 8080)], vec![])],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();

        assert_eq!(s.routes.len(), 2, "route attaches under both listeners");
        let mut listeners: Vec<&str> = s
            .routes
            .values()
            .map(|r| r.key.as_ref().unwrap().listener.as_str())
            .collect();
        listeners.sort_unstable();
        assert_eq!(listeners, vec!["web-a", "web-b"]);
        // Hostname intersection applies per listener: each emitted
        // route carries its own listener's hostname.
        for route in s.routes.values() {
            let key = route.key.as_ref().unwrap();
            assert_eq!(key.bind, "demo/api:80");
            let expect_host = match key.listener.as_str() {
                "web-a" => "a.example.com",
                "web-b" => "b.example.com",
                other => panic!("unexpected listener {other}"),
            };
            assert_eq!(route.matches.len(), 1);
            assert_eq!(route.matches[0].host, expect_host);
        }
    }

    #[test]
    fn route_with_section_name_only_under_named_listener() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![
                    http_listener("web-a", 80, Some("a.example.com")),
                    http_listener("web-b", 80, Some("b.example.com")),
                ],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), Some("web-b"))],
                vec![rule(Some("/"), vec![backend_ref("svc", 8080)], vec![])],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();

        assert_eq!(s.routes.len(), 1);
        let key = s.routes.values().next().unwrap().key.as_ref().unwrap();
        assert_eq!(key.bind, "demo/api:80");
        assert_eq!(key.listener, "web-b");
    }

    #[test]
    fn unowned_gateway_class_produces_no_slice() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS), gc("foreign", "other.io/controller")],
            gateways: vec![gw(
                "demo",
                "api",
                "foreign",
                vec![http_listener("http", 80, None)],
            )],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        assert!(out.is_empty(), "no owned slice should exist");
    }

    #[test]
    fn route_appears_in_each_parent_slice() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![
                gw("demo", "gw1", "zd", vec![http_listener("http", 80, None)]),
                gw("demo", "gw2", "zd", vec![http_listener("http", 81, None)]),
            ],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![
                    parent_ref("gw1", Some("demo"), None),
                    parent_ref("gw2", Some("demo"), None),
                ],
                vec![rule(Some("/"), vec![backend_ref("svc", 8080)], vec![])],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };

        let out = translate(&state, OURS);
        let s1 = out.get(&("demo".into(), "gw1".into())).expect("gw1");
        let s2 = out.get(&("demo".into(), "gw2".into())).expect("gw2");
        assert_eq!(s1.routes.len(), 1);
        assert_eq!(s2.routes.len(), 1);
        // Backend duplicated across slices.
        assert!(s1.backends.contains_key(&BackendKey::new("demo/svc:8080")));
        assert!(s2.backends.contains_key(&BackendKey::new("demo/svc:8080")));
    }

    #[test]
    fn multiple_rules_yield_multiple_routes_in_one_slice() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![
                    rule(Some("/a"), vec![backend_ref("svc", 8080)], vec![]),
                    rule(Some("/b"), vec![backend_ref("svc", 8080)], vec![]),
                    rule(Some("/c"), vec![backend_ref("svc", 8080)], vec![]),
                ],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        assert_eq!(s.routes.len(), 3);
    }

    #[test]
    fn cross_namespace_backendref_is_dropped() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![HttpRouteRules {
                    matches: Some(vec![HttpRouteRulesMatches {
                        path: Some(path_prefix("/")),
                        headers: None,
                        query_params: None,
                        method: None,
                    }]),
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: "svc".into(),
                        namespace: Some("other-ns".into()),
                        port: Some(8080),
                        group: None,
                        kind: None,
                        weight: None,
                        filters: None,
                    }]),
                    filters: Some(vec![]),
                    name: None,
                    timeouts: None,
                }],
            )],
            services: vec![service("other-ns", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().unwrap();
        assert!(
            route.backend_refs.is_empty(),
            "cross-ns backendRef should be dropped"
        );
        assert!(s.backends.is_empty(), "no backend emitted for cross-ns");
    }

    #[test]
    fn headless_service_produces_no_backend() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(Some("/"), vec![backend_ref("svc", 8080)], vec![])],
            )],
            services: vec![service("demo", "svc", Some("None"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        assert!(s.backends.is_empty());
    }

    #[test]
    fn missing_service_produces_no_backend() {
        // Route references "svc" but no such Service exists. The Store
        // will stash the route until the backend appears.
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(Some("/"), vec![backend_ref("svc", 8080)], vec![])],
            )],
            services: vec![],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        assert!(s.backends.is_empty());
        // Route still emitted; the BackendRef carries the unresolved name.
        assert_eq!(s.routes.len(), 1);
    }

    fn endpoint_slice(name: &str, service: &str, pods: &[(&str, &str)]) -> EndpointSlice {
        EndpointSlice {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some(name.into()),
                labels: Some(
                    [(SERVICE_NAME_LABEL.to_string(), service.to_string())]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
            address_type: "IPv4".into(),
            endpoints: pods
                .iter()
                .map(|(address, pod)| Endpoint {
                    addresses: vec![(*address).to_string()],
                    conditions: Some(EndpointConditions {
                        ready: Some(true),
                        serving: Some(true),
                        ..Default::default()
                    }),
                    target_ref: Some(ObjectReference {
                        kind: Some("Pod".into()),
                        name: Some((*pod).to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .collect(),
            ports: Some(vec![EndpointPort {
                port: Some(8080),
                ..Default::default()
            }]),
        }
    }

    fn per_pod_state(endpoint_slices: Vec<EndpointSlice>) -> K8sState {
        K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(Some("/"), vec![backend_ref("svc", 8080)], vec![])],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices,
            secrets: vec![],
            extensions: vec![],
        }
    }

    #[test]
    fn backend_emits_one_endpoint_per_ready_pod() {
        let state = per_pod_state(vec![
            endpoint_slice(
                "svc-1",
                "svc",
                &[("10.1.0.2", "pod-b"), ("10.1.0.1", "pod-a")],
            ),
            endpoint_slice("svc-2", "svc", &[("10.1.0.3", "pod-c")]),
        ]);
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let backend = s.backends.get(&BackendKey::new("demo/svc:8080")).unwrap();
        let endpoints: Vec<(&str, &str, u32)> = backend
            .endpoints
            .iter()
            .map(|e| (e.name.as_str(), e.address.as_str(), e.port))
            .collect();
        assert_eq!(
            endpoints,
            vec![
                ("pod-a", "10.1.0.1", 8080),
                ("pod-b", "10.1.0.2", 8080),
                ("pod-c", "10.1.0.3", 8080),
            ],
            "endpoint set is the sorted union across slices"
        );
    }

    #[test]
    fn backend_with_no_slices_emits_empty_endpoints() {
        // The backend upsert still goes out: the Service exists but
        // has no ready pods, and the DP answers 503 for it — distinct
        // from a missing Service (no upsert, 500).
        let state = per_pod_state(vec![]);
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let backend = s.backends.get(&BackendKey::new("demo/svc:8080")).unwrap();
        assert!(backend.endpoints.is_empty());
    }

    #[test]
    fn translation_converges_regardless_of_slice_order() {
        let a = endpoint_slice(
            "svc-1",
            "svc",
            &[("10.1.0.1", "pod-a"), ("10.1.0.2", "pod-b")],
        );
        let b = endpoint_slice("svc-2", "svc", &[("10.1.0.3", "pod-c")]);
        let forward = translate(&per_pod_state(vec![a.clone(), b.clone()]), OURS);
        let reversed = translate(&per_pod_state(vec![b, a]), OURS);

        let id = ("demo".to_string(), "api".to_string());
        assert!(
            diff(forward.get(&id).unwrap(), reversed.get(&id).unwrap()).is_none(),
            "same slice set in different arrival order must diff to no-op"
        );
    }

    #[test]
    fn core_filters_synthesize_extension_objects() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(
                    Some("/"),
                    vec![backend_ref("svc", 8080)],
                    vec![header_modifier_filter(), response_header_modifier_filter()],
                )],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().unwrap();

        // Each core filter became a ref at its position.
        let names: Vec<&str> = route
            .filters
            .iter()
            .map(|f| match f.kind.as_ref().expect("kind set") {
                pb::http_filter::Kind::ExtensionRef(er) => {
                    assert_eq!(er.namespace, "demo");
                    er.name.as_str()
                }
                other => panic!("expected ExtensionRef, got {other:?}"),
            })
            .collect();
        assert_eq!(names, vec!["r~r0~f0", "r~r0~f1"]);

        // ...and one synthesized object each, whose config round-trips
        // into the exact type the built-in class deserializes.
        let req = &s.extensions[&ExtensionKey::new("demo", "r~r0~f0")];
        assert_eq!(req.class, "request_header_modifier");
        assert_eq!(req.failure_mode, pb::FailureMode::Closed as i32);
        assert!(req.limits.is_none());
        let ops: HeaderOps = serde_yaml::from_str(&req.config_yaml).expect("parses");
        assert_eq!(ops.add[0].name, "x-test");
        assert_eq!(ops.set[0].name, "x-set");
        assert_eq!(ops.remove, vec!["x-drop".to_string()]);

        let resp = &s.extensions[&ExtensionKey::new("demo", "r~r0~f1")];
        assert_eq!(resp.class, "response_header_modifier");
        let ops: HeaderOps = serde_yaml::from_str(&resp.config_yaml).expect("parses");
        assert_eq!(ops.add[0].name, "x-csp");
        assert_eq!(ops.set[0].name, "x-frame-options");
        assert_eq!(ops.remove, vec!["x-server-version".to_string()]);
    }

    #[test]
    fn request_redirect_synthesizes_and_round_trips() {
        use gateway_api::apis::standard::httproutes::{
            HttpRouteRulesFiltersRequestRedirect, HttpRouteRulesFiltersRequestRedirectPath,
            HttpRouteRulesFiltersRequestRedirectPathType,
            HttpRouteRulesFiltersRequestRedirectScheme,
        };

        let filter = HttpRouteRulesFilters {
            r#type:
                gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersType::RequestRedirect,
            request_header_modifier: None,
            response_header_modifier: None,
            request_redirect: Some(HttpRouteRulesFiltersRequestRedirect {
                scheme: Some(HttpRouteRulesFiltersRequestRedirectScheme::Https),
                hostname: None,
                port: None,
                status_code: Some(301),
                path: Some(HttpRouteRulesFiltersRequestRedirectPath {
                    r#type: HttpRouteRulesFiltersRequestRedirectPathType::ReplacePrefixMatch,
                    replace_full_path: None,
                    replace_prefix_match: Some("/new".into()),
                }),
            }),
            url_rewrite: None,
            request_mirror: None,
            cors: None,
            extension_ref: None,
        };

        let mut extensions = HashMap::new();
        let out = translate_filter(&filter, "ns", "r", 0, 0, &mut extensions)
            .expect("redirect translated");
        match out.kind.expect("kind set") {
            pb::http_filter::Kind::ExtensionRef(er) => {
                assert_eq!(er.name, "r~r0~f0");
                assert_eq!(er.namespace, "ns");
            }
            other => panic!("expected ExtensionRef, got {other:?}"),
        }
        let upsert = &extensions[&ExtensionKey::new("ns", "r~r0~f0")];
        assert_eq!(upsert.class, "request_redirect");
        let redirect: RedirectConfig = serde_yaml::from_str(&upsert.config_yaml).expect("parses");
        assert_eq!(redirect.scheme, Some(Scheme::Https));
        assert_eq!(redirect.status_code, RedirectStatus::MovedPermanently);
        assert_eq!(redirect.hostname, None);
        assert_eq!(redirect.port, None);
        assert_eq!(
            redirect.path,
            Some(RedirectPath::ReplacePrefixMatch("/new".into()))
        );

        // A minimal redirect serializes to YAML that still parses,
        // with the 302 default.
        let minimal = HttpRouteRulesFilters {
            request_redirect: Some(HttpRouteRulesFiltersRequestRedirect {
                scheme: None,
                hostname: None,
                port: None,
                status_code: None,
                path: None,
            }),
            ..filter
        };
        let mut extensions = HashMap::new();
        translate_filter(&minimal, "ns", "r", 0, 0, &mut extensions).expect("translated");
        let upsert = &extensions[&ExtensionKey::new("ns", "r~r0~f0")];
        let redirect: RedirectConfig = serde_yaml::from_str(&upsert.config_yaml).expect("parses");
        assert_eq!(redirect.status_code, RedirectStatus::Found);
        assert_eq!(redirect.scheme, None);
    }

    #[test]
    fn mixed_filters_keep_their_positions() {
        // Core filter, user ref, core filter: the refs land in filter
        // order, and only the core filters synthesize objects.
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(
                    Some("/"),
                    vec![backend_ref("svc", 8080)],
                    vec![
                        header_modifier_filter(),
                        extension_ref_filter("gateway.linkerd.io", "Extension", "picker"),
                        response_header_modifier_filter(),
                    ],
                )],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().unwrap();
        let names: Vec<&str> = route
            .filters
            .iter()
            .map(|f| match f.kind.as_ref().expect("kind set") {
                pb::http_filter::Kind::ExtensionRef(er) => er.name.as_str(),
                other => panic!("expected ExtensionRef, got {other:?}"),
            })
            .collect();
        assert_eq!(names, vec!["r~r0~f0", "picker", "r~r0~f2"]);
        assert_eq!(s.extensions.len(), 2, "only core filters synthesize");
    }

    #[test]
    fn synthesized_object_is_shared_across_listeners() {
        // The name derives from (route, rule, filter), not the edge:
        // a route attached to two listeners emits two route upserts
        // but one synthesized object.
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![
                    http_listener("web", 80, None),
                    http_listener("alt", 8080, None),
                ],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(
                    Some("/"),
                    vec![backend_ref("svc", 8080)],
                    vec![header_modifier_filter()],
                )],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        assert_eq!(s.routes.len(), 2);
        assert_eq!(s.extensions.len(), 1);
    }

    #[test]
    fn core_filter_config_change_leaves_the_route_untouched() {
        // The synthesized key is position-derived, so a config edit
        // re-emits only the extension object; the route upsert is
        // byte-identical and the diff carries one upsert.
        let route_with_value = |value: &str| {
            let mut filter = header_modifier_filter();
            filter
                .request_header_modifier
                .as_mut()
                .unwrap()
                .add
                .as_mut()
                .unwrap()[0]
                .value = value.into();
            http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(
                    Some("/"),
                    vec![backend_ref("svc", 8080)],
                    vec![filter],
                )],
            )
        };
        let state = |value: &str| K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![route_with_value(value)],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let before = translate(&state("yes"), OURS);
        let after = translate(&state("no"), OURS);
        let key = ("demo".to_string(), "api".to_string());
        let (b, a) = (before.get(&key).unwrap(), after.get(&key).unwrap());
        assert_eq!(b.routes, a.routes, "route upsert must not change");
        assert_ne!(
            b.extensions, a.extensions,
            "the synthesized object carries the change"
        );
    }

    // ---------- hostname helpers ----------

    #[test]
    fn wildcard_covers_suffix_match() {
        // Per Gateway API: wildcards are suffix matches, multi-label
        // prefixes accepted.
        assert!(wildcard_covers("example.com", "app.example.com"));
        assert!(wildcard_covers("example.com", "a.b.example.com"));
        // Bare suffix not covered — needs at least one extra label.
        assert!(!wildcard_covers("example.com", "example.com"));
        // Different domain.
        assert!(!wildcard_covers("example.com", "other.com"));
        // Case-insensitive.
        assert!(wildcard_covers("example.com", "APP.Example.COM"));
    }

    #[test]
    fn hostnames_overlap_cases() {
        // equal
        assert!(hostnames_overlap("a.com", "a.com"));
        assert!(hostnames_overlap("A.com", "a.COM")); // case-insensitive
        // not equal
        assert!(!hostnames_overlap("a.com", "b.com"));
        // wildcard vs concrete
        assert!(hostnames_overlap("*.example.com", "app.example.com"));
        assert!(hostnames_overlap("app.example.com", "*.example.com"));
        assert!(hostnames_overlap("*.example.com", "foo.bar.example.com"));
        assert!(!hostnames_overlap("*.example.com", "example.com"));
        // Two wildcards overlap if one suffix covers the other's
        // concrete set. `*.example.com` and `*.sub.example.com`
        // share `foo.sub.example.com`, so they overlap.
        assert!(hostnames_overlap("*.example.com", "*.sub.example.com"));
        assert!(hostnames_overlap("*.sub.example.com", "*.example.com"));
        // Disjoint domains.
        assert!(!hostnames_overlap("*.example.com", "*.foo.com"));
        // Identical wildcards overlap.
        assert!(hostnames_overlap("*.example.com", "*.example.com"));
    }

    #[test]
    fn effective_hostnames_catch_all() {
        // listener: none, route: none -> empty Vec (catch-all)
        let got = effective_hostnames(None, &[]).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn effective_hostnames_listener_only() {
        let got = effective_hostnames(Some("a.example.com"), &[]).unwrap();
        assert_eq!(got, vec!["a.example.com"]);
    }

    #[test]
    fn effective_hostnames_route_only() {
        let got =
            effective_hostnames(None, &["a.example.com".into(), "b.example.com".into()]).unwrap();
        assert_eq!(got, vec!["a.example.com", "b.example.com"]);
    }

    #[test]
    fn effective_hostnames_exact_intersect_singleton() {
        let got = effective_hostnames(
            Some("a.example.com"),
            &["a.example.com".into(), "b.example.com".into()],
        )
        .unwrap();
        assert_eq!(got, vec!["a.example.com"]);
    }

    #[test]
    fn effective_hostnames_exact_intersect_empty_drops() {
        assert!(effective_hostnames(Some("x.example.com"), &["a.example.com".into()]).is_none());
    }

    #[test]
    fn effective_hostnames_wildcard_listener_covers_route() {
        let got = effective_hostnames(
            Some("*.example.com"),
            &["a.example.com".into(), "b.other.com".into()],
        )
        .unwrap();
        assert_eq!(got, vec!["a.example.com"]);
    }

    #[test]
    fn effective_hostnames_wildcard_route_covers_listener() {
        let got = effective_hostnames(Some("api.example.com"), &["*.example.com".into()]).unwrap();
        assert_eq!(got, vec!["*.example.com"]);
    }

    // ---------- emit_routes_under_listener with hostnames ----------

    fn http_route_with_hostnames(
        ns: &str,
        name: &str,
        parents: Vec<HttpRouteParentRefs>,
        rules: Vec<HttpRouteRules>,
        hostnames: Vec<String>,
    ) -> HTTPRoute {
        let mut hr = http_route(ns, name, parents, rules);
        hr.spec.hostnames = Some(hostnames);
        hr
    }

    #[test]
    fn route_hostnames_fan_out_across_matches() {
        // Listener has no hostname; route has two hostnames.
        // Expect: one HttpRouteUpsert with 2 HttpMatches (one per host).
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route_with_hostnames(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(Some("/"), vec![backend_ref("svc", 8080)], vec![])],
                vec!["a.example.com".into(), "b.example.com".into()],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().expect("one route");
        assert_eq!(route.matches.len(), 2, "fan-out across 2 hostnames");
        let mut hosts: Vec<&str> = route.matches.iter().map(|m| m.host.as_str()).collect();
        hosts.sort_unstable();
        assert_eq!(hosts, vec!["a.example.com", "b.example.com"]);
        for m in &route.matches {
            assert!(m.has_host);
        }
    }

    #[test]
    fn route_with_non_overlapping_hostnames_is_dropped() {
        // Listener hostname: a.example.com. Route hostnames don't overlap.
        // Expect: nothing emitted for routes (snapshot may not even
        // have the slice if no other resources contribute, but the
        // Gateway's Bind + Listener still come from the Gateway pass).
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, Some("a.example.com"))],
            )],
            http_routes: vec![http_route_with_hostnames(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(Some("/"), vec![backend_ref("svc", 8080)], vec![])],
                vec!["other.example.com".into()],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        assert!(
            s.routes.is_empty(),
            "no routes when hostnames don't overlap"
        );
    }

    #[test]
    fn listener_hostname_propagates_when_route_has_none() {
        // Listener hostname: a.example.com. Route has no hostnames.
        // Expect: one HttpMatch with host = a.example.com.
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, Some("a.example.com"))],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(Some("/"), vec![backend_ref("svc", 8080)], vec![])],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().unwrap();
        assert_eq!(route.matches.len(), 1);
        assert!(route.matches[0].has_host);
        assert_eq!(route.matches[0].host, "a.example.com");
    }

    #[test]
    fn wildcard_route_hostname_passes_through_to_match() {
        // Route hostname "*.example.com" travels as-is into HttpMatch.host
        // for the resolver to wildcard-match at request time.
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route_with_hostnames(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(Some("/"), vec![backend_ref("svc", 8080)], vec![])],
                vec!["*.example.com".into()],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().unwrap();
        assert_eq!(route.matches.len(), 1);
        assert!(route.matches[0].has_host);
        assert_eq!(route.matches[0].host, "*.example.com");
    }

    // ---------- Exact path match ----------

    #[test]
    fn exact_path_match_translates_to_exact_kind() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![HttpRouteRules {
                    matches: Some(vec![HttpRouteRulesMatches {
                        path: Some(path_exact("/manifest.json")),
                        headers: None,
                        query_params: None,
                        method: None,
                    }]),
                    backend_refs: Some(vec![backend_ref("svc", 8080)]),
                    filters: Some(vec![]),
                    name: None,
                    timeouts: None,
                }],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().expect("one route");
        assert_eq!(route.matches.len(), 1);
        let path = route.matches[0].path.as_ref().expect("path set");
        assert_eq!(path.kind, pb::PathMatchKind::Exact as i32);
        assert_eq!(path.value, "/manifest.json");
    }

    // ---------- Regex path match ----------

    #[test]
    fn regex_path_match_translates_to_regex_kind() {
        // Previously dropped with a warn; this asserts that a
        // RegularExpression path now round-trips to the proto as
        // `PATH_MATCH_KIND_REGEX` with the pattern preserved as a
        // string. Compilation happens at the data plane via
        // `gateway-cp-client::convert::path_match`.
        let pattern = r"^/api/v\d+$";
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![HttpRouteRules {
                    matches: Some(vec![HttpRouteRulesMatches {
                        path: Some(path_regex(pattern)),
                        headers: None,
                        query_params: None,
                        method: None,
                    }]),
                    backend_refs: Some(vec![backend_ref("svc", 8080)]),
                    filters: Some(vec![]),
                    name: None,
                    timeouts: None,
                }],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().expect("one route");
        assert_eq!(route.matches.len(), 1, "regex match must not drop the rule");
        let path = route.matches[0].path.as_ref().expect("path set");
        assert_eq!(path.kind, pb::PathMatchKind::Regex as i32);
        assert_eq!(path.value, pattern);
    }

    // ---------- method / headers / queryParams ----------

    use gateway_api::apis::standard::httproutes::{
        HttpRouteRulesMatchesHeaders, HttpRouteRulesMatchesHeadersType,
        HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesQueryParams,
        HttpRouteRulesMatchesQueryParamsType,
    };

    fn match_full(
        path: Option<&str>,
        method: Option<HttpRouteRulesMatchesMethod>,
        headers: Vec<HttpRouteRulesMatchesHeaders>,
        query_params: Vec<HttpRouteRulesMatchesQueryParams>,
    ) -> HttpRouteRulesMatches {
        HttpRouteRulesMatches {
            path: path.map(path_prefix),
            method,
            headers: if headers.is_empty() {
                None
            } else {
                Some(headers)
            },
            query_params: if query_params.is_empty() {
                None
            } else {
                Some(query_params)
            },
        }
    }

    fn header_exact(name: &str, value: &str) -> HttpRouteRulesMatchesHeaders {
        HttpRouteRulesMatchesHeaders {
            name: name.into(),
            r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
            value: value.into(),
        }
    }

    fn header_regex(name: &str, value: &str) -> HttpRouteRulesMatchesHeaders {
        HttpRouteRulesMatchesHeaders {
            name: name.into(),
            r#type: Some(HttpRouteRulesMatchesHeadersType::RegularExpression),
            value: value.into(),
        }
    }

    fn qp_exact(name: &str, value: &str) -> HttpRouteRulesMatchesQueryParams {
        HttpRouteRulesMatchesQueryParams {
            name: name.into(),
            r#type: Some(HttpRouteRulesMatchesQueryParamsType::Exact),
            value: value.into(),
        }
    }

    fn qp_regex(name: &str, value: &str) -> HttpRouteRulesMatchesQueryParams {
        HttpRouteRulesMatchesQueryParams {
            name: name.into(),
            r#type: Some(HttpRouteRulesMatchesQueryParamsType::RegularExpression),
            value: value.into(),
        }
    }

    fn route_with_match(m: HttpRouteRulesMatches) -> HttpRouteRules {
        HttpRouteRules {
            matches: Some(vec![m]),
            backend_refs: Some(vec![backend_ref("svc", 8080)]),
            filters: Some(vec![]),
            name: None,
            timeouts: None,
        }
    }

    fn single_route_state(m: HttpRouteRulesMatches) -> K8sState {
        K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![route_with_match(m)],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        }
    }

    #[test]
    fn method_match_translated_to_proto_enum() {
        let state = single_route_state(match_full(
            Some("/"),
            Some(HttpRouteRulesMatchesMethod::Post),
            vec![],
            vec![],
        ));
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let m = &s.routes.values().next().unwrap().matches[0];
        assert_eq!(m.method, pb::HttpMethod::Post as i32);
    }

    #[test]
    fn header_match_exact_and_regex_translated() {
        let state = single_route_state(match_full(
            Some("/"),
            None,
            vec![
                header_exact("x-feature", "on"),
                header_regex("x-version", r"^v\d+$"),
            ],
            vec![],
        ));
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let m = &s.routes.values().next().unwrap().matches[0];
        assert_eq!(m.header_matches.len(), 2);
        assert_eq!(m.header_matches[0].name, "x-feature");
        assert!(matches!(
            m.header_matches[0].value,
            Some(pb::header_match::Value::Exact(_))
        ));
        assert!(matches!(
            m.header_matches[1].value,
            Some(pb::header_match::Value::Regex(_))
        ));
    }

    #[test]
    fn duplicate_header_name_case_insensitive_first_wins() {
        // "X-Debug" and "x-debug" must collapse to one entry, keeping
        // the first.
        let state = single_route_state(match_full(
            Some("/"),
            None,
            vec![
                header_exact("X-Debug", "1"),
                header_exact("x-debug", "2"),
                header_exact("y-Other", "z"),
            ],
            vec![],
        ));
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let m = &s.routes.values().next().unwrap().matches[0];
        assert_eq!(m.header_matches.len(), 2);
        assert_eq!(m.header_matches[0].name, "X-Debug");
        assert!(matches!(
            &m.header_matches[0].value,
            Some(pb::header_match::Value::Exact(v)) if v == "1"
        ));
        assert_eq!(m.header_matches[1].name, "y-Other");
    }

    #[test]
    fn query_param_match_translated() {
        let state = single_route_state(match_full(
            Some("/"),
            None,
            vec![],
            vec![qp_exact("preview", "true"), qp_regex("v", r"^v\d+$")],
        ));
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let m = &s.routes.values().next().unwrap().matches[0];
        assert_eq!(m.query_param_matches.len(), 2);
        assert!(matches!(
            m.query_param_matches[0].value,
            Some(pb::query_param_match::Value::Exact(_))
        ));
        assert!(matches!(
            m.query_param_matches[1].value,
            Some(pb::query_param_match::Value::Regex(_))
        ));
    }

    #[test]
    fn duplicate_query_param_name_case_sensitive_first_wins() {
        // Query keys are case-sensitive; `K` and `k` are NOT
        // duplicates. `k` repeated IS a duplicate.
        let state = single_route_state(match_full(
            Some("/"),
            None,
            vec![],
            vec![qp_exact("k", "1"), qp_exact("k", "2"), qp_exact("K", "3")],
        ));
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let m = &s.routes.values().next().unwrap().matches[0];
        assert_eq!(m.query_param_matches.len(), 2);
        assert_eq!(m.query_param_matches[0].name, "k");
        assert_eq!(m.query_param_matches[1].name, "K");
    }

    // ---------- appProtocol → BackendProtocol ----------

    /// Build a state with one route → one backend on `port`,
    /// where the Service declares `port` with the given
    /// `app_protocol`. Returns the emitted `BackendUpsert.protocol`
    /// for assertion.
    fn translate_app_protocol(app_protocol: Option<&str>, port: i32) -> pb::BackendProtocol {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(Some("/"), vec![backend_ref("svc", port)], vec![])],
            )],
            services: vec![service_with_ports(
                "demo",
                "svc",
                Some("10.0.0.1"),
                &[(port, app_protocol)],
            )],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let be = s.backends.values().next().expect("one backend emitted");
        pb::BackendProtocol::try_from(be.protocol).expect("known proto enum")
    }

    #[test]
    fn app_protocol_grpc_yields_http2() {
        assert_eq!(
            translate_app_protocol(Some("grpc"), 8080),
            pb::BackendProtocol::Http2
        );
    }

    #[test]
    fn app_protocol_h2c_yields_http2() {
        assert_eq!(
            translate_app_protocol(Some("h2c"), 8080),
            pb::BackendProtocol::Http2
        );
    }

    #[test]
    fn app_protocol_kubernetes_io_h2c_yields_http2() {
        assert_eq!(
            translate_app_protocol(Some("kubernetes.io/h2c"), 8080),
            pb::BackendProtocol::Http2
        );
    }

    #[test]
    fn app_protocol_kubernetes_io_ws_yields_http1() {
        // Websocket variant is not an HTTP/2 indicator.
        assert_eq!(
            translate_app_protocol(Some("kubernetes.io/ws"), 8080),
            pb::BackendProtocol::Http1
        );
    }

    #[test]
    fn app_protocol_unknown_yields_http1() {
        assert_eq!(
            translate_app_protocol(Some("mycompany.com/something"), 8080),
            pb::BackendProtocol::Http1
        );
    }

    // ---- secret emission ----

    #[test]
    fn referenced_secret_emitted_with_material() {
        // HTTPS listeners aren't translated yet, but the secret they
        // reference must still be published.
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![https_listener(
                    "https",
                    443,
                    Some("a.example.com"),
                    &[("", "foo")],
                )],
            )],
            endpoint_slices: vec![],
            secrets: vec![tls_secret("demo", "foo", "CERTPEM", "KEYPEM")],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).expect("snapshot");
        let up = s
            .secrets
            .get(&SecretKey::new("demo", "foo"))
            .expect("secret emitted");
        assert_eq!(up.namespace, "demo");
        assert_eq!(up.name, "foo");
        assert_eq!(up.cert_pem, "CERTPEM");
        assert_eq!(up.key_pem, "KEYPEM");
    }

    #[test]
    fn unreferenced_secret_not_emitted() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![https_listener(
                    "https",
                    443,
                    Some("a.example.com"),
                    &[("", "foo")],
                )],
            )],
            endpoint_slices: vec![],
            secrets: vec![
                tls_secret("demo", "foo", "CERTPEM", "KEYPEM"),
                tls_secret("demo", "bar", "OTHER", "OTHER"),
            ],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).expect("snapshot");
        assert!(s.secrets.contains_key(&SecretKey::new("demo", "foo")));
        assert!(
            !s.secrets.contains_key(&SecretKey::new("demo", "bar")),
            "the cluster's other TLS secrets must not be broadcast"
        );
    }

    #[test]
    fn cross_namespace_certref_resolves_permissively() {
        // Accepted without a ReferenceGrant check for now; the
        // secret is emitted under its own namespace-qualified key.
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![https_listener(
                    "https",
                    443,
                    Some("a.example.com"),
                    &[("other", "foo")],
                )],
            )],
            endpoint_slices: vec![],
            secrets: vec![tls_secret("other", "foo", "CERTPEM", "KEYPEM")],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).expect("snapshot");
        assert!(s.secrets.contains_key(&SecretKey::new("other", "foo")));
    }

    #[test]
    fn missing_secret_skipped() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![https_listener(
                    "https",
                    443,
                    Some("a.example.com"),
                    &[("", "foo")],
                )],
            )],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).expect("snapshot");
        assert!(s.secrets.is_empty());
    }

    // ---- HTTPS listener translation ----

    #[test]
    fn https_listener_emits_tls_bind_and_refs() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![https_listener(
                    "https",
                    443,
                    Some("a.example.com"),
                    &[("", "foo")],
                )],
            )],
            endpoint_slices: vec![],
            secrets: vec![tls_secret("demo", "foo", "CERT", "KEY")],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let snap = out.get(&("demo".into(), "api".into())).expect("slice");

        let bind = snap.binds.get(&BindKey::new("demo/api:443")).expect("bind");
        assert_eq!(bind.bind_protocol, pb::BindProtocol::Tls as i32);

        let lk = ListenerKey::new(BindKey::new("demo/api:443"), "https");
        let listener = snap.listeners.get(&lk).expect("listener");
        let tls = listener.tls.as_ref().expect("tls config");
        assert_eq!(tls.mode, pb::TlsMode::Terminate as i32);
        assert_eq!(tls.certificate_refs.len(), 1);
        assert_eq!(tls.certificate_refs[0].namespace, "demo");
        assert_eq!(tls.certificate_refs[0].name, "foo");
    }

    #[test]
    fn http_and_https_cannot_share_a_port() {
        // First listener on the port establishes its protocol; a later
        // listener of the other protocol is skipped (first-wins).
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![
                    http_listener("plain", 8443, Some("a.example.com")),
                    https_listener("secure", 8443, Some("b.example.com"), &[("", "foo")]),
                ],
            )],
            endpoint_slices: vec![],
            secrets: vec![tls_secret("demo", "foo", "CERT", "KEY")],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let snap = out.get(&("demo".into(), "api".into())).expect("slice");
        let bind = snap
            .binds
            .get(&BindKey::new("demo/api:8443"))
            .expect("bind");
        assert_eq!(bind.bind_protocol, pb::BindProtocol::Http as i32);
        assert!(
            snap.listeners
                .contains_key(&ListenerKey::new(BindKey::new("demo/api:8443"), "plain"))
        );
        assert!(
            !snap
                .listeners
                .contains_key(&ListenerKey::new(BindKey::new("demo/api:8443"), "secure")),
            "the conflicting HTTPS listener must be skipped"
        );
    }

    #[test]
    fn passthrough_listener_skipped() {
        let passthrough = GatewayListeners {
            name: "pass".into(),
            protocol: "HTTPS".into(),
            port: 443,
            hostname: Some("a.example.com".into()),
            tls: Some(GatewayListenersTls {
                mode: Some(GatewayListenersTlsMode::Passthrough),
                options: None,
                certificate_refs: None,
            }),
            allowed_routes: Some(GatewayListenersAllowedRoutes {
                namespaces: Some(GatewayListenersAllowedRoutesNamespaces {
                    from: None,
                    selector: None,
                }),
                kinds: None,
            }),
        };
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw("demo", "api", "zd", vec![passthrough])],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let snap = out.get(&("demo".into(), "api".into())).expect("slice");
        assert!(snap.binds.is_empty(), "passthrough creates no bind");
        assert!(snap.listeners.is_empty(), "passthrough creates no listener");
    }

    #[test]
    fn cross_namespace_certref_carried_on_listener() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![https_listener(
                    "https",
                    443,
                    Some("a.example.com"),
                    &[("other", "foo")],
                )],
            )],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let snap = out.get(&("demo".into(), "api".into())).expect("slice");
        let lk = ListenerKey::new(BindKey::new("demo/api:443"), "https");
        let tls = snap
            .listeners
            .get(&lk)
            .expect("listener")
            .tls
            .as_ref()
            .expect("tls config");
        // Accepted permissively (no ReferenceGrant check yet), with
        // the referenced namespace carried through.
        assert_eq!(tls.certificate_refs.len(), 1);
        assert_eq!(tls.certificate_refs[0].namespace, "other");
        assert_eq!(tls.certificate_refs[0].name, "foo");
    }

    #[test]
    fn no_app_protocol_yields_http1() {
        // Regression guard: the pre-issue-#4 default behaviour.
        assert_eq!(
            translate_app_protocol(None, 8080),
            pb::BackendProtocol::Http1
        );
    }

    #[test]
    fn route_port_not_declared_on_service_yields_http1_fallback() {
        // BackendRef references port 9999 but the Service only
        // declares port 8080. Backend still emits (via ClusterIP);
        // protocol falls back to HTTP/1.1.
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(Some("/"), vec![backend_ref("svc", 9999)], vec![])],
            )],
            // Only port 8080 declared, with appProtocol grpc — but
            // the route points at 9999, so the appProtocol does not
            // apply.
            services: vec![service_with_ports(
                "demo",
                "svc",
                Some("10.0.0.1"),
                &[(8080, Some("grpc"))],
            )],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let be = s.backends.values().next().expect("backend emitted");
        assert_eq!(
            pb::BackendProtocol::try_from(be.protocol).unwrap(),
            pb::BackendProtocol::Http1,
            "unmatched port must fall back to H1"
        );
    }
    // ---------- Catch-all for rules with no matches ----------

    #[test]
    fn rule_without_matches_emits_path_prefix_catchall() {
        // Per spec an absent `matches` defaults to `PathPrefix /`.
        // The route has a hostname, so the fan-out must apply to the
        // synthesized match too.
        let mut r = rule(None, vec![backend_ref("svc", 8080)], vec![]);
        r.matches = None;
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route_with_hostnames(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![r],
                vec!["app.example.com".into()],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().expect("one route");

        assert_eq!(route.matches.len(), 1);
        let m = &route.matches[0];
        assert!(m.has_host);
        assert_eq!(m.host, "app.example.com");
        let path = m.path.as_ref().expect("path set");
        assert_eq!(path.kind, pb::PathMatchKind::PathPrefix as i32);
        assert_eq!(path.value, "/");
    }

    fn extension_ref_filter(group: &str, kind: &str, name: &str) -> HttpRouteRulesFilters {
        HttpRouteRulesFilters {
            r#type:
                gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersType::ExtensionRef,
            request_header_modifier: None,
            response_header_modifier: None,
            request_redirect: None,
            url_rewrite: None,
            request_mirror: None,
            extension_ref: Some(
                gateway_api::apis::standard::httproutes::HttpRouteRulesFiltersExtensionRef {
                    group: group.into(),
                    kind: kind.into(),
                    name: name.into(),
                },
            ),
            cors: None,
        }
    }

    fn extension_object(ns: &str, name: &str) -> crate::crd::Extension {
        let spec = crate::crd::ExtensionSpec {
            class: "request_header_modifier".into(),
            failure_mode: crate::crd::FailureMode::Open,
            limits: crate::crd::Limits {
                request_body: Some(crate::crd::RequestBodyLimit::Stream),
                max_buffer_bytes: None,
            },
            config: serde_json::json!({ "add": [ { "name": "x-a", "value": "1" } ] }),
        };
        let mut ext = crate::crd::Extension::new(name, spec);
        ext.metadata.namespace = Some(ns.into());
        ext
    }

    #[test]
    fn extension_ref_translates_and_emits_the_object() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(
                    Some("/"),
                    vec![],
                    vec![extension_ref_filter(
                        "gateway.linkerd.io",
                        "Extension",
                        "picker",
                    )],
                )],
            )],
            services: vec![],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![extension_object("demo", "picker")],
        };
        let out = translate(&state, OURS);
        let snapshot = out.values().next().expect("one gateway");

        // The route carries the ref, namespaced to the route.
        let route = snapshot.routes.values().next().expect("one route");
        let filter = route.filters.first().expect("one filter");
        let Some(pb::http_filter::Kind::ExtensionRef(er)) = &filter.kind else {
            panic!("expected an ExtensionRef filter");
        };
        assert_eq!(er.name, "picker");
        assert_eq!(er.namespace, "demo");

        // The object is emitted, enums and config mapped.
        let upsert = snapshot
            .extensions
            .get(&ExtensionKey::new("demo", "picker"))
            .expect("extension emitted");
        assert_eq!(upsert.class, "request_header_modifier");
        assert_eq!(upsert.failure_mode, pb::FailureMode::Open as i32);
        assert_eq!(
            upsert.limits.as_ref().unwrap().request_body,
            pb::RequestBodyLimit::Stream as i32
        );
        assert!(upsert.config_yaml.contains("x-a"));
    }

    #[test]
    fn missing_extension_object_keeps_the_ref_and_emits_nothing() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(
                    Some("/"),
                    vec![],
                    vec![extension_ref_filter(
                        "gateway.linkerd.io",
                        "Extension",
                        "ghost",
                    )],
                )],
            )],
            services: vec![],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let snapshot = out.values().next().expect("one gateway");
        let route = snapshot.routes.values().next().expect("one route");
        assert_eq!(route.filters.len(), 1, "the ref survives translation");
        assert!(snapshot.extensions.is_empty(), "nothing to emit yet");
    }

    #[test]
    fn foreign_extension_ref_is_dropped() {
        let state = K8sState {
            gateway_classes: vec![gc("zd", OURS)],
            gateways: vec![gw(
                "demo",
                "api",
                "zd",
                vec![http_listener("http", 80, None)],
            )],
            http_routes: vec![http_route(
                "demo",
                "r",
                vec![parent_ref("api", Some("demo"), None)],
                vec![rule(
                    Some("/"),
                    vec![],
                    vec![extension_ref_filter("other.io", "Widget", "w")],
                )],
            )],
            services: vec![],
            endpoint_slices: vec![],
            secrets: vec![],
            extensions: vec![],
        };
        let out = translate(&state, OURS);
        let snapshot = out.values().next().expect("one gateway");
        let route = snapshot.routes.values().next().expect("one route");
        assert!(route.filters.is_empty(), "foreign refs drop with a warn");
        assert!(snapshot.extensions.is_empty());
    }
}
