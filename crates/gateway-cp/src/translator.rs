//! K8s resources -> per-Gateway snapshots.
//!
//! One `Gateway` = one snapshot keyed by `(namespace, name)`.
//! `HTTPRoute`s attach to multiple snapshots if they list multiple
//! parent Gateways. Services are duplicated across slices that
//! reference them.

use std::collections::HashMap;

use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::{Gateway, GatewayListeners};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteRulesBackendRefs, HttpRouteRulesFilters, HttpRouteRulesMatches,
    HttpRouteRulesMatchesHeaders, HttpRouteRulesMatchesHeadersType, HttpRouteRulesMatchesMethod,
    HttpRouteRulesMatchesPathType, HttpRouteRulesMatchesQueryParams,
    HttpRouteRulesMatchesQueryParamsType,
};
use gateway_cp_proto::v1 as pb;
use gateway_state::{BackendKey, BindKey, ListenerKey, RouteKey, SecretKey};
use k8s_openapi::api::core::v1::{Secret, Service};

use crate::snapshot::{GatewayId, Snapshot};

#[derive(Debug, Default)]
pub struct K8sState {
    pub gateway_classes: Vec<GatewayClass>,
    pub gateways: Vec<Gateway>,
    pub http_routes: Vec<HTTPRoute>,
    pub services: Vec<Service>,
    pub secrets: Vec<Secret>,
}

/// Build per-Gateway snapshots from a static K8s state.
///
/// Two passes:
/// 1. Walk Gateways whose class is one we control; group their
///    listeners by port and emit one `BindUpsert` per (Gateway,
///    port) plus one `ListenerUpsert` per accepted listener.
/// 2. Walk `HTTPRoute`s; for each `parentRef` pointing at a controlled
///    Gateway, emit one `HttpRouteUpsert` per (matched listener × rule)
///    plus a `BackendUpsert` for every referenced Service.
///
/// Skips (with a warn log, no error): non-HTTP listeners, listeners
/// conflicting on a shared port, foreign `GatewayClass`es, unknown
/// filter types, cross-namespace backendRefs, headless / missing
/// Services.
pub fn translate(state: &K8sState, controller_name: &str) -> HashMap<GatewayId, Snapshot> {
    // Index everything keyed by lookup paths the passes need.
    let owned_classes = collect_owned_classes(state, controller_name);
    let gateways_by_id = index_gateways(state);
    let services_by_id = index_services(state);
    let secrets_by_id = index_secrets(state);

    let mut slices: HashMap<GatewayId, Snapshot> = HashMap::new();
    // Listeners that survived pass-1 classification, per gateway:
    // listener name -> port. Pass 2 attaches routes only to these.
    let mut accepted_listeners: HashMap<GatewayId, HashMap<String, i32>> = HashMap::new();

    // Pass 1: one Bind per (Gateway, port), N Listeners under it.
    for gw in &state.gateways {
        let Some(ns) = gw.metadata.namespace.as_deref() else {
            continue;
        };
        let Some(name) = gw.metadata.name.as_deref() else {
            continue;
        };
        if !owned_classes.contains(gw.spec.gateway_class_name.as_str()) {
            continue;
        }
        let id: GatewayId = (ns.to_string(), name.to_string());
        let snapshot = slices.entry(id.clone()).or_default();

        let accepted = emit_gateway_listeners(snapshot, ns, name, &gw.spec.listeners);
        emit_gateway_secrets(snapshot, ns, &gw.spec.listeners, &secrets_by_id);
        accepted_listeners.insert(id, accepted);
    }

    // Pass 2: HTTPRoutes attach to their parent Gateways.
    for hr in &state.http_routes {
        let Some(route_ns) = hr.metadata.namespace.as_deref() else {
            continue;
        };
        let Some(route_name) = hr.metadata.name.as_deref() else {
            continue;
        };
        let parent_refs = hr.spec.parent_refs.as_deref().unwrap_or(&[]);
        for parent_ref in parent_refs {
            let parent_ns = parent_ref.namespace.as_deref().unwrap_or(route_ns);
            let parent_name = parent_ref.name.as_str();
            let Some(gw) = gateways_by_id.get(&(parent_ns, parent_name)) else {
                continue;
            };
            if !owned_classes.contains(gw.spec.gateway_class_name.as_str()) {
                continue;
            }

            // sectionName narrows the parentRef to a single listener
            // on the gateway; unset == attach to all.
            let section = parent_ref.section_name.as_deref();
            let target_listeners: Vec<&GatewayListeners> = gw
                .spec
                .listeners
                .iter()
                .filter(|l| section.is_none_or(|s| s == l.name.as_str()))
                .collect();

            let id: GatewayId = (parent_ns.to_string(), parent_name.to_string());
            let accepted = accepted_listeners.get(&id);
            let snapshot = slices.entry(id).or_default();

            for listener in target_listeners {
                // Listeners classified out in pass 1 (non-HTTP,
                // conflicted) take no route attachments.
                let Some(&port) = accepted.and_then(|m| m.get(listener.name.as_str())) else {
                    continue;
                };
                emit_routes_under_listener(
                    snapshot,
                    &bind_name(parent_ns, parent_name, port),
                    listener,
                    hr,
                    route_ns,
                    route_name,
                );
            }

            // Backends referenced anywhere in this route, in this Gateway's slice.
            for rule in hr.spec.rules.as_deref().unwrap_or(&[]) {
                for br in rule.backend_refs.as_deref().unwrap_or(&[]) {
                    emit_backend(snapshot, route_ns, br, &services_by_id);
                }
            }
        }
    }

    slices
}

fn collect_owned_classes<'a>(
    state: &'a K8sState,
    controller_name: &str,
) -> std::collections::HashSet<&'a str> {
    state
        .gateway_classes
        .iter()
        .filter(|gc| gc.spec.controller_name == controller_name)
        .filter_map(|gc| gc.metadata.name.as_deref())
        .collect()
}

fn index_gateways(state: &K8sState) -> HashMap<(&str, &str), &Gateway> {
    state
        .gateways
        .iter()
        .filter_map(|g| {
            let ns = g.metadata.namespace.as_deref()?;
            let name = g.metadata.name.as_deref()?;
            Some(((ns, name), g))
        })
        .collect()
}

fn index_services(state: &K8sState) -> HashMap<(&str, &str), &Service> {
    state
        .services
        .iter()
        .filter_map(|s| {
            let ns = s.metadata.namespace.as_deref()?;
            let name = s.metadata.name.as_deref()?;
            Some(((ns, name), s))
        })
        .collect()
}

fn index_secrets(state: &K8sState) -> HashMap<(&str, &str), &Secret> {
    state
        .secrets
        .iter()
        .filter_map(|s| {
            let ns = s.metadata.namespace.as_deref()?;
            let name = s.metadata.name.as_deref()?;
            Some(((ns, name), s))
        })
        .collect()
}

/// Per-port classification state while grouping a Gateway's
/// listeners: the `BindProtocol` established by the first accepted
/// listener on the port (every later listener must agree) and the
/// hostnames already taken (None == catch-all; duplicates conflict).
type PortGroup = (pb::BindProtocol, std::collections::HashSet<Option<String>>);

/// Walk a Gateway's listeners in spec order, group them by port, and
/// emit one `BindUpsert` per port plus one `ListenerUpsert` per
/// accepted listener. Returns the accepted set (listener name →
/// port) for the route pass.
///
/// Classification is first-listener-wins, per the Gateway API
/// listener-distinctness rule. A listener is skipped (warn, no
/// error) when:
/// * its protocol isn't HTTP — v0 translates HTTP only;
/// * its `BindProtocol` disagrees with the listener that established
///   the port's bind — unreachable while only HTTP is accepted, but
///   load-bearing once HTTPS translation lands;
/// * its hostname duplicates an accepted listener on the same port
///   (two unset hostnames collide too).
fn emit_gateway_listeners(
    snapshot: &mut Snapshot,
    gw_ns: &str,
    gw_name: &str,
    listeners: &[GatewayListeners],
) -> HashMap<String, i32> {
    let mut accepted: HashMap<String, i32> = HashMap::new();
    let mut ports: HashMap<i32, PortGroup> = HashMap::new();

    for listener in listeners {
        if listener.protocol != "HTTP" {
            tracing::warn!(
                gateway = gw_name,
                listener = %listener.name,
                protocol = %listener.protocol,
                "skipping non-HTTP listener"
            );
            continue;
        }
        let protocol = pb::BindProtocol::Http;

        let bind_name = bind_name(gw_ns, gw_name, listener.port);
        // First accepted-protocol listener on a port creates the
        // bind and establishes its protocol. The listener itself
        // can't conflict yet (no hostnames recorded), so a bind is
        // never emitted empty.
        let (bind_protocol, hostnames) = ports.entry(listener.port).or_insert_with(|| {
            snapshot.binds.insert(
                BindKey::new(&bind_name),
                pb::BindUpsert {
                    name: bind_name.clone(),
                    address: "0.0.0.0".into(),
                    port: listener.port.unsigned_abs(),
                    bind_protocol: protocol as i32,
                },
            );
            (protocol, std::collections::HashSet::new())
        });

        if *bind_protocol != protocol {
            tracing::warn!(
                gateway = gw_name,
                listener = %listener.name,
                port = listener.port,
                "skipping listener: protocol conflicts with the port's bind"
            );
            continue;
        }
        if !hostnames.insert(listener.hostname.clone()) {
            tracing::warn!(
                gateway = gw_name,
                listener = %listener.name,
                port = listener.port,
                hostname = listener.hostname.as_deref().unwrap_or("<none>"),
                "skipping listener: hostname conflicts on a shared port"
            );
            continue;
        }

        let lk = ListenerKey::new(BindKey::new(&bind_name), &listener.name);
        snapshot.listeners.insert(
            lk,
            pb::ListenerUpsert {
                key: Some(pb::ListenerKey {
                    bind: bind_name.clone(),
                    name: listener.name.clone(),
                }),
                hostname: listener.hostname.clone().unwrap_or_default(),
                has_hostname: listener.hostname.is_some(),
                tls: None,
            },
        );
        accepted.insert(listener.name.clone(), listener.port);
    }

    accepted
}

/// Emit a `SecretUpsert` for each `kubernetes.io/tls` Secret referenced
/// by the gateway's listener `certificateRefs`. Same-namespace only;
/// cross-namespace refs need a `ReferenceGrant` (not yet supported) and
/// are skipped. Runs independent of listener acceptance so the material
/// is already published when HTTPS listeners are translated.
fn emit_gateway_secrets(
    snapshot: &mut Snapshot,
    gateway_ns: &str,
    listeners: &[GatewayListeners],
    secrets_by_id: &HashMap<(&str, &str), &Secret>,
) {
    for listener in listeners {
        let Some(refs) = listener
            .tls
            .as_ref()
            .and_then(|t| t.certificate_refs.as_ref())
        else {
            continue;
        };
        for r in refs {
            // Only core/v1 Secret refs are supported.
            if r.group.as_deref().is_some_and(|g| !g.is_empty()) {
                tracing::warn!(name = %r.name, group = ?r.group, "skipping non-core certificateRef");
                continue;
            }
            if r.kind.as_deref().is_some_and(|k| k != "Secret") {
                tracing::warn!(name = %r.name, kind = ?r.kind, "skipping non-Secret certificateRef");
                continue;
            }
            // Cross-namespace refs require a ReferenceGrant (not yet supported).
            if r.namespace
                .as_deref()
                .is_some_and(|n| !n.is_empty() && n != gateway_ns)
            {
                tracing::warn!(name = %r.name, namespace = ?r.namespace,
                    "skipping cross-namespace certificateRef");
                continue;
            }
            let Some(secret) = secrets_by_id.get(&(gateway_ns, r.name.as_str())) else {
                tracing::warn!(namespace = %gateway_ns, name = %r.name,
                    "certificateRef Secret not present yet");
                continue;
            };
            let Some((cert_pem, key_pem)) = tls_material(secret) else {
                tracing::warn!(namespace = %gateway_ns, name = %r.name,
                    "Secret missing or invalid tls.crt / tls.key");
                continue;
            };
            // HashMap insert dedups a Secret referenced by several listeners.
            snapshot.secrets.insert(
                SecretKey::new(gateway_ns, r.name.clone()),
                pb::SecretUpsert {
                    namespace: gateway_ns.to_string(),
                    name: r.name.clone(),
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

fn emit_routes_under_listener(
    snapshot: &mut Snapshot,
    bind_name: &str,
    listener: &GatewayListeners,
    hr: &HTTPRoute,
    route_ns: &str,
    route_name: &str,
) {
    // Intersect listener.hostname with route.spec.hostnames. If the
    // intersection is empty, the route doesn't attach to this
    // listener and we emit nothing.
    let route_hostnames = hr.spec.hostnames.as_deref().unwrap_or(&[]);
    let Some(effective) = effective_hostnames(listener.hostname.as_deref(), route_hostnames) else {
        tracing::debug!(
            route = route_name,
            listener = %listener.name,
            "route hostnames don't intersect listener hostname; skipping"
        );
        return;
    };

    let listener_key = ListenerKey::new(BindKey::new(bind_name), &listener.name);

    for (rule_idx, rule) in hr.spec.rules.as_deref().unwrap_or(&[]).iter().enumerate() {
        let route_full_name = format!("{route_ns}/{route_name}/rule{rule_idx}");
        let route_key = RouteKey::new(listener_key.clone(), &route_full_name);

        let base_matches: Vec<pb::HttpMatch> = rule
            .matches
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(translate_match)
            .collect();

        // Fan-out: one HttpMatch per (effective hostname × user
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

        let backend_refs = rule
            .backend_refs
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter_map(|br| translate_backend_ref(br, route_ns))
            .collect();

        let filters = rule
            .filters
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter_map(translate_filter)
            .collect();

        snapshot.routes.insert(
            route_key,
            pb::HttpRouteUpsert {
                key: Some(pb::RouteKey {
                    bind: bind_name.to_string(),
                    listener: listener.name.clone(),
                    name: route_full_name,
                }),
                matches,
                backend_refs,
                filters,
            },
        );
    }
}

/// Intersect a listener's hostname with an `HTTPRoute`'s hostnames
/// per the Gateway API. Returns:
/// * `Some(vec![])` — no host constraint (both sides empty);
///   `HttpMatch.has_host` stays false.
/// * `Some(non-empty)` — the set of effective hostnames; the route
///   fans out across them.
/// * `None` — the listener has a hostname and none of the route's
///   hostnames overlap; the attachment is dropped.
fn effective_hostnames(listener: Option<&str>, route: &[String]) -> Option<Vec<String>> {
    match (listener, route.is_empty()) {
        (None, true) => Some(Vec::new()),
        (None, false) => Some(route.to_vec()),
        (Some(l), true) => Some(vec![l.to_string()]),
        (Some(l), false) => {
            let kept: Vec<String> = route
                .iter()
                .filter(|r| hostnames_overlap(l, r))
                .cloned()
                .collect();
            if kept.is_empty() { None } else { Some(kept) }
        }
    }
}

/// Two hostnames overlap if they're equal (case-insensitive) or one
/// is a wildcard pattern that covers the other.
fn hostnames_overlap(a: &str, b: &str) -> bool {
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    if let Some(suffix) = a.strip_prefix("*.")
        && wildcard_covers(suffix, b)
    {
        return true;
    }
    if let Some(suffix) = b.strip_prefix("*.")
        && wildcard_covers(suffix, a)
    {
        return true;
    }
    false
}

/// Per Gateway API: `*.example.com` is a **suffix match** — it
/// covers `app.example.com`, `foo.bar.example.com`, and any other
/// hostname ending in `.example.com`. It does NOT cover
/// `example.com` itself (the wildcard requires at least one label
/// before the suffix). Case-insensitive.
///
/// `host` may itself be a wildcard pattern — `*.sub.example.com`
/// is covered by `*.example.com` because `foo.sub.example.com` is in
/// both their concrete sets.
fn wildcard_covers(pattern_suffix: &str, host: &str) -> bool {
    if host.len() <= pattern_suffix.len() {
        return false;
    }
    let (head, tail) = host.split_at(host.len() - pattern_suffix.len());
    if !tail.eq_ignore_ascii_case(pattern_suffix) {
        return false;
    }
    let Some(prefix) = head.strip_suffix('.') else {
        return false;
    };
    !prefix.is_empty()
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
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
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
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
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

fn translate_backend_ref(br: &HttpRouteRulesBackendRefs, route_ns: &str) -> Option<pb::BackendRef> {
    let port = br.port?;
    let backend_ns = br.namespace.as_deref().unwrap_or(route_ns);
    if backend_ns != route_ns {
        tracing::warn!(
            ns = backend_ns,
            "skipping cross-namespace backendRef (ReferenceGrant not supported in v0)"
        );
        return None;
    }
    let key = backend_key_string(backend_ns, &br.name, port);
    let weight = br.weight.unwrap_or(1);
    Some(pb::BackendRef {
        name: key,
        weight: weight.unsigned_abs(),
    })
}

fn translate_filter(f: &HttpRouteRulesFilters) -> Option<pb::HttpFilter> {
    if let Some(rhm) = f.request_header_modifier.as_ref() {
        let (add, set, remove) = translate_header_ops(
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
        return Some(pb::HttpFilter {
            kind: Some(pb::http_filter::Kind::RequestHeaderModifier(
                pb::RequestHeaderModifier {
                    name: String::new(),
                    request_headers: Some(pb::HeaderOps { add, set, remove }),
                },
            )),
        });
    }
    if let Some(rhm) = f.response_header_modifier.as_ref() {
        let (add, set, remove) = translate_header_ops(
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
        return Some(pb::HttpFilter {
            kind: Some(pb::http_filter::Kind::ResponseHeaderModifier(
                pb::ResponseHeaderModifier {
                    name: String::new(),
                    response_headers: Some(pb::HeaderOps { add, set, remove }),
                },
            )),
        });
    }
    tracing::warn!(?f.r#type, "skipping unsupported HTTPRoute filter");
    None
}

/// Shared add/set/remove translator for the request- and
/// response-side header modifiers. Returns proto-shaped vecs.
fn translate_header_ops<'a, A, S, R>(
    add: A,
    set: S,
    remove: R,
) -> (Vec<pb::HeaderPair>, Vec<pb::HeaderPair>, Vec<String>)
where
    A: Iterator<Item = (&'a String, &'a String)>,
    S: Iterator<Item = (&'a String, &'a String)>,
    R: Iterator<Item = &'a str>,
{
    let to_pair = |(name, value): (&String, &String)| pb::HeaderPair {
        name: name.clone(),
        value: value.clone(),
    };
    (
        add.map(to_pair).collect(),
        set.map(to_pair).collect(),
        remove.map(str::to_owned).collect(),
    )
}

/// Emit one `BackendUpsert` per (svc, port) referenced by a route in
/// this slice. Idempotent — same (svc, port) reached by multiple rules
/// only produces one entry per slice. Missing or headless Services
/// emit nothing; the DP-side Store stashes any dependent route until
/// the backend lands.
///
/// Protocol is derived from `Service.spec.ports[*].appProtocol` for
/// the port matching `backendRef.port`. Port names are intentionally
/// not inspected — the K8s API treats name as an operator-facing
/// label only; `appProtocol` is the standard hint. See
/// [`map_app_protocol`] for recognized values.
fn emit_backend(
    snapshot: &mut Snapshot,
    route_ns: &str,
    br: &HttpRouteRulesBackendRefs,
    services_by_id: &HashMap<(&str, &str), &Service>,
) {
    let Some(port) = br.port else { return };
    let backend_ns = br.namespace.as_deref().unwrap_or(route_ns);
    if backend_ns != route_ns {
        return; // cross-ns; ReferenceGrant not supported in v0
    }
    let key_str = backend_key_string(backend_ns, &br.name, port);
    let bk = BackendKey::new(&key_str);
    if snapshot.backends.contains_key(&bk) {
        return;
    }
    let Some(svc) = services_by_id.get(&(backend_ns, br.name.as_str())) else {
        return;
    };
    let Some(spec) = svc.spec.as_ref() else {
        return;
    };
    let cluster_ip = spec.cluster_ip.as_deref().unwrap_or("");
    if cluster_ip.is_empty() || cluster_ip == "None" {
        return; // headless / unassigned
    }
    let port_app_protocol = spec
        .ports
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|p| p.port == port)
        .and_then(|p| p.app_protocol.as_deref());
    let protocol = map_app_protocol(port_app_protocol);
    snapshot.backends.insert(
        bk,
        pb::BackendUpsert {
            name: key_str,
            endpoints: vec![pb::Endpoint {
                name: format!("{backend_ns}/{}", br.name),
                address: cluster_ip.to_string(),
                port: port.unsigned_abs(),
            }],
            protocol: protocol as i32,
        },
    );
}

/// Recognized HTTP/2 indicators on `Service.spec.ports[*].appProtocol`.
///
/// `kubernetes.io/h2c` is the Kubernetes-registered value;
/// `h2c` and `grpc` are de-facto conventions used by NGINX, Envoy,
/// and agent gateway. Any other value — including the websocket
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

fn backend_key_string(svc_ns: &str, svc_name: &str, port: i32) -> String {
    format!("{svc_ns}/{svc_name}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_api::apis::standard::gatewayclasses::GatewayClassSpec;
    use gateway_api::apis::standard::gateways::{
        GatewayListenersAllowedRoutes, GatewayListenersAllowedRoutesNamespaces,
        GatewayListenersTls, GatewayListenersTlsCertificateRefs, GatewaySpec,
    };
    use gateway_api::apis::standard::httproutes::{
        HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs,
        HttpRouteRulesFiltersRequestHeaderModifier, HttpRouteRulesFiltersRequestHeaderModifierAdd,
        HttpRouteRulesFiltersRequestHeaderModifierSet, HttpRouteRulesMatchesPath, HttpRouteSpec,
    };
    use std::collections::BTreeMap;

    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::ServiceSpec;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        assert!(s.backends.is_empty());
        // Route still emitted; the BackendRef carries the unresolved name.
        assert_eq!(s.routes.len(), 1);
    }

    #[test]
    fn request_header_modifier_translated() {
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
                    vec![header_modifier_filter()],
                )],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            secrets: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().unwrap();
        assert_eq!(route.filters.len(), 1);
    }

    #[test]
    fn response_header_modifier_translated() {
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
                    vec![response_header_modifier_filter()],
                )],
            )],
            services: vec![service("demo", "svc", Some("10.0.0.1"))],
            secrets: vec![],
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().unwrap();
        assert_eq!(route.filters.len(), 1);
        let f = &route.filters[0];
        match f.kind.as_ref().expect("filter kind set") {
            pb::http_filter::Kind::ResponseHeaderModifier(rhm) => {
                let ops = rhm.response_headers.as_ref().expect("response_headers set");
                assert_eq!(ops.add.len(), 1);
                assert_eq!(ops.add[0].name, "x-csp");
                assert_eq!(ops.set.len(), 1);
                assert_eq!(ops.set[0].name, "x-frame-options");
                assert_eq!(ops.remove, vec!["x-server-version".to_string()]);
            }
            other @ pb::http_filter::Kind::RequestHeaderModifier(_) => {
                panic!("expected ResponseHeaderModifier, got {other:?}")
            }
        }
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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
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
            secrets: vec![],
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
    fn cross_namespace_certref_skipped() {
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
            secrets: vec![tls_secret("other", "foo", "CERTPEM", "KEYPEM")],
            ..Default::default()
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).expect("snapshot");
        assert!(
            s.secrets.is_empty(),
            "cross-namespace ref needs a ReferenceGrant"
        );
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
            secrets: vec![],
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
}
