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
};
use gateway_cp_proto::v1 as pb;
use gateway_state::{BackendKey, BindKey, ListenerKey, RouteKey};
use k8s_openapi::api::core::v1::Service;

use crate::snapshot::{GatewayId, Snapshot};

#[derive(Debug, Default)]
pub struct K8sState {
    pub gateway_classes: Vec<GatewayClass>,
    pub gateways: Vec<Gateway>,
    pub http_routes: Vec<HTTPRoute>,
    pub services: Vec<Service>,
}

/// Build per-Gateway snapshots from a static K8s state.
///
/// Two passes:
/// 1. Walk Gateways whose class is one we control; emit
///    `BindUpsert` + `ListenerUpsert` per HTTP listener.
/// 2. Walk `HTTPRoute`s; for each `parentRef` pointing at a controlled
///    Gateway, emit one `HttpRouteUpsert` per (matched listener × rule)
///    plus a `BackendUpsert` for every referenced Service.
///
/// Skips (with a warn log, no error): non-HTTP listeners, foreign
/// `GatewayClass`es, unknown filter types, path matches other than
/// `PathPrefix`, cross-namespace backendRefs, headless / missing
/// Services.
pub fn translate(state: &K8sState, controller_name: &str) -> HashMap<GatewayId, Snapshot> {
    // Index everything keyed by lookup paths the passes need.
    let owned_classes = collect_owned_classes(state, controller_name);
    let gateways_by_id = index_gateways(state);
    let services_by_id = index_services(state);

    let mut slices: HashMap<GatewayId, Snapshot> = HashMap::new();

    // Pass 1: Bind + Listener per owned Gateway listener.
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
        let snapshot = slices.entry(id).or_default();

        for listener in &gw.spec.listeners {
            emit_listener(snapshot, ns, name, listener);
        }
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
            let snapshot = slices.entry(id).or_default();

            for listener in target_listeners {
                emit_routes_under_listener(
                    snapshot,
                    parent_ns,
                    parent_name,
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

fn emit_listener(snapshot: &mut Snapshot, gw_ns: &str, gw_name: &str, listener: &GatewayListeners) {
    if listener.protocol != "HTTP" {
        tracing::warn!(
            gateway = gw_name,
            listener = %listener.name,
            protocol = %listener.protocol,
            "skipping non-HTTP listener"
        );
        return;
    }
    // v0: one Bind per Gateway listener, no port-sharing across
    // listeners. Bind and Listener share the same derived name —
    // we don't yet group multiple listeners under one Bind.
    let bind_name = bind_name(gw_ns, gw_name, &listener.name);
    let bind_key = BindKey::new(&bind_name);

    snapshot.binds.insert(
        bind_key.clone(),
        pb::BindUpsert {
            name: bind_name.clone(),
            address: "0.0.0.0".into(),
            port: listener.port.unsigned_abs(),
            bind_protocol: pb::BindProtocol::Http as i32,
        },
    );

    let hostname = listener.hostname.clone();
    let lk = ListenerKey::new(bind_key, &bind_name);
    snapshot.listeners.insert(
        lk,
        pb::ListenerUpsert {
            key: Some(pb::ListenerKey {
                bind: bind_name.clone(),
                name: bind_name.clone(),
            }),
            hostname: hostname.clone().unwrap_or_default(),
            has_hostname: hostname.is_some(),
        },
    );
}

fn emit_routes_under_listener(
    snapshot: &mut Snapshot,
    gw_ns: &str,
    gw_name: &str,
    listener: &GatewayListeners,
    hr: &HTTPRoute,
    route_ns: &str,
    route_name: &str,
) {
    if listener.protocol != "HTTP" {
        return;
    }

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

    let bind_name = bind_name(gw_ns, gw_name, &listener.name);
    let listener_key = ListenerKey::new(BindKey::new(&bind_name), &bind_name);

    for (rule_idx, rule) in hr.spec.rules.as_deref().unwrap_or(&[]).iter().enumerate() {
        let route_full_name = format!("{route_ns}/{route_name}/rule{rule_idx}");
        let route_key = RouteKey::new(listener_key.clone(), &route_full_name);

        let base_matches: Vec<pb::HttpMatch> = rule
            .matches
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .filter_map(translate_match)
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
                    bind: bind_name.clone(),
                    listener: bind_name.clone(),
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

/// v0: path only. `Exact` / `RegularExpression` matches and
/// `method` / `headers` / `queryParams` matches are dropped with a
/// warn — the parent route still ships, just with reduced
/// specificity.
fn translate_match(m: &HttpRouteRulesMatches) -> Option<pb::HttpMatch> {
    // Path defaults to `PathPrefix /` if unset, per Gateway API spec.
    let path = m.path.as_ref();
    let path_msg = match path {
        None => pb::PathMatch {
            kind: pb::PathMatchKind::PathPrefix as i32,
            value: "/".into(),
        },
        Some(p) => {
            // p.r#type defaults to PathPrefix per Gateway API.
            let kind = p.r#type.as_ref();
            let value = p.value.clone().unwrap_or_else(|| "/".into());
            match kind {
                Some(t) if format!("{t:?}").contains("PathPrefix") => pb::PathMatch {
                    kind: pb::PathMatchKind::PathPrefix as i32,
                    value,
                },
                None => pb::PathMatch {
                    kind: pb::PathMatchKind::PathPrefix as i32,
                    value,
                },
                Some(other) => {
                    tracing::warn!(?other, "skipping path match: only PathPrefix supported");
                    return None;
                }
            }
        }
    };
    Some(pb::HttpMatch {
        host: String::new(),
        has_host: false,
        path: Some(path_msg),
    })
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
        let add = rhm
            .add
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|h| pb::HeaderPair {
                name: h.name.clone(),
                value: h.value.clone(),
            })
            .collect();
        let set = rhm
            .set
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|h| pb::HeaderPair {
                name: h.name.clone(),
                value: h.value.clone(),
            })
            .collect();
        let remove = rhm.remove.clone().unwrap_or_default();
        return Some(pb::HttpFilter {
            kind: Some(pb::http_filter::Kind::RequestHeaderModifier(
                pb::RequestHeaderModifier {
                    name: String::new(),
                    request_headers: Some(pb::RequestHeaderOps { add, set, remove }),
                },
            )),
        });
    }
    tracing::warn!(?f.r#type, "skipping unsupported HTTPRoute filter");
    None
}

/// Emit one `BackendUpsert` per (svc, port) referenced by a route in
/// this slice. Idempotent — same (svc, port) reached by multiple rules
/// only produces one entry per slice. Missing or headless Services
/// emit nothing; the DP-side Store stashes any dependent route until
/// the backend lands.
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
    snapshot.backends.insert(
        bk,
        pb::BackendUpsert {
            name: key_str,
            endpoints: vec![pb::Endpoint {
                name: format!("{backend_ns}/{}", br.name),
                address: cluster_ip.to_string(),
                port: port.unsigned_abs(),
            }],
            protocol: pb::BackendProtocol::Http1 as i32,
        },
    );
}

// ==================== name helpers ====================

fn bind_name(gw_ns: &str, gw_name: &str, listener_name: &str) -> String {
    format!("{gw_ns}/{gw_name}/{listener_name}")
}

fn backend_key_string(svc_ns: &str, svc_name: &str, port: i32) -> String {
    format!("{svc_ns}/{svc_name}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_api::apis::standard::gatewayclasses::GatewayClassSpec;
    use gateway_api::apis::standard::gateways::{
        GatewayListenersAllowedRoutes, GatewayListenersAllowedRoutesNamespaces, GatewaySpec,
    };
    use gateway_api::apis::standard::httproutes::{
        HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs,
        HttpRouteRulesFiltersRequestHeaderModifier, HttpRouteRulesFiltersRequestHeaderModifierAdd,
        HttpRouteRulesFiltersRequestHeaderModifierSet, HttpRouteRulesMatchesPath, HttpRouteSpec,
    };
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

        let bind = snap
            .binds
            .get(&BindKey::new("demo/api/http"))
            .expect("bind");
        assert_eq!(bind.port, 80);

        let lk = ListenerKey::new(BindKey::new("demo/api/http"), "demo/api/http");
        let listener = snap.listeners.get(&lk).expect("listener");
        assert!(listener.has_hostname);
        assert_eq!(listener.hostname, "app.example.com");
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
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().unwrap();
        assert_eq!(route.filters.len(), 1);
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
        };
        let out = translate(&state, OURS);
        let s = out.get(&("demo".into(), "api".into())).unwrap();
        let route = s.routes.values().next().unwrap();
        assert_eq!(route.matches.len(), 1);
        assert!(route.matches[0].has_host);
        assert_eq!(route.matches[0].host, "*.example.com");
    }
}
