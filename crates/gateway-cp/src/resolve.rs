//! K8s state -> attachment graph with outcomes.
//!
//! [`resolve`] makes every accept/reject decision exactly once —
//! which Gateways are ours, how each listener classifies, which
//! routes attach where, whether backends and certificateRefs
//! resolve — and records an outcome for accepted *and* rejected
//! elements. The translator consumes the resolved graph to emit
//! data-plane snapshots; the status builder consumes the outcomes.
//! Neither re-derives a decision.
//!
//! Two counts are deliberately distinct, because the spec is:
//! *attachment* (`attachedRoutes`) is based solely on parentRef
//! selection (plus `allowedRoutes`, once enforced), while *emission*
//! (what programs the data plane) additionally requires listener
//! acceptance and a non-empty hostname intersection.

use std::collections::HashMap;

use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::{Gateway, GatewayListeners, GatewayListenersTlsMode};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteParentRefs, HttpRouteRulesBackendRefs,
};
use gateway_cp_proto::v1 as pb;
use k8s_openapi::api::core::v1::{Secret, Service};

use crate::infra::desired::object_name;
use crate::infra::{GATEWAY_NAME_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE};
use crate::snapshot::GatewayId;
use crate::translator::K8sState;

/// The resolved world for one pass: every owned Gateway with its
/// classified listeners and addresses, and every (route x parentRef)
/// with its attachment outcome, emission edges, and backend
/// resolutions.
pub struct Resolution<'a> {
    /// `GatewayClass`es whose `controllerName` is ours.
    pub gateway_classes: Vec<&'a GatewayClass>,
    pub gateways: Vec<GatewayResolution<'a>>,
    pub routes: Vec<RouteResolution<'a>>,
}

pub struct GatewayResolution<'a> {
    pub gateway: &'a Gateway,
    pub id: GatewayId,
    /// One entry per spec listener, in spec order.
    pub listeners: Vec<ListenerResolution<'a>>,
    /// From the provisioner-managed Service; empty for self-managed
    /// Gateways or while a `LoadBalancer` is pending.
    pub addresses: Vec<GatewayAddress>,
}

pub struct ListenerResolution<'a> {
    pub listener: &'a GatewayListeners,
    pub outcome: ListenerOutcome,
    /// Routes attached per the spec's attachment rule (parentRef
    /// selection; `allowedRoutes` once enforced). Counted regardless
    /// of listener acceptance, hostname intersection, or backend
    /// validity.
    pub attached_routes: u32,
    /// Accepted certificateRefs, with the Secret if present.
    pub cert_refs: Vec<CertRef<'a>>,
    /// certificateRefs rejected outright: non-core group, non-Secret
    /// kind, or cross-namespace without a `ReferenceGrant`.
    pub rejected_cert_refs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerOutcome {
    Accepted {
        protocol: pb::BindProtocol,
        /// HTTPS listener terminating TLS (carries cert refs).
        terminate_tls: bool,
    },
    /// Protocol is neither HTTP nor HTTPS-Terminate.
    UnsupportedProtocol,
    /// Disagrees with the bind protocol established on its port.
    ProtocolConflict,
    /// Duplicates an accepted listener's hostname on its port.
    HostnameConflict,
}

impl ListenerOutcome {
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }
}

/// An accepted certificateRef. `secret` is `Some` when the material
/// is present in the cluster (the DP stashes the listener until then).
pub struct CertRef<'a> {
    pub namespace: String,
    pub name: String,
    pub secret: Option<&'a Secret>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayAddress {
    pub value: String,
    pub kind: AddressKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    Ip,
    Hostname,
}

/// One (`HTTPRoute` x parentRef) evaluation against an owned
/// Gateway. parentRefs pointing at unknown or foreign Gateways
/// produce an entry with `NoMatchingParent` and no edges.
pub struct RouteResolution<'a> {
    pub route: &'a HTTPRoute,
    pub route_ns: &'a str,
    pub route_name: &'a str,
    pub parent_ref: &'a HttpRouteParentRefs,
    /// The owned parent, when found.
    pub gateway_id: Option<GatewayId>,
    pub outcome: RouteParentOutcome,
    /// Emission edges: accepted listeners this route programs, with
    /// the precomputed hostname intersection.
    pub edges: Vec<RouteEdge<'a>>,
    /// Backend resolution per rule, in rule order, refs in spec order.
    pub rule_backends: Vec<Vec<BackendResolution<'a>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteParentOutcome {
    Accepted,
    /// Gateway missing or foreign, or `sectionName` selects no
    /// (accepted) listener.
    NoMatchingParent,
    /// Parent matched, but every hostname intersection is empty.
    NoMatchingListenerHostname,
}

pub struct RouteEdge<'a> {
    pub listener: &'a GatewayListeners,
    pub port: i32,
    /// Non-empty: the route fans out across these hostnames.
    /// Empty: no host constraint (catch-all).
    pub effective_hostnames: Vec<String>,
}

pub struct BackendResolution<'a> {
    pub backend_ref: &'a HttpRouteRulesBackendRefs,
    pub outcome: BackendOutcome<'a>,
}

pub enum BackendOutcome<'a> {
    /// Service present with a usable `ClusterIP`; an upsert is emitted.
    Resolved { key: String, service: &'a Service },
    /// Referenced Service does not exist; the ref is still emitted on
    /// the route and the DP stashes it until the backend lands.
    MissingService { key: String },
    /// Service exists but is headless / has no assigned `ClusterIP`
    /// (or no spec). Same wire behavior as missing.
    Headless { key: String },
    /// Cross-namespace without a `ReferenceGrant`: dropped entirely.
    CrossNamespace,
    /// backendRef without a port: dropped entirely.
    NoPort,
}

/// Names of the `GatewayClass`es whose `controllerName` is ours.
/// Shared with the infra provisioner so "owned Gateway" means the
/// same thing on both paths.
pub(crate) fn collect_owned_classes<'a>(
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

/// Resolve `state` into the attachment graph for `controller_name`.
pub fn resolve<'a>(state: &'a K8sState, controller_name: &str) -> Resolution<'a> {
    let gateway_classes: Vec<&GatewayClass> = state
        .gateway_classes
        .iter()
        .filter(|gc| gc.spec.controller_name == controller_name)
        .collect();
    let owned_classes = collect_owned_classes(state, controller_name);

    let services_by_id = index_by_id(&state.services, |s| &s.metadata);
    let secrets_by_id = index_by_id(&state.secrets, |s| &s.metadata);

    let mut gateways: Vec<GatewayResolution<'a>> = Vec::new();
    for gw in &state.gateways {
        let (Some(ns), Some(name)) = (
            gw.metadata.namespace.as_deref(),
            gw.metadata.name.as_deref(),
        ) else {
            continue;
        };
        if !owned_classes.contains(gw.spec.gateway_class_name.as_str()) {
            continue;
        }
        gateways.push(GatewayResolution {
            gateway: gw,
            id: (ns.to_string(), name.to_string()),
            listeners: resolve_listeners(ns, name, &gw.spec.listeners, &secrets_by_id),
            addresses: managed_service_addresses(gw, ns, name, &services_by_id),
        });
    }

    // Owned keys: route resolution below takes `&mut` gateway
    // entries to bump attachment counts.
    let by_id: HashMap<GatewayId, usize> = gateways
        .iter()
        .enumerate()
        .map(|(idx, g)| (g.id.clone(), idx))
        .collect();
    let mut routes: Vec<RouteResolution<'a>> = Vec::new();
    for hr in &state.http_routes {
        let (Some(route_ns), Some(route_name)) = (
            hr.metadata.namespace.as_deref(),
            hr.metadata.name.as_deref(),
        ) else {
            continue;
        };
        for parent_ref in hr.spec.parent_refs.as_deref().unwrap_or(&[]) {
            let parent_ns = parent_ref.namespace.as_deref().unwrap_or(route_ns);
            let gw_idx = by_id
                .get(&(parent_ns.to_string(), parent_ref.name.clone()))
                .copied();
            routes.push(resolve_route_parent(
                hr,
                route_ns,
                route_name,
                parent_ref,
                gw_idx.map(|i| &mut gateways[i]),
                &services_by_id,
            ));
        }
    }

    Resolution {
        gateway_classes,
        gateways,
        routes,
    }
}

/// Classify a Gateway's listeners in spec order: group by port,
/// first-listener-wins protocol per port, hostname distinctness per
/// port. Mirrors the Gateway API listener-distinctness rule.
fn resolve_listeners<'a>(
    gw_ns: &str,
    gw_name: &str,
    listeners: &'a [GatewayListeners],
    secrets_by_id: &HashMap<(&str, &str), &'a Secret>,
) -> Vec<ListenerResolution<'a>> {
    // Per port: protocol established by the first accepted listener,
    // and the hostnames already taken (None == catch-all).
    type PortGroup = (pb::BindProtocol, std::collections::HashSet<Option<String>>);
    let mut ports: HashMap<i32, PortGroup> = HashMap::new();
    let mut out = Vec::with_capacity(listeners.len());

    for listener in listeners {
        // certificateRefs are resolved for every listener regardless
        // of acceptance: the secrets emission pass and (later) the
        // status builder both want them.
        let (cert_refs, rejected_cert_refs) = resolve_cert_refs(gw_ns, listener, secrets_by_id);

        let classified = match listener.protocol.as_str() {
            "HTTP" => Some((pb::BindProtocol::Http, false)),
            "HTTPS" => match listener.tls.as_ref().and_then(|t| t.mode.as_ref()) {
                // Gateway API defaults an unset mode to Terminate.
                None | Some(GatewayListenersTlsMode::Terminate) => {
                    Some((pb::BindProtocol::Tls, true))
                }
                Some(GatewayListenersTlsMode::Passthrough) => {
                    tracing::warn!(
                        gateway = gw_name,
                        listener = %listener.name,
                        "skipping TLS passthrough listener (not yet supported)"
                    );
                    None
                }
            },
            other => {
                tracing::warn!(
                    gateway = gw_name,
                    listener = %listener.name,
                    protocol = %other,
                    "skipping unsupported listener protocol"
                );
                None
            }
        };

        let outcome = match classified {
            None => ListenerOutcome::UnsupportedProtocol,
            Some((protocol, terminate_tls)) => {
                let (bind_protocol, hostnames) = ports
                    .entry(listener.port)
                    .or_insert_with(|| (protocol, std::collections::HashSet::new()));
                if *bind_protocol != protocol {
                    tracing::warn!(
                        gateway = gw_name,
                        listener = %listener.name,
                        port = listener.port,
                        "skipping listener: protocol conflicts with the port's bind"
                    );
                    ListenerOutcome::ProtocolConflict
                } else if !hostnames.insert(listener.hostname.clone()) {
                    tracing::warn!(
                        gateway = gw_name,
                        listener = %listener.name,
                        port = listener.port,
                        hostname = listener.hostname.as_deref().unwrap_or("<none>"),
                        "skipping listener: hostname conflicts on a shared port"
                    );
                    ListenerOutcome::HostnameConflict
                } else {
                    ListenerOutcome::Accepted {
                        protocol,
                        terminate_tls,
                    }
                }
            }
        };

        out.push(ListenerResolution {
            listener,
            outcome,
            attached_routes: 0,
            cert_refs,
            rejected_cert_refs,
        });
    }
    out
}

/// Resolve a listener's `certificateRefs`: core-group `Secret` refs
/// in the Gateway's namespace are accepted (with the Secret attached
/// when present); anything else is rejected with a warn.
fn resolve_cert_refs<'a>(
    gateway_ns: &str,
    listener: &GatewayListeners,
    secrets_by_id: &HashMap<(&str, &str), &'a Secret>,
) -> (Vec<CertRef<'a>>, u32) {
    let Some(refs) = listener
        .tls
        .as_ref()
        .and_then(|t| t.certificate_refs.as_ref())
    else {
        return (Vec::new(), 0);
    };
    let mut accepted = Vec::new();
    let mut rejected = 0;
    for r in refs {
        if r.group.as_deref().is_some_and(|g| !g.is_empty()) {
            tracing::warn!(name = %r.name, group = ?r.group, "skipping non-core certificateRef");
            rejected += 1;
            continue;
        }
        if r.kind.as_deref().is_some_and(|k| k != "Secret") {
            tracing::warn!(name = %r.name, kind = ?r.kind, "skipping non-Secret certificateRef");
            rejected += 1;
            continue;
        }
        if r.namespace
            .as_deref()
            .is_some_and(|n| !n.is_empty() && n != gateway_ns)
        {
            tracing::warn!(name = %r.name, namespace = ?r.namespace,
                "skipping cross-namespace certificateRef");
            rejected += 1;
            continue;
        }
        accepted.push(CertRef {
            namespace: gateway_ns.to_string(),
            name: r.name.clone(),
            secret: secrets_by_id.get(&(gateway_ns, r.name.as_str())).copied(),
        });
    }
    (accepted, rejected)
}

/// Evaluate one (route x parentRef). Bumps attachment counts on the
/// parent's selected listeners; computes emission edges over the
/// accepted ones.
fn resolve_route_parent<'a>(
    hr: &'a HTTPRoute,
    route_ns: &'a str,
    route_name: &'a str,
    parent_ref: &'a HttpRouteParentRefs,
    gateway: Option<&mut GatewayResolution<'a>>,
    services_by_id: &HashMap<(&str, &str), &'a Service>,
) -> RouteResolution<'a> {
    let rule_backends = resolve_rule_backends(hr, route_ns, services_by_id);

    let Some(gateway) = gateway else {
        return RouteResolution {
            route: hr,
            route_ns,
            route_name,
            parent_ref,
            gateway_id: None,
            outcome: RouteParentOutcome::NoMatchingParent,
            edges: Vec::new(),
            rule_backends,
        };
    };

    // sectionName narrows the parentRef to one listener; unset
    // attaches to all.
    let section = parent_ref.section_name.as_deref();
    let route_hostnames = hr.spec.hostnames.as_deref().unwrap_or(&[]);

    let mut selected_any = false;
    let mut accepted_any = false;
    let mut edges = Vec::new();
    for lr in &mut gateway.listeners {
        if section.is_some_and(|s| s != lr.listener.name.as_str()) {
            continue;
        }
        selected_any = true;
        // Attachment counts on selection alone (spec: AllowedRoutes +
        // parentRefs) — acceptance and hostname do not subtract.
        lr.attached_routes += 1;
        if !lr.outcome.is_accepted() {
            continue;
        }
        accepted_any = true;
        if let Some(effective) =
            effective_hostnames(lr.listener.hostname.as_deref(), route_hostnames)
        {
            edges.push(RouteEdge {
                listener: lr.listener,
                port: lr.listener.port,
                effective_hostnames: effective,
            });
        } else {
            tracing::debug!(
                route = route_name,
                listener = %lr.listener.name,
                "route hostnames don't intersect listener hostname; skipping"
            );
        }
    }

    let outcome = if !selected_any || !accepted_any {
        RouteParentOutcome::NoMatchingParent
    } else if edges.is_empty() {
        RouteParentOutcome::NoMatchingListenerHostname
    } else {
        RouteParentOutcome::Accepted
    };

    RouteResolution {
        route: hr,
        route_ns,
        route_name,
        parent_ref,
        gateway_id: Some(gateway.id.clone()),
        outcome,
        edges,
        rule_backends,
    }
}

fn resolve_rule_backends<'a>(
    hr: &'a HTTPRoute,
    route_ns: &str,
    services_by_id: &HashMap<(&str, &str), &'a Service>,
) -> Vec<Vec<BackendResolution<'a>>> {
    hr.spec
        .rules
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|rule| {
            rule.backend_refs
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(|br| BackendResolution {
                    backend_ref: br,
                    outcome: resolve_backend(br, route_ns, services_by_id),
                })
                .collect()
        })
        .collect()
}

fn resolve_backend<'a>(
    br: &HttpRouteRulesBackendRefs,
    route_ns: &str,
    services_by_id: &HashMap<(&str, &str), &'a Service>,
) -> BackendOutcome<'a> {
    let Some(port) = br.port else {
        return BackendOutcome::NoPort;
    };
    let backend_ns = br.namespace.as_deref().unwrap_or(route_ns);
    if backend_ns != route_ns {
        tracing::warn!(
            ns = backend_ns,
            "skipping cross-namespace backendRef (ReferenceGrant not supported in v0)"
        );
        return BackendOutcome::CrossNamespace;
    }
    let key = backend_key_string(backend_ns, &br.name, port);
    let Some(service) = services_by_id.get(&(backend_ns, br.name.as_str())) else {
        return BackendOutcome::MissingService { key };
    };
    let usable_ip = service
        .spec
        .as_ref()
        .and_then(|s| s.cluster_ip.as_deref())
        .is_some_and(|ip| !ip.is_empty() && ip != "None");
    if usable_ip {
        BackendOutcome::Resolved { key, service }
    } else {
        BackendOutcome::Headless { key }
    }
}

/// The address(es) a Gateway is reachable at, read from the
/// provisioner-managed Service: `LoadBalancer` ingress when present,
/// else the `ClusterIP`. The Service is verified by the managed-by
/// label and a controller ownerReference with the Gateway's uid —
/// never by name alone.
fn managed_service_addresses(
    gw: &Gateway,
    gw_ns: &str,
    gw_name: &str,
    services_by_id: &HashMap<(&str, &str), &Service>,
) -> Vec<GatewayAddress> {
    let managed_name = object_name(gw_name);
    let Some(svc) = services_by_id.get(&(gw_ns, managed_name.as_str())) else {
        return Vec::new();
    };
    let labeled = svc.metadata.labels.as_ref().is_some_and(|l| {
        l.get(MANAGED_BY_LABEL).map(String::as_str) == Some(MANAGED_BY_VALUE)
            && l.get(GATEWAY_NAME_LABEL).map(String::as_str) == Some(gw_name)
    });
    let owned = svc.metadata.owner_references.as_deref().is_some_and(|o| {
        o.iter().any(|r| {
            r.controller == Some(true) && Some(r.uid.as_str()) == gw.metadata.uid.as_deref()
        })
    });
    if !labeled || !owned {
        return Vec::new();
    }

    let mut out = Vec::new();
    let ingress = svc
        .status
        .as_ref()
        .and_then(|s| s.load_balancer.as_ref())
        .and_then(|lb| lb.ingress.as_deref())
        .unwrap_or(&[]);
    for i in ingress {
        if let Some(ip) = i.ip.as_deref().filter(|v| !v.is_empty()) {
            out.push(GatewayAddress {
                value: ip.to_string(),
                kind: AddressKind::Ip,
            });
        } else if let Some(host) = i.hostname.as_deref().filter(|v| !v.is_empty()) {
            out.push(GatewayAddress {
                value: host.to_string(),
                kind: AddressKind::Hostname,
            });
        }
    }
    if !out.is_empty() {
        return out;
    }

    // No LB ingress (ClusterIP/NodePort Service, or LB pending):
    // report the cluster IPs.
    let spec = svc.spec.as_ref();
    let cluster_ips: Vec<&str> = spec
        .and_then(|s| s.cluster_ips.as_deref())
        .map(|ips| ips.iter().map(String::as_str).collect())
        .or_else(|| {
            spec.and_then(|s| s.cluster_ip.as_deref())
                .map(|ip| vec![ip])
        })
        .unwrap_or_default();
    cluster_ips
        .into_iter()
        .filter(|ip| !ip.is_empty() && *ip != "None")
        .map(|ip| GatewayAddress {
            value: ip.to_string(),
            kind: AddressKind::Ip,
        })
        .collect()
}

/// Intersect a listener's hostname with an `HTTPRoute`'s hostnames
/// per the Gateway API. Returns:
/// * `Some(vec![])` — no host constraint (both sides empty).
/// * `Some(non-empty)` — the effective hostnames to fan out across.
/// * `None` — the listener has a hostname and none of the route's
///   hostnames overlap; the attachment carries no edge.
pub(crate) fn effective_hostnames(listener: Option<&str>, route: &[String]) -> Option<Vec<String>> {
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
pub(crate) fn hostnames_overlap(a: &str, b: &str) -> bool {
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
/// covers `app.example.com` and deeper labels but not `example.com`
/// itself (the wildcard requires at least one label before the
/// suffix). Case-insensitive. `host` may itself be a wildcard.
pub(crate) fn wildcard_covers(pattern_suffix: &str, host: &str) -> bool {
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

pub(crate) fn backend_key_string(svc_ns: &str, svc_name: &str, port: i32) -> String {
    format!("{svc_ns}/{svc_name}:{port}")
}

fn index_by_id<T>(
    items: &[T],
    meta: impl Fn(&T) -> &kube::api::ObjectMeta,
) -> HashMap<(&str, &str), &T> {
    items
        .iter()
        .filter_map(|item| {
            let m = meta(item);
            let ns = m.namespace.as_deref()?;
            let name = m.name.as_deref()?;
            Some(((ns, name), item))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_api::apis::standard::gatewayclasses::GatewayClassSpec;
    use gateway_api::apis::standard::gateways::{
        GatewayListenersTls, GatewayListenersTlsCertificateRefs, GatewaySpec,
    };
    use gateway_api::apis::standard::httproutes::{HttpRouteRules, HttpRouteSpec};
    use k8s_openapi::api::core::v1::{
        LoadBalancerIngress, LoadBalancerStatus, ServiceSpec, ServiceStatus,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};

    const OURS: &str = "gateway.buoyant.io/controller";

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

    fn gw(ns: &str, name: &str, class: &str, listeners: Vec<GatewayListeners>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                uid: Some("uid-1".into()),
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

    fn http_listener(name: &str, port: i32, hostname: Option<&str>) -> GatewayListeners {
        GatewayListeners {
            name: name.into(),
            protocol: "HTTP".into(),
            port,
            hostname: hostname.map(String::from),
            ..Default::default()
        }
    }

    fn https_listener(name: &str, port: i32, certs: &[&str]) -> GatewayListeners {
        GatewayListeners {
            name: name.into(),
            protocol: "HTTPS".into(),
            port,
            tls: Some(GatewayListenersTls {
                certificate_refs: Some(
                    certs
                        .iter()
                        .map(|c| GatewayListenersTlsCertificateRefs {
                            name: (*c).to_string(),
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn parent(name: &str, section: Option<&str>) -> HttpRouteParentRefs {
        HttpRouteParentRefs {
            name: name.into(),
            section_name: section.map(String::from),
            ..Default::default()
        }
    }

    fn backend_ref(name: &str, ns: Option<&str>, port: Option<i32>) -> HttpRouteRulesBackendRefs {
        HttpRouteRulesBackendRefs {
            name: name.into(),
            namespace: ns.map(String::from),
            port,
            ..Default::default()
        }
    }

    fn route(
        ns: &str,
        name: &str,
        parents: Vec<HttpRouteParentRefs>,
        hostnames: Option<Vec<&str>>,
        backend_refs: Vec<HttpRouteRulesBackendRefs>,
    ) -> HTTPRoute {
        HTTPRoute {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(parents),
                hostnames: hostnames.map(|h| h.into_iter().map(String::from).collect()),
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(backend_refs),
                    ..Default::default()
                }]),
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

    fn managed_service(
        gw_ns: &str,
        gw_name: &str,
        ingress: Vec<LoadBalancerIngress>,
        cluster_ips: Vec<&str>,
    ) -> Service {
        Service {
            metadata: ObjectMeta {
                namespace: Some(gw_ns.into()),
                name: Some(object_name(gw_name)),
                labels: Some(
                    [
                        (MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string()),
                        (GATEWAY_NAME_LABEL.to_string(), gw_name.to_string()),
                    ]
                    .into(),
                ),
                owner_references: Some(vec![OwnerReference {
                    controller: Some(true),
                    uid: "uid-1".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ips: Some(cluster_ips.into_iter().map(String::from).collect()),
                ..Default::default()
            }),
            status: Some(ServiceStatus {
                load_balancer: Some(LoadBalancerStatus {
                    ingress: Some(ingress),
                }),
                ..Default::default()
            }),
        }
    }

    fn secret(ns: &str, name: &str) -> Secret {
        Secret {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn state(gateways: Vec<Gateway>, routes: Vec<HTTPRoute>) -> K8sState {
        K8sState {
            gateway_classes: vec![gc("zd", OURS), gc("other", "example.com/other")],
            gateways,
            http_routes: routes,
            ..Default::default()
        }
    }

    // ----- listener classification -----

    #[test]
    fn listener_outcomes_cover_every_rejection() {
        let mut passthrough = https_listener("pass", 443, &[]);
        passthrough.tls.as_mut().unwrap().mode = Some(GatewayListenersTlsMode::Passthrough);
        let listeners = vec![
            http_listener("http", 80, None),
            GatewayListeners {
                name: "tcp".into(),
                protocol: "TCP".into(),
                port: 9000,
                ..Default::default()
            },
            passthrough,
            https_listener("mixed", 80, &["cert"]), // HTTPS on the HTTP port
            http_listener("dup", 80, None),         // duplicate catch-all hostname
        ];
        let s = state(vec![gw("demo", "gw", "zd", listeners)], vec![]);

        let r = resolve(&s, OURS);
        let outcomes: Vec<&ListenerOutcome> =
            r.gateways[0].listeners.iter().map(|l| &l.outcome).collect();
        assert!(outcomes[0].is_accepted());
        assert_eq!(*outcomes[1], ListenerOutcome::UnsupportedProtocol);
        assert_eq!(*outcomes[2], ListenerOutcome::UnsupportedProtocol);
        assert_eq!(*outcomes[3], ListenerOutcome::ProtocolConflict);
        assert_eq!(*outcomes[4], ListenerOutcome::HostnameConflict);
    }

    // ----- attachment vs emission -----

    #[test]
    fn attachment_counts_on_selection_alone() {
        // One accepted listener plus a hostname-conflicted duplicate.
        let listeners = vec![
            http_listener("http", 80, Some("a.example")),
            http_listener("dup", 80, Some("a.example")),
        ];
        let s = state(
            vec![gw("demo", "gw", "zd", listeners)],
            vec![
                // Hostnames don't intersect: attached, never emitted.
                route(
                    "demo",
                    "miss",
                    vec![parent("gw", None)],
                    Some(vec!["b.example"]),
                    vec![],
                ),
                // Hostnames intersect: attached and emitted — but only
                // the accepted listener takes an edge.
                route(
                    "demo",
                    "hit",
                    vec![parent("gw", None)],
                    Some(vec!["a.example"]),
                    vec![],
                ),
            ],
        );
        let r = resolve(&s, OURS);

        // Both routes count on both listeners: neither hostname
        // mismatch nor listener conflict subtracts from attachment.
        let counts: Vec<u32> = r.gateways[0]
            .listeners
            .iter()
            .map(|l| l.attached_routes)
            .collect();
        assert_eq!(counts, vec![2, 2]);

        let by_name: HashMap<&str, &RouteResolution<'_>> =
            r.routes.iter().map(|rr| (rr.route_name, rr)).collect();
        assert_eq!(
            by_name["miss"].outcome,
            RouteParentOutcome::NoMatchingListenerHostname
        );
        assert!(by_name["miss"].edges.is_empty());
        assert_eq!(by_name["hit"].outcome, RouteParentOutcome::Accepted);
        assert_eq!(
            by_name["hit"].edges.len(),
            1,
            "no edge on the conflicted dup"
        );
    }

    #[test]
    fn section_name_narrows_selection_and_counting() {
        let listeners = vec![http_listener("a", 80, None), http_listener("b", 81, None)];
        let s = state(
            vec![gw("demo", "gw", "zd", listeners)],
            vec![
                route("demo", "to-b", vec![parent("gw", Some("b"))], None, vec![]),
                route("demo", "to-all", vec![parent("gw", None)], None, vec![]),
                route(
                    "demo",
                    "to-nope",
                    vec![parent("gw", Some("nope"))],
                    None,
                    vec![],
                ),
            ],
        );
        let r = resolve(&s, OURS);

        let counts: Vec<u32> = r.gateways[0]
            .listeners
            .iter()
            .map(|l| l.attached_routes)
            .collect();
        assert_eq!(counts, vec![1, 2]); // a: to-all; b: to-b + to-all

        let by_name: HashMap<&str, &RouteResolution<'_>> =
            r.routes.iter().map(|rr| (rr.route_name, rr)).collect();
        assert_eq!(by_name["to-b"].outcome, RouteParentOutcome::Accepted);
        assert_eq!(by_name["to-b"].edges.len(), 1);
        assert_eq!(by_name["to-all"].edges.len(), 2);
        assert_eq!(
            by_name["to-nope"].outcome,
            RouteParentOutcome::NoMatchingParent
        );
    }

    #[test]
    fn unknown_and_foreign_parents_resolve_to_no_matching_parent() {
        let s = state(
            vec![gw(
                "demo",
                "foreign",
                "other",
                vec![http_listener("h", 80, None)],
            )],
            vec![
                route(
                    "demo",
                    "to-missing",
                    vec![parent("ghost", None)],
                    None,
                    vec![],
                ),
                route(
                    "demo",
                    "to-foreign",
                    vec![parent("foreign", None)],
                    None,
                    vec![],
                ),
            ],
        );
        let r = resolve(&s, OURS);

        assert!(r.gateways.is_empty());
        for rr in &r.routes {
            assert_eq!(rr.outcome, RouteParentOutcome::NoMatchingParent);
            assert!(rr.gateway_id.is_none());
        }
    }

    // ----- backends -----

    #[test]
    fn backend_outcomes_cover_every_case() {
        let mut s = state(
            vec![gw("demo", "gw", "zd", vec![http_listener("h", 80, None)])],
            vec![route(
                "demo",
                "r",
                vec![parent("gw", None)],
                None,
                vec![
                    backend_ref("ok", None, Some(8080)),
                    backend_ref("gone", None, Some(8080)),
                    backend_ref("headless", None, Some(8080)),
                    backend_ref("other", Some("elsewhere"), Some(8080)),
                    backend_ref("portless", None, None),
                ],
            )],
        );
        s.services = vec![
            service("demo", "ok", Some("10.0.0.1")),
            service("demo", "headless", Some("None")),
        ];
        let r = resolve(&s, OURS);

        let outcomes = &r.routes[0].rule_backends[0];
        assert!(matches!(
            &outcomes[0].outcome,
            BackendOutcome::Resolved { key, .. } if key == "demo/ok:8080"
        ));
        assert!(matches!(
            &outcomes[1].outcome,
            BackendOutcome::MissingService { key } if key == "demo/gone:8080"
        ));
        assert!(matches!(
            &outcomes[2].outcome,
            BackendOutcome::Headless { .. }
        ));
        assert!(matches!(
            &outcomes[3].outcome,
            BackendOutcome::CrossNamespace
        ));
        assert!(matches!(&outcomes[4].outcome, BackendOutcome::NoPort));
    }

    // ----- certificateRefs -----

    #[test]
    fn cert_refs_track_presence_and_rejections() {
        let mut listener = https_listener("https", 443, &["present", "absent"]);
        listener
            .tls
            .as_mut()
            .unwrap()
            .certificate_refs
            .as_mut()
            .unwrap()
            .push(GatewayListenersTlsCertificateRefs {
                name: "cross".into(),
                namespace: Some("elsewhere".into()),
                ..Default::default()
            });
        let mut s = state(vec![gw("demo", "gw", "zd", vec![listener])], vec![]);
        s.secrets = vec![secret("demo", "present")];
        let r = resolve(&s, OURS);

        let lr = &r.gateways[0].listeners[0];
        assert_eq!(lr.cert_refs.len(), 2);
        assert!(lr.cert_refs[0].secret.is_some());
        assert!(lr.cert_refs[1].secret.is_none());
        assert_eq!(lr.rejected_cert_refs, 1);
    }

    // ----- addresses -----

    #[test]
    fn addresses_come_from_the_managed_service_only() {
        // gw-lb: managed Service with LB ingress -> typed entries.
        // gw-cluster: managed Service without ingress -> ClusterIP.
        // gw-squat: same-name Service without our label/owner -> none.
        let mut squatter = service("demo", &object_name("gw-squat"), Some("10.96.0.99"));
        squatter.metadata.labels = None;
        let mut s = state(
            vec![
                gw("demo", "gw-lb", "zd", vec![http_listener("h", 80, None)]),
                gw(
                    "demo",
                    "gw-cluster",
                    "zd",
                    vec![http_listener("h", 80, None)],
                ),
                gw("demo", "gw-squat", "zd", vec![http_listener("h", 80, None)]),
            ],
            vec![],
        );
        s.services = vec![
            managed_service(
                "demo",
                "gw-lb",
                vec![
                    LoadBalancerIngress {
                        ip: Some("203.0.113.7".into()),
                        ..Default::default()
                    },
                    LoadBalancerIngress {
                        hostname: Some("lb.example.com".into()),
                        ..Default::default()
                    },
                ],
                vec!["10.96.0.10"],
            ),
            managed_service("demo", "gw-cluster", vec![], vec!["10.96.0.10"]),
            squatter,
        ];
        let r = resolve(&s, OURS);

        assert_eq!(
            r.gateways[0].addresses,
            vec![
                GatewayAddress {
                    value: "203.0.113.7".into(),
                    kind: AddressKind::Ip
                },
                GatewayAddress {
                    value: "lb.example.com".into(),
                    kind: AddressKind::Hostname
                },
            ]
        );
        assert_eq!(
            r.gateways[1].addresses,
            vec![GatewayAddress {
                value: "10.96.0.10".into(),
                kind: AddressKind::Ip
            }]
        );
        assert!(r.gateways[2].addresses.is_empty());
    }
}
