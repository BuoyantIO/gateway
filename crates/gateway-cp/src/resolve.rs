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
//! A `GatewayBackend` is decided here too, and once per object
//! rather than once per reference: its `baseURL` is split into the
//! host, port and path prefix the data plane dials with (a URL exists
//! nowhere past this module), and every Secret it names is looked up.
//! The two failures are deliberately different. A spec that cannot
//! name a destination is [`GatewayBackendOutcome::Invalid`] and
//! publishes nothing. A spec that is fine but names material that has
//! not arrived stays `Resolved` with that reference unresolved: the
//! backend is published, the request path fails visibly, and the
//! material can land later without the object changing.
//!
//! `attachedRoutes` counting follows the Gateway CRD text precisely: it
//! counts *distinct routes* whose parent attachment is Accepted, on
//! every listener the parentRef selects (plus `allowedRoutes`, once
//! enforced) — even a listener that is itself conflicted. Routes not
//! Accepted (no matching parent, no hostname intersection anywhere)
//! MUST NOT be counted; unresolved backends don't subtract (that's
//! `ResolvedRefs`, not `Accepted`).

use std::collections::HashMap;

use gateway_api::apis::standard::gatewayclasses::GatewayClass;
use gateway_api::apis::standard::gateways::{Gateway, GatewayListeners, GatewayListenersTlsMode};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteParentRefs, HttpRouteRulesBackendRefs,
};
use gateway_config::secret::SecretValue;
use gateway_cp_proto::v1 as pb;
use k8s_openapi::api::core::v1::{Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;

use crate::crd::{self, GatewayBackend};
use crate::infra;
use crate::infra::desired::object_name;
use crate::infra::{GATEWAY_NAME_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE};
use crate::snapshot::GatewayId;
use crate::translator::K8sState;

/// The well-known `EndpointSlice` label naming the owning Service.
pub(crate) const SERVICE_NAME_LABEL: &str = "kubernetes.io/service-name";
/// API group of the gateway's own custom resources.
pub(crate) const GATEWAY_GROUP: &str = "gateway.linkerd.io";

/// The resolved world for one pass: every owned Gateway with its
/// classified listeners and addresses, every `GatewayBackend` with
/// its URL parsed and its secrets looked up, and every
/// (route x parentRef) with its attachment outcome, emission edges,
/// and backend resolutions.
pub struct Resolution<'a> {
    /// `GatewayClass`es whose `controllerName` is ours.
    pub gateway_classes: Vec<&'a GatewayClass>,
    pub gateways: Vec<GatewayResolution<'a>>,
    /// Every `GatewayBackend` in the cluster, resolved once whether
    /// or not a route names it. Route refs point in here by index,
    /// and the status builder reads it directly, so an object ten
    /// routes reference is still decided once.
    pub gateway_backends: Vec<GatewayBackendResolution<'a>>,
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
    /// Distinct routes with an Accepted parent attachment whose
    /// parentRef selects this listener (see the module doc). Counted
    /// regardless of this listener's own validity.
    pub attached_routes: u32,
    /// Accepted certificateRefs, with the Secret if present.
    pub cert_refs: Vec<CertRef<'a>>,
    /// certificateRefs rejected outright: non-core group or
    /// non-Secret kind. Cross-namespace refs are currently accepted
    /// without a `ReferenceGrant` check.
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

/// An accepted reference to TLS material: a listener's
/// certificateRef, or the trust roots of a `GatewayBackend`.
///
/// `secret` is `Some` only when the named Secret is present *and*
/// carries a non-empty `tls.crt`. A Secret whose material is
/// unusable is deliberately indistinguishable here from one that has
/// not arrived: both leave the reference unresolved, both are
/// reported the same way, and neither is published to a data plane
/// that would only reject it.
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
    /// The route's `extensionRef` filters, resolved. Refs are
    /// route-local; deduped by identity across rules.
    pub extensions: Vec<ExtRef<'a>>,
}

/// One `extensionRef` of a route, resolved against the watched
/// `Extension` objects. `object` is `None` while the named object
/// does not exist — the ref is still emitted and the DP answers 500
/// until it arrives.
pub struct ExtRef<'a> {
    pub namespace: String,
    pub name: String,
    pub object: Option<&'a crate::crd::Extension>,
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
    /// Service present with a usable `ClusterIP`; an upsert is
    /// emitted carrying the per-pod endpoints derived from the
    /// Service's `EndpointSlice`s. `endpoints` may be empty (no
    /// ready pods): the upsert still goes out and the DP answers
    /// 503 until pods become ready.
    Resolved {
        key: String,
        service: &'a Service,
        endpoints: Vec<ResolvedEndpoint>,
    },
    /// Referenced Service does not exist; the ref is still emitted on
    /// the route and the DP stashes it until the backend lands.
    MissingService { key: String },
    /// Service exists but is headless / has no assigned `ClusterIP`
    /// (or no spec). Same wire behavior as missing. Headless
    /// Services could resolve through their `EndpointSlice`s too;
    /// that is deliberately not done yet.
    Headless { key: String },
    /// A `GatewayBackend` this route names, resolved once at
    /// `Resolution::gateway_backends[index]`. The ref is emitted
    /// whatever that resolution says; the upsert behind it is only
    /// emitted when the object is usable, so a route pointing at a
    /// broken backend gets a 500 rather than silence.
    Dialable { key: String, index: usize },
    /// Named `GatewayBackend` does not exist. Same wire behavior as
    /// a missing Service: the ref rides along unresolved.
    MissingDialable { key: String },
    /// Cross-namespace without a `ReferenceGrant`: dropped entirely.
    CrossNamespace,
    /// A Service backendRef without a port: dropped entirely.
    NoPort,
    /// A `GatewayBackend` backendRef *with* a port: dropped
    /// entirely. The port belongs to `baseURL`, and a ref naming a
    /// second one has no sensible reading.
    PortNotAllowed,
    /// A group/kind pair that is neither a core `Service` nor our
    /// `GatewayBackend`: dropped entirely.
    UnsupportedKind,
}

/// One usable pod address for a backend, derived from the Service's
/// `EndpointSlice`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEndpoint {
    /// Stable per pod: the targetRef name when it is a Pod, else the
    /// address. Becomes `pb::Endpoint.name` and therefore the DP's
    /// per-endpoint state key, so health and latency history track a
    /// pod across `EndpointSlice` updates.
    pub name: String,
    pub address: String,
    pub port: u16,
}

/// One `GatewayBackend`, decided once per pass.
pub struct GatewayBackendResolution<'a> {
    pub object: &'a GatewayBackend,
    pub namespace: String,
    pub name: String,
    /// The key this backend travels under on the wire, and therefore
    /// the data plane's per-backend state key: `namespace/name`. It
    /// cannot collide with a Service-derived key, which always
    /// carries `:port`, and it is stable across every edit to the
    /// spec — the connection pool and the endpoint's latency and
    /// eviction history hang off it.
    pub key: String,
    pub outcome: GatewayBackendOutcome<'a>,
}

pub enum GatewayBackendOutcome<'a> {
    /// Usable: the URL is split into what the data plane dials with,
    /// and every Secret the spec names has been looked up. A named
    /// Secret that is absent leaves its reference unresolved rather
    /// than failing the object; the backend is still published, and
    /// requests through it fail until the material lands.
    Resolved(Box<ResolvedDialable<'a>>),
    /// The spec cannot be turned into a destination at all, so
    /// nothing is published for it and traffic aimed at it gets a
    /// 500. `reason` is the status condition reason.
    Invalid {
        reason: &'static str,
        message: String,
    },
}

/// A `GatewayBackend` spec resolved into what the data plane needs:
/// the URL in parts (the DP never sees a URL), and each referenced
/// Secret paired with what the lookup found.
pub struct ResolvedDialable<'a> {
    pub host: String,
    pub port: u16,
    /// The `baseURL` path, when it is one worth sending: `/` and an
    /// empty path both forward the request path untouched.
    pub path_prefix: Option<String>,
    /// `Some` originates TLS, which the `https` scheme decides.
    pub tls: Option<ResolvedBackendTls<'a>>,
    pub auth: Option<ResolvedBackendAuth>,
}

pub struct ResolvedBackendTls<'a> {
    /// `None` is the platform trust store.
    pub ca: Option<CertRef<'a>>,
    pub sni: Option<String>,
    pub alpn: Vec<pb::AlpnProtocol>,
    pub insecure_skip_verify: bool,
}

/// The credential a backend authenticates with, with the material
/// already looked up.
///
/// Deliberately not `Debug`: the variants carry a resolved
/// credential, and the only thing that may print one is nothing.
pub enum ResolvedBackendAuth {
    ApiKey {
        credential: CredentialRef,
        header: String,
        prefix: String,
    },
    OAuth2 {
        credential: CredentialRef,
        token_url: String,
        client_id: String,
        scopes: Vec<String>,
        client_auth_method: pb::ClientAuthMethod,
    },
}

impl ResolvedBackendAuth {
    /// The one secret this auth block spends. Every scheme names
    /// exactly one, which is what lets status and emission treat
    /// them alike.
    pub fn credential(&self) -> &CredentialRef {
        match self {
            Self::ApiKey { credential, .. } | Self::OAuth2 { credential, .. } => credential,
        }
    }
}

/// A reference to one data key inside one Secret, resolved.
pub struct CredentialRef {
    pub namespace: String,
    pub name: String,
    pub key: String,
    pub outcome: CredentialOutcome,
}

impl CredentialRef {
    /// `namespace/name#key`, matching how a reference to it prints
    /// everywhere else.
    pub fn id(&self) -> String {
        format!("{}/{}#{}", self.namespace, self.name, self.key)
    }
}

pub enum CredentialOutcome {
    /// The material under the named data key. Owned, and in the
    /// carrier that redacts under `Debug` and `Display`, so holding
    /// it here cannot leak it.
    Present(SecretValue),
    /// No such Secret in this namespace.
    SecretMissing,
    /// The Secret is there and carries no such data key.
    KeyMissing,
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
    let extensions_by_id = index_by_id(&state.extensions, |e| &e.metadata);
    let slices_by_service = index_slices(&state.endpoint_slices);

    // Resolved before routes so a ref can point at the one
    // resolution by index instead of re-deciding per ref.
    let gateway_backends = resolve_gateway_backends(&state.gateway_backends, &secrets_by_id);
    let dialables_by_id: HashMap<(&str, &str), usize> = gateway_backends
        .iter()
        .enumerate()
        .map(|(idx, b)| ((b.namespace.as_str(), b.name.as_str()), idx))
        .collect();

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
        // (gateway idx, listener idx) pairs this route was already
        // counted on: several parentRefs of one route may select the
        // same listener, but `attachedRoutes` counts distinct routes.
        let mut counted: std::collections::HashSet<(usize, usize)> =
            std::collections::HashSet::new();
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
                gw_idx.map(|i| (i, &mut gateways[i])),
                &mut counted,
                &services_by_id,
                &slices_by_service,
                &dialables_by_id,
                &extensions_by_id,
            ));
        }
    }

    Resolution {
        gateway_classes,
        gateways,
        gateway_backends,
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
/// are accepted (with the Secret attached when present); non-core
/// and non-Secret refs are rejected with a warn.
///
/// Cross-namespace refs resolve in the referenced namespace and are
/// accepted unconditionally for now — permissive until
/// `ReferenceGrant` enforcement lands, at which point a grant in
/// the Secret's namespace becomes required (the same
/// permissive-now posture route attachment has with
/// `allowedRoutes`).
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
        let ref_ns = match r.namespace.as_deref() {
            Some(n) if !n.is_empty() => n,
            _ => gateway_ns,
        };
        if ref_ns != gateway_ns {
            tracing::info!(name = %r.name, namespace = %ref_ns,
                "accepting cross-namespace certificateRef without a ReferenceGrant check");
        }
        accepted.push(cert_ref(ref_ns, &r.name, secrets_by_id));
    }
    (accepted, rejected)
}

/// Resolve one reference to TLS material in `namespace`.
///
/// A Secret carrying no usable certificate chain leaves the
/// reference unresolved rather than resolved-to-something-broken.
/// That keeps two things true at once: the status of the object that
/// named it says so, and nothing the data plane would refuse is ever
/// published — a rejected upsert costs the rest of its batch.
fn cert_ref<'a>(
    namespace: &str,
    name: &str,
    secrets_by_id: &HashMap<(&str, &str), &'a Secret>,
) -> CertRef<'a> {
    CertRef {
        namespace: namespace.to_string(),
        name: name.to_string(),
        secret: secrets_by_id
            .get(&(namespace, name))
            .copied()
            .filter(|s| has_certificate(s)),
    }
}

/// Whether a Secret carries a non-empty `tls.crt`. A
/// `kubernetes.io/tls` Secret always has the data key, so this asks
/// about the material, not the shape.
fn has_certificate(secret: &Secret) -> bool {
    secret
        .data
        .as_ref()
        .and_then(|d| d.get(gateway_config::secret::TLS_CERT_KEY))
        .is_some_and(|v| !v.0.is_empty())
}

/// Evaluate one (route x parentRef): compute emission edges over the
/// accepted listeners, then — when the attachment is Accepted —
/// count the route once per selected listener (`counted` carries the
/// per-route memory across this route's parentRefs).
#[allow(clippy::too_many_arguments)]
fn resolve_route_parent<'a>(
    hr: &'a HTTPRoute,
    route_ns: &'a str,
    route_name: &'a str,
    parent_ref: &'a HttpRouteParentRefs,
    gateway: Option<(usize, &mut GatewayResolution<'a>)>,
    counted: &mut std::collections::HashSet<(usize, usize)>,
    services_by_id: &HashMap<(&str, &str), &'a Service>,
    slices_by_service: &HashMap<(&str, &str), Vec<&'a EndpointSlice>>,
    dialables_by_id: &HashMap<(&str, &str), usize>,
    extensions_by_id: &HashMap<(&str, &str), &'a crate::crd::Extension>,
) -> RouteResolution<'a> {
    let rule_backends = resolve_rule_backends(
        hr,
        route_ns,
        services_by_id,
        slices_by_service,
        dialables_by_id,
    );
    let extensions = resolve_route_extensions(hr, route_ns, extensions_by_id);

    let Some((gw_idx, gateway)) = gateway else {
        return RouteResolution {
            route: hr,
            route_ns,
            route_name,
            parent_ref,
            gateway_id: None,
            outcome: RouteParentOutcome::NoMatchingParent,
            edges: Vec::new(),
            rule_backends,
            extensions,
        };
    };

    // sectionName narrows the parentRef to one listener; unset
    // attaches to all.
    let section = parent_ref.section_name.as_deref();
    let route_hostnames = hr.spec.hostnames.as_deref().unwrap_or(&[]);

    let mut selected: Vec<usize> = Vec::new();
    let mut accepted_any = false;
    let mut edges = Vec::new();
    for (idx, lr) in gateway.listeners.iter().enumerate() {
        if section.is_some_and(|s| s != lr.listener.name.as_str()) {
            continue;
        }
        selected.push(idx);
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

    let outcome = if selected.is_empty() || !accepted_any {
        RouteParentOutcome::NoMatchingParent
    } else if edges.is_empty() {
        RouteParentOutcome::NoMatchingListenerHostname
    } else {
        RouteParentOutcome::Accepted
    };

    // Only Accepted routes count (CRD: "Routes with any other value
    // for the Accepted condition MUST NOT be included"), once per
    // distinct route, on every listener the parentRef selects —
    // including listeners that are themselves conflicted.
    if outcome == RouteParentOutcome::Accepted {
        for idx in selected {
            if counted.insert((gw_idx, idx)) {
                gateway.listeners[idx].attached_routes += 1;
            }
        }
    }

    RouteResolution {
        route: hr,
        route_ns,
        route_name,
        parent_ref,
        gateway_id: Some(gateway.id.clone()),
        outcome,
        edges,
        rule_backends,
        extensions,
    }
}

/// Collect the route's `extensionRef` filters that name our
/// `Extension` kind, deduped by identity, resolved against the
/// watched objects. Refs are route-local: the namespace is the
/// route's own.
fn resolve_route_extensions<'a>(
    hr: &'a HTTPRoute,
    route_ns: &str,
    extensions_by_id: &HashMap<(&str, &str), &'a crate::crd::Extension>,
) -> Vec<ExtRef<'a>> {
    let mut seen = std::collections::HashSet::new();
    let mut refs = Vec::new();
    for rule in hr.spec.rules.as_deref().unwrap_or(&[]) {
        for f in rule.filters.as_deref().unwrap_or(&[]) {
            let Some(er) = f.extension_ref.as_ref() else {
                continue;
            };
            if er.group != GATEWAY_GROUP || er.kind != "Extension" {
                continue; // foreign refs drop at translation, with a warn
            }
            if !seen.insert(er.name.clone()) {
                continue;
            }
            refs.push(ExtRef {
                namespace: route_ns.to_string(),
                name: er.name.clone(),
                object: extensions_by_id.get(&(route_ns, er.name.as_str())).copied(),
            });
        }
    }
    refs
}

fn resolve_rule_backends<'a>(
    hr: &'a HTTPRoute,
    route_ns: &str,
    services_by_id: &HashMap<(&str, &str), &'a Service>,
    slices_by_service: &HashMap<(&str, &str), Vec<&'a EndpointSlice>>,
    dialables_by_id: &HashMap<(&str, &str), usize>,
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
                    outcome: resolve_backend(
                        br,
                        route_ns,
                        services_by_id,
                        slices_by_service,
                        dialables_by_id,
                    ),
                })
                .collect()
        })
        .collect()
}

/// Resolve every `GatewayBackend` in the cluster: split its
/// `baseURL` into the parts a data plane dials with, and look up
/// each Secret it names.
///
/// Two failure shapes, deliberately different. A spec that cannot
/// name a destination — an unparseable URL, an auth block that
/// contradicts its own `type` — is [`GatewayBackendOutcome::Invalid`]
/// and publishes nothing. A spec that is fine but names material
/// that has not arrived stays `Resolved` with that one reference
/// unresolved: the backend is published, the request path fails the
/// dial, and the material can land later without the object having
/// to change.
fn resolve_gateway_backends<'a>(
    objects: &'a [GatewayBackend],
    secrets_by_id: &HashMap<(&str, &str), &'a Secret>,
) -> Vec<GatewayBackendResolution<'a>> {
    let mut out = Vec::with_capacity(objects.len());
    for object in objects {
        let (Some(namespace), Some(name)) = (
            object.metadata.namespace.as_deref(),
            object.metadata.name.as_deref(),
        ) else {
            continue;
        };
        out.push(GatewayBackendResolution {
            object,
            namespace: namespace.to_string(),
            name: name.to_string(),
            key: dialable_key_string(namespace, name),
            outcome: resolve_gateway_backend(object, namespace, secrets_by_id),
        });
    }
    out
}

fn resolve_gateway_backend<'a>(
    object: &GatewayBackend,
    namespace: &str,
    secrets_by_id: &HashMap<(&str, &str), &'a Secret>,
) -> GatewayBackendOutcome<'a> {
    let spec = &object.spec;
    let url = match parse_base_url(&spec.base_url) {
        Ok(url) => url,
        Err(message) => {
            return GatewayBackendOutcome::Invalid {
                reason: "InvalidBaseURL",
                message,
            };
        }
    };
    // The scheme decides whether TLS is originated at all; the `tls`
    // block only says how. Settings on a cleartext URL would be
    // silently ignored, which is worse than being told.
    if !url.tls && spec.tls.is_some() {
        return GatewayBackendOutcome::Invalid {
            reason: "InvalidBaseURL",
            message: "tls settings require an https baseURL".to_string(),
        };
    }
    let auth = match spec
        .auth
        .as_ref()
        .map(|a| resolve_auth(a, namespace, secrets_by_id))
    {
        Some(Ok(auth)) => Some(auth),
        Some(Err(invalid)) => return invalid,
        None => None,
    };
    GatewayBackendOutcome::Resolved(Box::new(ResolvedDialable {
        host: url.host,
        port: url.port,
        path_prefix: url.path_prefix,
        tls: url.tls.then(|| {
            let tls = spec.tls.as_ref();
            ResolvedBackendTls {
                ca: tls
                    .and_then(|t| t.ca.as_ref())
                    .map(|ca| cert_ref(namespace, &ca.name, secrets_by_id)),
                sni: tls.and_then(|t| t.sni.clone()),
                alpn: tls.and_then(|t| t.alpn.as_deref()).map_or_else(
                    // Offer both and let the provider choose: HTTP/2
                    // where it is available, HTTP/1.1 everywhere else.
                    || vec![pb::AlpnProtocol::H2, pb::AlpnProtocol::Http11],
                    |alpn| alpn.iter().copied().map(alpn_protocol).collect(),
                ),
                insecure_skip_verify: tls.is_some_and(|t| t.insecure_skip_verify),
            }
        }),
        auth,
    }))
}

/// Resolve an auth block, or say why it is not one. The `type` and
/// the block of the same name have to agree: a `type` whose block is
/// absent is a spec that states a scheme and then does not configure
/// it.
fn resolve_auth<'a>(
    auth: &crd::BackendAuth,
    namespace: &str,
    secrets_by_id: &HashMap<(&str, &str), &'a Secret>,
) -> Result<ResolvedBackendAuth, GatewayBackendOutcome<'a>> {
    let missing = |field: &str| GatewayBackendOutcome::Invalid {
        reason: "InvalidAuth",
        message: format!("auth.type is {:?} but auth.{field} is absent", auth.r#type),
    };
    match auth.r#type {
        crd::BackendAuthType::ApiKey => {
            let Some(api_key) = auth.api_key.as_ref() else {
                return Err(missing("apiKey"));
            };
            Ok(ResolvedBackendAuth::ApiKey {
                credential: credential_ref(namespace, &api_key.secret_ref, secrets_by_id),
                header: api_key
                    .header
                    .clone()
                    .unwrap_or_else(|| http::header::AUTHORIZATION.to_string()),
                // An absent prefix is the default; an empty one is a
                // choice, and sends the credential bare.
                prefix: api_key
                    .prefix
                    .clone()
                    .unwrap_or_else(|| "Bearer ".to_string()),
            })
        }
        crd::BackendAuthType::OAuth2 => {
            let Some(oauth2) = auth.oauth2.as_ref() else {
                return Err(missing("oauth2"));
            };
            if !is_absolute_http_url(&oauth2.token_url) {
                return Err(GatewayBackendOutcome::Invalid {
                    reason: "InvalidAuth",
                    message: format!(
                        "auth.oauth2.tokenURL `{}` is not an absolute http(s) URL",
                        oauth2.token_url
                    ),
                });
            }
            Ok(ResolvedBackendAuth::OAuth2 {
                credential: credential_ref(namespace, &oauth2.client_secret_ref, secrets_by_id),
                token_url: oauth2.token_url.clone(),
                client_id: oauth2.client_id.clone(),
                scopes: oauth2.scopes.clone(),
                client_auth_method: match oauth2.client_auth_method {
                    Some(crd::ClientAuthMethod::ClientSecretPost) => {
                        pb::ClientAuthMethod::ClientSecretPost
                    }
                    Some(crd::ClientAuthMethod::ClientSecretBasic) | None => {
                        pb::ClientAuthMethod::ClientSecretBasic
                    }
                },
            })
        }
    }
}

/// Look up one data key inside one Secret in `namespace`.
///
/// "Present but without that key" is kept apart from "not there at
/// all" because they are different operator mistakes and only the
/// first is diagnosable from the object alone.
fn credential_ref(
    namespace: &str,
    secret_ref: &crd::SecretKeyReference,
    secrets_by_id: &HashMap<(&str, &str), &Secret>,
) -> CredentialRef {
    let outcome = match secrets_by_id.get(&(namespace, secret_ref.name.as_str())) {
        None => CredentialOutcome::SecretMissing,
        Some(secret) => match secret.data.as_ref().and_then(|d| d.get(&secret_ref.key)) {
            Some(value) => CredentialOutcome::Present(SecretValue::new(value.0.clone())),
            None => CredentialOutcome::KeyMissing,
        },
    };
    CredentialRef {
        namespace: namespace.to_string(),
        name: secret_ref.name.clone(),
        key: secret_ref.key.clone(),
        outcome,
    }
}

/// The parts of a `baseURL` the data plane is given.
struct BaseUrl {
    host: String,
    port: u16,
    path_prefix: Option<String>,
    /// The `https` scheme, which is what decides TLS origination.
    tls: bool,
}

/// Split a `baseURL` into host, port, path prefix and scheme.
///
/// This is the one place a URL exists: the data plane is handed the
/// parts. The scheme supplies the default port, and a path of `/`
/// (or none) is no prefix at all rather than one that contributes
/// nothing.
fn parse_base_url(raw: &str) -> Result<BaseUrl, String> {
    let uri = raw
        .parse::<http::Uri>()
        .map_err(|e| format!("baseURL `{raw}` is not a URL: {e}"))?;
    let tls = match uri.scheme() {
        Some(s) if *s == http::uri::Scheme::HTTPS => true,
        Some(s) if *s == http::uri::Scheme::HTTP => false,
        _ => return Err(format!("baseURL `{raw}` must be an http or https URL")),
    };
    let host = uri
        .host()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| format!("baseURL `{raw}` names no host"))?;
    if uri.query().is_some() {
        return Err(format!("baseURL `{raw}` must not carry a query"));
    }
    let path = uri.path();
    Ok(BaseUrl {
        host: host.to_string(),
        port: uri.port_u16().unwrap_or(if tls { 443 } else { 80 }),
        path_prefix: (path != "/" && !path.is_empty()).then(|| path.to_string()),
        tls,
    })
}

fn is_absolute_http_url(url: &str) -> bool {
    let Ok(uri) = url.parse::<http::Uri>() else {
        return false;
    };
    let scheme = uri.scheme();
    uri.host().is_some_and(|h| !h.is_empty())
        && (scheme == Some(&http::uri::Scheme::HTTP) || scheme == Some(&http::uri::Scheme::HTTPS))
}

fn alpn_protocol(p: crd::AlpnProtocol) -> pb::AlpnProtocol {
    match p {
        crd::AlpnProtocol::H2 => pb::AlpnProtocol::H2,
        crd::AlpnProtocol::Http11 => pb::AlpnProtocol::Http11,
    }
}

/// Which kind a backendRef names. Group and kind are both optional
/// in the API and default to the core `Service`, so a ref that says
/// nothing is a Service.
enum RefKind {
    Service,
    GatewayBackend,
    Unsupported,
}

fn classify_ref(br: &HttpRouteRulesBackendRefs) -> RefKind {
    let group = br.group.as_deref().unwrap_or("");
    let kind = br.kind.as_deref().unwrap_or("Service");
    match (group, kind) {
        ("", "Service") => RefKind::Service,
        (GATEWAY_GROUP, "GatewayBackend") => RefKind::GatewayBackend,
        _ => RefKind::Unsupported,
    }
}

fn resolve_backend<'a>(
    br: &HttpRouteRulesBackendRefs,
    route_ns: &str,
    services_by_id: &HashMap<(&str, &str), &'a Service>,
    slices_by_service: &HashMap<(&str, &str), Vec<&'a EndpointSlice>>,
    dialables_by_id: &HashMap<(&str, &str), usize>,
) -> BackendOutcome<'a> {
    let kind = classify_ref(br);
    if matches!(kind, RefKind::Unsupported) {
        tracing::warn!(
            name = %br.name, group = ?br.group, kind = ?br.kind,
            "skipping backendRef of an unsupported kind"
        );
        return BackendOutcome::UnsupportedKind;
    }
    // Cross-namespace is refused before anything else is looked at,
    // for either kind: it is a decision about the reference, not
    // about what it points to.
    let backend_ns = br.namespace.as_deref().unwrap_or(route_ns);
    if backend_ns != route_ns {
        tracing::warn!(
            ns = backend_ns,
            "skipping cross-namespace backendRef (ReferenceGrant not supported in v0)"
        );
        return BackendOutcome::CrossNamespace;
    }
    if matches!(kind, RefKind::GatewayBackend) {
        if br.port.is_some() {
            tracing::warn!(
                name = %br.name, port = ?br.port,
                "skipping GatewayBackend backendRef carrying a port; the port belongs to baseURL"
            );
            return BackendOutcome::PortNotAllowed;
        }
        let key = dialable_key_string(backend_ns, &br.name);
        return match dialables_by_id.get(&(backend_ns, br.name.as_str())) {
            Some(&index) => BackendOutcome::Dialable { key, index },
            None => BackendOutcome::MissingDialable { key },
        };
    }
    let Some(port) = br.port else {
        return BackendOutcome::NoPort;
    };
    let key = backend_key_string(backend_ns, &br.name, port);
    let Some(service) = services_by_id.get(&(backend_ns, br.name.as_str())) else {
        return BackendOutcome::MissingService { key };
    };
    let usable_ip = service
        .spec
        .as_ref()
        .and_then(|s| s.cluster_ip.as_deref())
        .is_some_and(|ip| !ip.is_empty() && ip != "None");
    if !usable_ip {
        return BackendOutcome::Headless { key };
    }
    let slices = slices_by_service
        .get(&(backend_ns, br.name.as_str()))
        .map_or(&[][..], Vec::as_slice);
    BackendOutcome::Resolved {
        key,
        service,
        endpoints: endpoints_from_slices(service, port, slices),
    }
}

/// Index `EndpointSlice`s by the Service they belong to, read from
/// the `kubernetes.io/service-name` label. Unlabeled slices are
/// skipped (the slice controller always sets the label; anything
/// else is not Service-owned).
fn index_slices(slices: &[EndpointSlice]) -> HashMap<(&str, &str), Vec<&EndpointSlice>> {
    let mut index: HashMap<(&str, &str), Vec<&EndpointSlice>> = HashMap::new();
    for slice in slices {
        let Some(ns) = slice.metadata.namespace.as_deref() else {
            continue;
        };
        let Some(service) = slice
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(SERVICE_NAME_LABEL))
        else {
            continue;
        };
        index.entry((ns, service)).or_default().push(slice);
    }
    index
}

/// Derive the usable per-pod endpoints for one Service port from its
/// `EndpointSlice`s: one endpoint per ready address, at the slice
/// port whose name matches the service port's name.
///
/// The result is a pure function of the slice *set* — accumulation
/// is keyed by endpoint name with a deterministic merge, and the
/// output is sorted — so translation converges to the same snapshot
/// regardless of slice arrival order and the diff never sees a
/// same-set reorder.
fn endpoints_from_slices(
    service: &Service,
    service_port: i32,
    slices: &[&EndpointSlice],
) -> Vec<ResolvedEndpoint> {
    // The slice port carries the *service port's name*, not its
    // number. A Service with a single unnamed port yields slices
    // with unnamed ports; no matching ServicePort means no slice
    // port can match either way.
    let port_name = service
        .spec
        .as_ref()
        .and_then(|s| s.ports.as_deref())
        .unwrap_or(&[])
        .iter()
        .find(|p| p.port == service_port)
        .and_then(|p| p.name.as_deref())
        .unwrap_or("");

    let mut out: std::collections::BTreeMap<String, ResolvedEndpoint> =
        std::collections::BTreeMap::new();
    for slice in slices {
        if slice.address_type != "IPv4" {
            continue;
        }
        let Some(target_port) = slice
            .ports
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .find(|p| p.name.as_deref().unwrap_or("") == port_name)
            .and_then(|p| p.port)
            .and_then(|p| u16::try_from(p).ok())
        else {
            continue;
        };
        for endpoint in &slice.endpoints {
            let usable = endpoint
                .conditions
                .as_ref()
                .is_none_or(|c| c.ready != Some(false) && c.serving != Some(false));
            if !usable {
                continue;
            }
            let pod_name = endpoint
                .target_ref
                .as_ref()
                .filter(|r| r.kind.as_deref() == Some("Pod"))
                .and_then(|r| r.name.as_deref());
            for address in &endpoint.addresses {
                let candidate = ResolvedEndpoint {
                    name: pod_name.unwrap_or(address).to_string(),
                    address: address.clone(),
                    port: target_port,
                };
                // Same name in two slices (rebalancing in flight):
                // keep the smaller (address, port) so the winner
                // doesn't depend on iteration order.
                out.entry(candidate.name.clone())
                    .and_modify(|existing| {
                        if (candidate.address.as_str(), candidate.port)
                            < (existing.address.as_str(), existing.port)
                        {
                            *existing = candidate.clone();
                        }
                    })
                    .or_insert(candidate);
            }
        }
    }
    out.into_values().collect()
}

/// The address(es) a Gateway is reachable at: `LoadBalancer` ingress
/// when present, the `ClusterIP` for non-`LoadBalancer` Services, and
/// nothing while a `LoadBalancer` assignment is pending.
///
/// With the service-name annotation the addresses come from the
/// referenced operator-owned Service in the Gateway's namespace —
/// named by the Gateway's own author, so no ownership guard applies;
/// while it doesn't exist the Gateway stays unaddressed (with a
/// warning). Otherwise they come from the provisioner-managed
/// Service, verified by the managed-by label and a controller
/// ownerReference with the Gateway's uid — never by name alone.
fn managed_service_addresses(
    gw: &Gateway,
    gw_ns: &str,
    gw_name: &str,
    services_by_id: &HashMap<(&str, &str), &Service>,
) -> Vec<GatewayAddress> {
    if let Some(ref_name) = infra::annotations::service_name(gw) {
        let Some(svc) = services_by_id.get(&(gw_ns, ref_name)) else {
            tracing::warn!(
                gateway = format!("{gw_ns}/{gw_name}"),
                service = ref_name,
                "referenced Service does not exist; gateway stays unaddressed"
            );
            return Vec::new();
        };
        return service_addresses(svc);
    }

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
    service_addresses(svc)
}

/// Extract a Service's published addresses: LB ingress, or the
/// cluster IPs when it isn't a `LoadBalancer`.
fn service_addresses(svc: &Service) -> Vec<GatewayAddress> {
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

    let spec = svc.spec.as_ref();
    // A LoadBalancer Service without ingress is still waiting for its
    // address; publishing the ClusterIP in the meantime would hand
    // clients an address that stops being the right one moments
    // later. Report nothing until the LB assigns.
    if spec.and_then(|s| s.type_.as_deref()) == Some("LoadBalancer") {
        return Vec::new();
    }

    // No LB ingress and not a LoadBalancer (ClusterIP/NodePort
    // Service): report the cluster IPs.
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

/// The wire key of a `GatewayBackend`. No port, which is what keeps
/// it out of [`backend_key_string`]'s space for good: a Service key
/// always ends in `:port`.
pub(crate) fn dialable_key_string(ns: &str, name: &str) -> String {
    format!("{ns}/{name}")
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
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::{
        LoadBalancerIngress, LoadBalancerStatus, ObjectReference, ServicePort, ServiceSpec,
        ServiceStatus,
    };
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort};
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

    fn service_with_port(ns: &str, name: &str, port: i32, port_name: Option<&str>) -> Service {
        let mut svc = service(ns, name, Some("10.0.0.1"));
        svc.spec.as_mut().unwrap().ports = Some(vec![ServicePort {
            name: port_name.map(String::from),
            port,
            ..Default::default()
        }]);
        svc
    }

    fn endpoint_slice(
        ns: &str,
        name: &str,
        service: &str,
        ports: &[(Option<&str>, i32)],
        endpoints: Vec<Endpoint>,
    ) -> EndpointSlice {
        EndpointSlice {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                labels: Some(
                    [(SERVICE_NAME_LABEL.to_string(), service.to_string())]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
            address_type: "IPv4".into(),
            endpoints,
            ports: Some(
                ports
                    .iter()
                    .map(|(name, port)| EndpointPort {
                        name: name.map(String::from),
                        port: Some(*port),
                        ..Default::default()
                    })
                    .collect(),
            ),
        }
    }

    fn slice_endpoint(
        address: &str,
        pod: Option<&str>,
        ready: Option<bool>,
        serving: Option<bool>,
    ) -> Endpoint {
        Endpoint {
            addresses: vec![address.into()],
            conditions: Some(EndpointConditions {
                ready,
                serving,
                ..Default::default()
            }),
            target_ref: pod.map(|p| ObjectReference {
                kind: Some("Pod".into()),
                name: Some(p.into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn managed_service(
        gw_ns: &str,
        gw_name: &str,
        svc_type: &str,
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
                type_: Some(svc_type.into()),
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

    /// A `kubernetes.io/tls` Secret carrying material, which is what
    /// makes a reference to it resolve.
    fn secret(ns: &str, name: &str) -> Secret {
        secret_with(ns, name, [("tls.crt", &b"cert"[..]), ("tls.key", b"key")])
    }

    fn secret_with<'a>(
        ns: &str,
        name: &str,
        data: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    ) -> Secret {
        Secret {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            data: Some(
                data.into_iter()
                    .map(|(k, v)| (k.to_string(), ByteString(v.to_vec())))
                    .collect(),
            ),
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
    fn attached_routes_counts_accepted_routes_once() {
        // One accepted listener plus a hostname-conflicted duplicate.
        let listeners = vec![
            http_listener("http", 80, Some("a.example")),
            http_listener("dup", 80, Some("a.example")),
        ];
        let s = state(
            vec![gw("demo", "gw", "zd", listeners)],
            vec![
                // No hostname intersection anywhere: not Accepted, so
                // it MUST NOT count (and takes no edge).
                route(
                    "demo",
                    "miss",
                    vec![parent("gw", None)],
                    Some(vec!["b.example"]),
                    vec![],
                ),
                // Accepted: counts on both selected listeners — the
                // conflicted dup included — but edges only on the
                // accepted one.
                route(
                    "demo",
                    "hit",
                    vec![parent("gw", None)],
                    Some(vec!["a.example"]),
                    vec![],
                ),
                // Two parentRefs to the same Gateway: a distinct
                // route counts once per listener, not once per
                // parentRef.
                route(
                    "demo",
                    "twice",
                    vec![parent("gw", None), parent("gw", Some("http"))],
                    Some(vec!["a.example"]),
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
        assert_eq!(
            counts,
            vec![2, 2],
            "hit + twice; miss excluded; no double count"
        );

        let by_name: HashMap<&str, Vec<&RouteResolution<'_>>> =
            r.routes.iter().fold(HashMap::new(), |mut m, rr| {
                m.entry(rr.route_name).or_default().push(rr);
                m
            });
        assert_eq!(
            by_name["miss"][0].outcome,
            RouteParentOutcome::NoMatchingListenerHostname
        );
        assert!(by_name["miss"][0].edges.is_empty());
        assert_eq!(by_name["hit"][0].outcome, RouteParentOutcome::Accepted);
        assert_eq!(
            by_name["hit"][0].edges.len(),
            1,
            "no edge on the conflicted dup"
        );
        assert_eq!(by_name["twice"].len(), 2, "one resolution per parentRef");
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
            BackendOutcome::Resolved { key, endpoints, .. }
                if key == "demo/ok:8080" && endpoints.is_empty()
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

    // ----- GatewayBackend -----

    fn dialable_ref(name: &str, ns: Option<&str>, port: Option<i32>) -> HttpRouteRulesBackendRefs {
        HttpRouteRulesBackendRefs {
            name: name.into(),
            namespace: ns.map(String::from),
            port,
            group: Some(GATEWAY_GROUP.into()),
            kind: Some("GatewayBackend".into()),
            ..Default::default()
        }
    }

    fn gateway_backend(ns: &str, name: &str, base_url: &str) -> GatewayBackend {
        GatewayBackend {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                generation: Some(2),
                ..Default::default()
            },
            spec: crd::GatewayBackendSpec {
                base_url: base_url.into(),
                tls: None,
                auth: None,
            },
            status: None,
        }
    }

    fn api_key_auth(secret: &str, key: &str) -> crd::BackendAuth {
        crd::BackendAuth {
            r#type: crd::BackendAuthType::ApiKey,
            api_key: Some(crd::ApiKeyAuth {
                secret_ref: crd::SecretKeyReference {
                    name: secret.into(),
                    key: key.into(),
                },
                header: None,
                prefix: None,
            }),
            oauth2: None,
        }
    }

    /// Resolve one `GatewayBackend` on its own, with `secrets` in the
    /// cluster.
    fn resolve_one<'a>(
        object: &'a GatewayBackend,
        secrets: &'a [Secret],
    ) -> GatewayBackendOutcome<'a> {
        let by_id = index_by_id(secrets, |s| &s.metadata);
        resolve_gateway_backend(object, "demo", &by_id)
    }

    fn resolved<'a>(outcome: &'a GatewayBackendOutcome<'a>) -> &'a ResolvedDialable<'a> {
        match outcome {
            GatewayBackendOutcome::Resolved(r) => r,
            GatewayBackendOutcome::Invalid { reason, message } => {
                panic!("expected a resolved backend, got {reason}: {message}")
            }
        }
    }

    #[test]
    fn base_url_splits_into_host_port_and_prefix() {
        let cases = [
            (
                "https://api.example.com/v1",
                "api.example.com",
                443,
                Some("/v1"),
                true,
            ),
            ("http://api.example.com", "api.example.com", 80, None, false),
            (
                "https://api.example.com:8443/",
                "api.example.com",
                8443,
                None,
                true,
            ),
            (
                "http://10.0.0.7:8080/base/",
                "10.0.0.7",
                8080,
                Some("/base/"),
                false,
            ),
        ];
        for (url, host, port, prefix, tls) in cases {
            let object = gateway_backend("demo", "be", url);
            let outcome = resolve_one(&object, &[]);
            let r = resolved(&outcome);
            assert_eq!((r.host.as_str(), r.port), (host, port), "{url}");
            assert_eq!(r.path_prefix.as_deref(), prefix, "{url}");
            assert_eq!(r.tls.is_some(), tls, "{url}");
        }
    }

    #[test]
    fn base_url_must_be_an_absolute_http_url() {
        for url in [
            "api.example.com/v1",
            "ftp://api.example.com",
            "https://",
            "https://api.example.com?k=v",
        ] {
            let object = gateway_backend("demo", "be", url);
            let outcome = resolve_one(&object, &[]);
            assert!(
                matches!(
                    &outcome,
                    GatewayBackendOutcome::Invalid { reason, .. } if *reason == "InvalidBaseURL"
                ),
                "`{url}` must not resolve"
            );
        }
    }

    #[test]
    fn tls_settings_require_an_https_base_url() {
        let mut object = gateway_backend("demo", "be", "http://api.example.com");
        object.spec.tls = Some(crd::BackendTls::default());
        assert!(matches!(
            resolve_one(&object, &[]),
            GatewayBackendOutcome::Invalid { reason, .. } if reason == "InvalidBaseURL"
        ));
    }

    #[test]
    fn https_defaults_the_trust_roots_and_alpn() {
        let object = gateway_backend("demo", "be", "https://api.example.com");
        let outcome = resolve_one(&object, &[]);
        let tls = resolved(&outcome).tls.as_ref().expect("tls originated");
        assert!(tls.ca.is_none(), "no CA named means the system store");
        assert_eq!(
            tls.alpn,
            vec![pb::AlpnProtocol::H2, pb::AlpnProtocol::Http11]
        );
        assert!(!tls.insecure_skip_verify);
    }

    #[test]
    fn an_explicitly_empty_alpn_list_offers_none() {
        let mut object = gateway_backend("demo", "be", "https://api.example.com");
        object.spec.tls = Some(crd::BackendTls {
            alpn: Some(vec![]),
            ..Default::default()
        });
        let outcome = resolve_one(&object, &[]);
        let tls = resolved(&outcome).tls.as_ref().expect("tls originated");
        assert!(tls.alpn.is_empty());
    }

    #[test]
    fn trust_roots_resolve_against_a_ca_secret() {
        let mut object = gateway_backend("demo", "be", "https://api.example.com");
        object.spec.tls = Some(crd::BackendTls {
            ca: Some(crd::LocalSecretReference { name: "ca".into() }),
            ..Default::default()
        });

        let outcome = resolve_one(&object, &[]);
        let tls = resolved(&outcome).tls.as_ref().unwrap();
        let ca = tls.ca.as_ref().expect("ca named");
        assert!(ca.secret.is_none(), "not present yet");

        // A CA-only Secret: a chain and no key.
        let secrets = vec![secret_with("demo", "ca", [("tls.crt", &b"cert"[..])])];
        let outcome = resolve_one(&object, &secrets);
        let tls = resolved(&outcome).tls.as_ref().unwrap();
        assert!(tls.ca.as_ref().unwrap().secret.is_some());
    }

    #[test]
    fn api_key_defaults_the_header_and_prefix() {
        let mut object = gateway_backend("demo", "be", "https://api.example.com");
        object.spec.auth = Some(api_key_auth("key", "apiKey"));
        let secrets = vec![secret_with(
            "demo",
            "key",
            [
                ("tls.crt", &b""[..]),
                ("tls.key", b""),
                ("apiKey", b"s3cr3t"),
            ],
        )];
        let outcome = resolve_one(&object, &secrets);
        let auth = resolved(&outcome).auth.as_ref().expect("auth resolved");
        let ResolvedBackendAuth::ApiKey { header, prefix, .. } = auth else {
            panic!("expected an api key");
        };
        assert_eq!(header, "authorization");
        assert_eq!(prefix, "Bearer ");
        assert!(matches!(
            auth.credential().outcome,
            CredentialOutcome::Present(_)
        ));
    }

    #[test]
    fn an_empty_api_key_prefix_is_a_choice() {
        let mut object = gateway_backend("demo", "be", "https://api.example.com");
        let mut auth = api_key_auth("key", "apiKey");
        auth.api_key.as_mut().unwrap().prefix = Some(String::new());
        auth.api_key.as_mut().unwrap().header = Some("x-api-key".into());
        object.spec.auth = Some(auth);
        let outcome = resolve_one(&object, &[]);
        let ResolvedBackendAuth::ApiKey { header, prefix, .. } =
            resolved(&outcome).auth.as_ref().unwrap()
        else {
            panic!("expected an api key");
        };
        assert_eq!(header, "x-api-key");
        assert_eq!(prefix, "");
    }

    #[test]
    fn a_credential_tells_a_missing_secret_from_a_missing_key() {
        let mut object = gateway_backend("demo", "be", "https://api.example.com");
        object.spec.auth = Some(api_key_auth("key", "apiKey"));

        let outcome = resolve_one(&object, &[]);
        assert!(matches!(
            resolved(&outcome)
                .auth
                .as_ref()
                .unwrap()
                .credential()
                .outcome,
            CredentialOutcome::SecretMissing
        ));

        let secrets = vec![secret_with("demo", "key", [("apikey", &b"s3cr3t"[..])])];
        let outcome = resolve_one(&object, &secrets);
        let credential = resolved(&outcome).auth.as_ref().unwrap().credential();
        assert!(matches!(credential.outcome, CredentialOutcome::KeyMissing));
        assert_eq!(credential.id(), "demo/key#apiKey");
    }

    #[test]
    fn an_auth_type_without_its_block_is_invalid() {
        let mut object = gateway_backend("demo", "be", "https://api.example.com");
        object.spec.auth = Some(crd::BackendAuth {
            r#type: crd::BackendAuthType::OAuth2,
            api_key: None,
            oauth2: None,
        });
        assert!(matches!(
            resolve_one(&object, &[]),
            GatewayBackendOutcome::Invalid { reason, .. } if reason == "InvalidAuth"
        ));
    }

    #[test]
    fn an_oauth2_token_url_must_be_absolute() {
        let mut object = gateway_backend("demo", "be", "https://api.example.com");
        let oauth2 = |token_url: &str| crd::BackendAuth {
            r#type: crd::BackendAuthType::OAuth2,
            api_key: None,
            oauth2: Some(crd::OAuth2Auth {
                token_url: token_url.into(),
                client_id: "gw".into(),
                client_secret_ref: crd::SecretKeyReference {
                    name: "key".into(),
                    key: "clientSecret".into(),
                },
                scopes: vec!["all-apis".into()],
                client_auth_method: Some(crd::ClientAuthMethod::ClientSecretPost),
            }),
        };

        object.spec.auth = Some(oauth2("/oauth2/token"));
        assert!(matches!(
            resolve_one(&object, &[]),
            GatewayBackendOutcome::Invalid { reason, .. } if reason == "InvalidAuth"
        ));

        object.spec.auth = Some(oauth2("https://idp.example.com/token"));
        let outcome = resolve_one(&object, &[]);
        let ResolvedBackendAuth::OAuth2 {
            client_id,
            scopes,
            client_auth_method,
            ..
        } = resolved(&outcome).auth.as_ref().unwrap()
        else {
            panic!("expected oauth2");
        };
        assert_eq!(client_id, "gw");
        assert_eq!(scopes, &["all-apis".to_string()]);
        assert_eq!(*client_auth_method, pb::ClientAuthMethod::ClientSecretPost);
    }

    #[test]
    fn dialable_backend_refs_resolve_by_kind() {
        let mut s = state(
            vec![gw("demo", "gw", "zd", vec![http_listener("h", 80, None)])],
            vec![route(
                "demo",
                "r",
                vec![parent("gw", None)],
                None,
                vec![
                    dialable_ref("provider", None, None),
                    dialable_ref("gone", None, None),
                    dialable_ref("provider", None, Some(443)),
                    dialable_ref("provider", Some("elsewhere"), None),
                    HttpRouteRulesBackendRefs {
                        name: "cm".into(),
                        kind: Some("ConfigMap".into()),
                        port: Some(80),
                        ..Default::default()
                    },
                ],
            )],
        );
        s.gateway_backends = vec![gateway_backend(
            "demo",
            "provider",
            "https://api.example.com/v1",
        )];
        let r = resolve(&s, OURS);

        let outcomes = &r.routes[0].rule_backends[0];
        // The key has no port, which is what keeps it out of the
        // Service key space for good.
        assert!(matches!(
            &outcomes[0].outcome,
            BackendOutcome::Dialable { key, index }
                if key == "demo/provider" && *index == 0
        ));
        assert!(matches!(
            &outcomes[1].outcome,
            BackendOutcome::MissingDialable { key } if key == "demo/gone"
        ));
        assert!(matches!(
            &outcomes[2].outcome,
            BackendOutcome::PortNotAllowed
        ));
        assert!(matches!(
            &outcomes[3].outcome,
            BackendOutcome::CrossNamespace
        ));
        assert!(matches!(
            &outcomes[4].outcome,
            BackendOutcome::UnsupportedKind
        ));
    }

    #[test]
    fn every_gateway_backend_resolves_whether_or_not_a_route_names_it() {
        let mut s = state(
            vec![gw("demo", "gw", "zd", vec![http_listener("h", 80, None)])],
            vec![],
        );
        s.gateway_backends = vec![
            gateway_backend("demo", "unreferenced", "https://api.example.com"),
            gateway_backend("other", "broken", "not-a-url"),
        ];
        let r = resolve(&s, OURS);

        assert_eq!(r.gateway_backends.len(), 2);
        assert_eq!(r.gateway_backends[0].key, "demo/unreferenced");
        assert!(matches!(
            r.gateway_backends[0].outcome,
            GatewayBackendOutcome::Resolved(_)
        ));
        assert_eq!(r.gateway_backends[1].key, "other/broken");
        assert!(matches!(
            r.gateway_backends[1].outcome,
            GatewayBackendOutcome::Invalid { .. }
        ));
    }

    // ----- per-pod endpoints -----

    fn ready(address: &str, pod: &str) -> Endpoint {
        slice_endpoint(address, Some(pod), Some(true), Some(true))
    }

    /// State with one gateway, one route to `svc:8080`, and the given
    /// Service + slices; returns the endpoints of the route's only
    /// backend.
    fn resolve_endpoints(svc: Service, slices: Vec<EndpointSlice>) -> Vec<ResolvedEndpoint> {
        let mut s = state(
            vec![gw("demo", "gw", "zd", vec![http_listener("h", 80, None)])],
            vec![route(
                "demo",
                "r",
                vec![parent("gw", None)],
                None,
                vec![backend_ref("svc", None, Some(8080))],
            )],
        );
        s.services = vec![svc];
        s.endpoint_slices = slices;
        let r = resolve(&s, OURS);
        match &r.routes[0].rule_backends[0][0].outcome {
            BackendOutcome::Resolved { endpoints, .. } => endpoints.clone(),
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn resolved_backend_unions_endpoints_across_slices() {
        let endpoints = resolve_endpoints(
            service_with_port("demo", "svc", 8080, None),
            vec![
                endpoint_slice(
                    "demo",
                    "svc-1",
                    "svc",
                    &[(None, 8080)],
                    vec![ready("10.1.0.1", "pod-a"), ready("10.1.0.2", "pod-b")],
                ),
                endpoint_slice(
                    "demo",
                    "svc-2",
                    "svc",
                    &[(None, 8080)],
                    vec![ready("10.1.0.3", "pod-c")],
                ),
            ],
        );
        assert_eq!(
            endpoints,
            vec![
                ResolvedEndpoint {
                    name: "pod-a".into(),
                    address: "10.1.0.1".into(),
                    port: 8080,
                },
                ResolvedEndpoint {
                    name: "pod-b".into(),
                    address: "10.1.0.2".into(),
                    port: 8080,
                },
                ResolvedEndpoint {
                    name: "pod-c".into(),
                    address: "10.1.0.3".into(),
                    port: 8080,
                },
            ],
        );
    }

    #[test]
    fn endpoint_derivation_is_slice_order_independent() {
        let svc = service_with_port("demo", "svc", 8080, None);
        let a = endpoint_slice(
            "demo",
            "svc-1",
            "svc",
            &[(None, 8080)],
            vec![ready("10.1.0.2", "pod-b"), ready("10.1.0.1", "pod-a")],
        );
        let b = endpoint_slice(
            "demo",
            "svc-2",
            "svc",
            &[(None, 8080)],
            vec![ready("10.1.0.3", "pod-c")],
        );
        assert_eq!(
            endpoints_from_slices(&svc, 8080, &[&a, &b]),
            endpoints_from_slices(&svc, 8080, &[&b, &a]),
        );
    }

    #[test]
    fn duplicate_pod_across_slices_dedupes_deterministically() {
        // The same pod in two slices mid-rebalance: one endpoint
        // survives, and which one doesn't depend on slice order.
        let svc = service_with_port("demo", "svc", 8080, None);
        let a = endpoint_slice(
            "demo",
            "svc-1",
            "svc",
            &[(None, 8080)],
            vec![ready("10.1.0.2", "pod-a")],
        );
        let b = endpoint_slice(
            "demo",
            "svc-2",
            "svc",
            &[(None, 8080)],
            vec![ready("10.1.0.1", "pod-a")],
        );
        let forward = endpoints_from_slices(&svc, 8080, &[&a, &b]);
        assert_eq!(forward, endpoints_from_slices(&svc, 8080, &[&b, &a]));
        assert_eq!(
            forward,
            vec![ResolvedEndpoint {
                name: "pod-a".into(),
                address: "10.1.0.1".into(),
                port: 8080,
            }],
        );
    }

    #[test]
    fn unready_and_unserving_endpoints_are_filtered() {
        let endpoints = resolve_endpoints(
            service_with_port("demo", "svc", 8080, None),
            vec![endpoint_slice(
                "demo",
                "svc-1",
                "svc",
                &[(None, 8080)],
                vec![
                    slice_endpoint("10.1.0.1", Some("pod-a"), Some(false), Some(true)),
                    slice_endpoint("10.1.0.2", Some("pod-b"), Some(true), Some(false)),
                    // Absent conditions count as ready (K8s semantics).
                    slice_endpoint("10.1.0.3", Some("pod-c"), None, None),
                    ready("10.1.0.4", "pod-d"),
                ],
            )],
        );
        let names: Vec<&str> = endpoints.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["pod-c", "pod-d"]);
    }

    #[test]
    fn named_port_resolves_through_slice_port_name() {
        let endpoints = resolve_endpoints(
            service_with_port("demo", "svc", 8080, Some("http")),
            vec![endpoint_slice(
                "demo",
                "svc-1",
                "svc",
                &[(Some("metrics"), 9999), (Some("http"), 9090)],
                vec![ready("10.1.0.1", "pod-a")],
            )],
        );
        assert_eq!(
            endpoints,
            vec![ResolvedEndpoint {
                name: "pod-a".into(),
                address: "10.1.0.1".into(),
                port: 9090,
            }],
        );
    }

    #[test]
    fn slice_without_matching_port_contributes_nothing() {
        let endpoints = resolve_endpoints(
            service_with_port("demo", "svc", 8080, Some("http")),
            vec![endpoint_slice(
                "demo",
                "svc-1",
                "svc",
                &[(Some("grpc"), 9090)],
                vec![ready("10.1.0.1", "pod-a")],
            )],
        );
        assert!(endpoints.is_empty());
    }

    #[test]
    fn non_ipv4_slices_are_ignored() {
        let mut slice = endpoint_slice(
            "demo",
            "svc-1",
            "svc",
            &[(None, 8080)],
            vec![ready("fd00::1", "pod-a")],
        );
        slice.address_type = "IPv6".into();
        let endpoints =
            resolve_endpoints(service_with_port("demo", "svc", 8080, None), vec![slice]);
        assert!(endpoints.is_empty());
    }

    #[test]
    fn zero_ready_endpoints_still_resolve() {
        // The backend exists with no usable pods: still Resolved (the
        // upsert goes out empty and the DP answers 503), never
        // conflated with a missing Service.
        let endpoints = resolve_endpoints(
            service_with_port("demo", "svc", 8080, None),
            vec![endpoint_slice(
                "demo",
                "svc-1",
                "svc",
                &[(None, 8080)],
                vec![slice_endpoint(
                    "10.1.0.1",
                    Some("pod-a"),
                    Some(false),
                    Some(false),
                )],
            )],
        );
        assert!(endpoints.is_empty());
    }

    #[test]
    fn endpoint_name_prefers_pod_target_ref() {
        let endpoints = resolve_endpoints(
            service_with_port("demo", "svc", 8080, None),
            vec![endpoint_slice(
                "demo",
                "svc-1",
                "svc",
                &[(None, 8080)],
                vec![
                    ready("10.1.0.1", "pod-a"),
                    slice_endpoint("10.1.0.2", None, Some(true), Some(true)),
                ],
            )],
        );
        let names: Vec<&str> = endpoints.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["10.1.0.2", "pod-a"]);
    }

    #[test]
    fn slices_from_other_services_and_namespaces_are_excluded() {
        let endpoints = resolve_endpoints(
            service_with_port("demo", "svc", 8080, None),
            vec![
                endpoint_slice(
                    "demo",
                    "other-1",
                    "other",
                    &[(None, 8080)],
                    vec![ready("10.9.0.1", "pod-x")],
                ),
                endpoint_slice(
                    "elsewhere",
                    "svc-1",
                    "svc",
                    &[(None, 8080)],
                    vec![ready("10.9.0.2", "pod-y")],
                ),
                endpoint_slice(
                    "demo",
                    "svc-1",
                    "svc",
                    &[(None, 8080)],
                    vec![ready("10.1.0.1", "pod-a")],
                ),
            ],
        );
        let names: Vec<&str> = endpoints.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["pod-a"]);
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
        listener
            .tls
            .as_mut()
            .unwrap()
            .certificate_refs
            .as_mut()
            .unwrap()
            .push(GatewayListenersTlsCertificateRefs {
                name: "cm".into(),
                kind: Some("ConfigMap".into()),
                ..Default::default()
            });
        let mut s = state(vec![gw("demo", "gw", "zd", vec![listener])], vec![]);
        s.secrets = vec![secret("demo", "present"), secret("elsewhere", "cross")];
        let r = resolve(&s, OURS);

        let lr = &r.gateways[0].listeners[0];
        // present, absent, and the cross-namespace ref all resolve
        // as refs; only the non-Secret kind is rejected.
        assert_eq!(lr.cert_refs.len(), 3);
        assert!(lr.cert_refs[0].secret.is_some());
        assert!(lr.cert_refs[1].secret.is_none());
        // Cross-namespace: accepted permissively, secret found in
        // the referenced namespace, namespace carried through.
        assert!(lr.cert_refs[2].secret.is_some());
        assert_eq!(lr.cert_refs[2].namespace, "elsewhere");
        assert_eq!(lr.rejected_cert_refs, 1);
    }

    #[test]
    fn cross_namespace_cert_ref_with_missing_secret_is_unresolved() {
        let mut listener = https_listener("https", 443, &[]);
        listener.tls.as_mut().unwrap().certificate_refs =
            Some(vec![GatewayListenersTlsCertificateRefs {
                name: "ghost".into(),
                namespace: Some("elsewhere".into()),
                ..Default::default()
            }]);
        let s = state(vec![gw("demo", "gw", "zd", vec![listener])], vec![]);
        let r = resolve(&s, OURS);

        let lr = &r.gateways[0].listeners[0];
        // Accepted (not rejected), but unresolved — same treatment
        // as a missing same-namespace secret.
        assert_eq!(lr.cert_refs.len(), 1);
        assert!(lr.cert_refs[0].secret.is_none());
        assert_eq!(lr.cert_refs[0].namespace, "elsewhere");
        assert_eq!(lr.rejected_cert_refs, 0);
    }

    // ----- addresses -----

    #[test]
    fn addresses_come_from_the_managed_service_only() {
        // gw-lb: managed Service with LB ingress -> typed entries.
        // gw-pending: LoadBalancer Service without ingress yet -> none
        //   (the ClusterIP must not leak out as a transient address).
        // gw-cluster: ClusterIP Service -> its cluster IP.
        // gw-squat: same-name Service without our label/owner -> none.
        let mut squatter = service("demo", &object_name("gw-squat"), Some("10.96.0.99"));
        squatter.metadata.labels = None;
        let mut s = state(
            vec![
                gw("demo", "gw-lb", "zd", vec![http_listener("h", 80, None)]),
                gw(
                    "demo",
                    "gw-pending",
                    "zd",
                    vec![http_listener("h", 80, None)],
                ),
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
                "LoadBalancer",
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
            managed_service(
                "demo",
                "gw-pending",
                "LoadBalancer",
                vec![],
                vec!["10.96.0.10"],
            ),
            managed_service(
                "demo",
                "gw-cluster",
                "ClusterIP",
                vec![],
                vec!["10.96.0.10"],
            ),
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
        assert!(r.gateways[1].addresses.is_empty());
        assert_eq!(
            r.gateways[2].addresses,
            vec![GatewayAddress {
                value: "10.96.0.10".into(),
                kind: AddressKind::Ip
            }]
        );
        assert!(r.gateways[3].addresses.is_empty());
    }

    #[test]
    fn annotated_gateway_reads_addresses_from_the_referenced_service() {
        // gw-ref: names an operator-owned Service — plain, unlabeled,
        //   unowned — and gets its cluster IP; the leftover managed
        //   Service must not win over the annotation.
        // gw-missing: names a Service that doesn't exist -> none.
        let annotate = |mut g: Gateway, v: &str| {
            g.metadata.annotations = Some(
                [(
                    crate::infra::SERVICE_NAME_ANNOTATION.to_string(),
                    v.to_string(),
                )]
                .into(),
            );
            g
        };
        let mut s = state(
            vec![
                annotate(
                    gw("demo", "gw-ref", "zd", vec![http_listener("h", 80, None)]),
                    "edge",
                ),
                annotate(
                    gw(
                        "demo",
                        "gw-missing",
                        "zd",
                        vec![http_listener("h", 80, None)],
                    ),
                    "nope",
                ),
            ],
            vec![],
        );
        s.services = vec![
            service("demo", "edge", Some("10.96.0.42")),
            managed_service("demo", "gw-ref", "ClusterIP", vec![], vec!["10.96.0.10"]),
        ];
        let r = resolve(&s, OURS);

        assert_eq!(
            r.gateways[0].addresses,
            vec![GatewayAddress {
                value: "10.96.0.42".into(),
                kind: AddressKind::Ip
            }]
        );
        assert!(r.gateways[1].addresses.is_empty());
    }
}
