//! Desired status values from a [`Resolution`].
//!
//! Pure: [`build`] maps resolution outcomes onto the Gateway API
//! status types, and the `reconcile_*` functions decide whether a
//! write is needed — carrying `lastTransitionTime` forward for
//! semantically unchanged conditions so identical passes compare
//! equal. No API calls here; the writer task owns those. `now` is a
//! parameter so tests run on a fixed clock.
//!
//! An `HTTPRoute`'s `status.parents` is shared with other
//! controllers: we only ever add, replace or remove entries carrying
//! our `controllerName`.

use std::collections::HashMap;
use std::fmt::Write as _;

use gateway_api::apis::standard::gatewayclasses::{GatewayClass, GatewayClassStatus};
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayStatus, GatewayStatusAddresses, GatewayStatusListeners,
    GatewayStatusListenersSupportedKinds,
};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteStatus, HttpRouteStatusParents, HttpRouteStatusParentsParentRef,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

use crate::crd::{BackendBinding, BackendBindingStatus, GatewayBackend, GatewayBackendStatus};
use crate::resolve::{
    AddressKind, BackendBindingOutcome, BackendBindingResolution, BackendOutcome,
    BackendResolution, CredentialOutcome, GatewayBackendOutcome, GatewayBackendResolution,
    GatewayResolution, ListenerOutcome, ListenerResolution, Resolution, ResolvedBackendAuth,
    ResolvedDialable, RouteParentOutcome, RouteResolution,
};
use crate::snapshot::GatewayId;

/// Failing backendRefs named in a route's `ResolvedRefs` message
/// before the rest are only counted.
const MAX_LISTED_REFS: usize = 8;

/// Desired statuses for one pass, keyed by object identity.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusSet {
    /// `GatewayClass` name -> desired status.
    pub gateway_classes: Vec<(String, GatewayClassStatus)>,
    pub gateways: Vec<(GatewayId, GatewayStatus)>,
    /// `GatewayBackend` `(namespace, name)` -> desired status.
    pub gateway_backends: Vec<(GatewayId, GatewayBackendStatus)>,
    /// `BackendBinding` `(namespace, name)` -> desired status.
    pub backend_bindings: Vec<(GatewayId, BackendBindingStatus)>,
    /// `HTTPRoute` `(namespace, name)` -> our parent entries only.
    pub http_routes: Vec<(GatewayId, HttpRouteStatus)>,
}

/// One translate pass's status work for the writer: each desired
/// status paired with the observed object it was computed from (the
/// writer reconciles against its status, and the conflict-checked
/// write needs the full object with its `resourceVersion`).
#[derive(Debug, Clone, Default)]
pub struct StatusWork {
    pub gateway_classes: Vec<(GatewayClass, GatewayClassStatus)>,
    pub gateways: Vec<(Gateway, GatewayStatus)>,
    pub gateway_backends: Vec<(GatewayBackend, GatewayBackendStatus)>,
    pub backend_bindings: Vec<(BackendBinding, BackendBindingStatus)>,
    /// Desired statuses hold only our parent entries; routes with
    /// none desired and none observed are left out.
    pub http_routes: Vec<(HTTPRoute, HttpRouteStatus)>,
    /// Identifies our entries in `status.parents`.
    pub controller_name: String,
}

/// [`build`], with each desired status paired to a clone of the
/// observed object it was computed from.
pub fn build_work(resolution: &Resolution<'_>, now: &Time) -> StatusWork {
    StatusWork {
        gateway_classes: resolution
            .gateway_classes
            .iter()
            .map(|gc| ((*gc).clone(), gateway_class_status(gc, now)))
            .collect(),
        gateways: resolution
            .gateways
            .iter()
            .map(|g| (g.gateway.clone(), gateway_status(g, now)))
            .collect(),
        gateway_backends: resolution
            .gateway_backends
            .iter()
            .map(|b| (b.object.clone(), gateway_backend_status(b, now)))
            .collect(),
        backend_bindings: resolution
            .backend_bindings
            .iter()
            .map(|b| (b.object.clone(), backend_binding_status(b, now)))
            .collect(),
        http_routes: http_route_statuses(resolution, now)
            .into_iter()
            .filter(|(hr, desired)| {
                !desired.parents.is_empty() || has_parent_entry(hr, resolution.controller_name)
            })
            .map(|(hr, desired)| (hr.clone(), desired))
            .collect(),
        controller_name: resolution.controller_name.to_string(),
    }
}

/// Build the desired status for every owned object in `resolution`.
/// Every condition is stamped `now`; the reconcile step swaps in the
/// observed timestamp when a condition is unchanged.
pub fn build(resolution: &Resolution<'_>, now: &Time) -> StatusSet {
    StatusSet {
        gateway_classes: resolution
            .gateway_classes
            .iter()
            .filter_map(|gc| {
                let name = gc.metadata.name.clone()?;
                Some((name, gateway_class_status(gc, now)))
            })
            .collect(),
        gateways: resolution
            .gateways
            .iter()
            .map(|g| (g.id.clone(), gateway_status(g, now)))
            .collect(),
        gateway_backends: resolution
            .gateway_backends
            .iter()
            .map(|b| {
                (
                    (b.namespace.clone(), b.name.clone()),
                    gateway_backend_status(b, now),
                )
            })
            .collect(),
        backend_bindings: resolution
            .backend_bindings
            .iter()
            .map(|b| {
                (
                    (b.namespace.clone(), b.name.clone()),
                    backend_binding_status(b, now),
                )
            })
            .collect(),
        http_routes: http_route_statuses(resolution, now)
            .into_iter()
            .filter_map(|(hr, desired)| Some((route_id(hr)?, desired)))
            .collect(),
    }
}

/// Decide whether the class status needs a write: `Some(final)` with
/// carried-forward timestamps, or `None` when semantically equal.
pub fn reconcile_gateway_class_status(
    mut desired: GatewayClassStatus,
    observed: Option<&GatewayClassStatus>,
) -> Option<GatewayClassStatus> {
    if let Some(observed) = observed {
        carry_timestamps(
            desired.conditions.as_deref_mut().unwrap_or(&mut []),
            observed.conditions.as_deref().unwrap_or(&[]),
        );
        if *observed == desired {
            return None;
        }
    }
    Some(desired)
}

/// Decide whether the `GatewayBackend` status needs a write:
/// `Some(final)` with carried-forward timestamps, or `None` when
/// semantically equal.
pub fn reconcile_gateway_backend_status(
    mut desired: GatewayBackendStatus,
    observed: Option<&GatewayBackendStatus>,
) -> Option<GatewayBackendStatus> {
    if let Some(observed) = observed {
        carry_timestamps(&mut desired.conditions, &observed.conditions);
        if *observed == desired {
            return None;
        }
    }
    Some(desired)
}

/// Decide whether the `BackendBinding` status needs a write:
/// `Some(final)` with carried-forward timestamps, or `None` when
/// semantically equal.
pub fn reconcile_backend_binding_status(
    mut desired: BackendBindingStatus,
    observed: Option<&BackendBindingStatus>,
) -> Option<BackendBindingStatus> {
    if let Some(observed) = observed {
        carry_timestamps(&mut desired.conditions, &observed.conditions);
        if *observed == desired {
            return None;
        }
    }
    Some(desired)
}

/// Decide whether the Gateway status needs a write: `Some(final)`
/// with carried-forward timestamps (top-level and per listener by
/// name), or `None` when semantically equal.
pub fn reconcile_gateway_status(
    mut desired: GatewayStatus,
    observed: Option<&GatewayStatus>,
) -> Option<GatewayStatus> {
    if let Some(observed) = observed {
        carry_timestamps(
            desired.conditions.as_deref_mut().unwrap_or(&mut []),
            observed.conditions.as_deref().unwrap_or(&[]),
        );
        let observed_listeners = observed.listeners.as_deref().unwrap_or(&[]);
        for dl in desired.listeners.as_deref_mut().unwrap_or(&mut []) {
            if let Some(ol) = observed_listeners.iter().find(|o| o.name == dl.name) {
                carry_timestamps(&mut dl.conditions, &ol.conditions);
            }
        }
        if *observed == desired {
            return None;
        }
    }
    Some(desired)
}

/// Merge our desired parent entries into the observed route status:
/// entries of other controllers are kept as they are, ours are
/// replaced, and ours for parents no longer desired are dropped.
/// `None` when our entries are semantically unchanged, whatever
/// their order.
pub fn reconcile_http_route_status(
    desired: HttpRouteStatus,
    observed: Option<&HttpRouteStatus>,
    controller_name: &str,
) -> Option<HttpRouteStatus> {
    let observed = observed.map_or(&[][..], |o| o.parents.as_slice());
    let observed_ours: Vec<&HttpRouteStatusParents> = observed
        .iter()
        .filter(|o| o.controller_name == controller_name)
        .collect();

    let mut ours = desired.parents;
    for d in &mut ours {
        if let Some(o) = observed_ours.iter().find(|o| o.parent_ref == d.parent_ref) {
            carry_timestamps(&mut d.conditions, &o.conditions);
        }
    }
    if ours.len() == observed_ours.len() && ours.iter().all(|d| observed_ours.contains(&d)) {
        return None;
    }

    let mut parents: Vec<HttpRouteStatusParents> = observed
        .iter()
        .filter(|o| o.controller_name != controller_name)
        .cloned()
        .collect();
    parents.extend(ours);
    Some(HttpRouteStatus { parents })
}

fn gateway_class_status(gc: &GatewayClass, now: &Time) -> GatewayClassStatus {
    GatewayClassStatus {
        conditions: Some(vec![condition(
            "Accepted",
            true,
            "Accepted",
            "accepted by this controller",
            gc.metadata.generation,
            now,
        )]),
        supported_features: None,
    }
}

fn gateway_status(g: &GatewayResolution<'_>, now: &Time) -> GatewayStatus {
    let generation = g.gateway.metadata.generation;

    let addresses: Vec<GatewayStatusAddresses> = g
        .addresses
        .iter()
        .map(|a| GatewayStatusAddresses {
            r#type: Some(
                match a.kind {
                    AddressKind::Ip => "IPAddress",
                    AddressKind::Hostname => "Hostname",
                }
                .to_string(),
            ),
            value: a.value.clone(),
        })
        .collect();

    let listeners: Vec<GatewayStatusListeners> = g
        .listeners
        .iter()
        .map(|lr| listener_status(lr, generation, now))
        .collect();

    let programmed_count = g
        .listeners
        .iter()
        .filter(|l| l.outcome.is_accepted())
        .count();
    let programmed = if programmed_count > 0 {
        (
            true,
            "Programmed",
            format!("{programmed_count} listener(s) programmed"),
        )
    } else {
        (false, "Invalid", "no listener is programmed".to_string())
    };

    GatewayStatus {
        addresses: Some(addresses),
        attached_listener_sets: None,
        conditions: Some(vec![
            condition(
                "Accepted",
                true,
                "Accepted",
                "gateway is accepted",
                generation,
                now,
            ),
            condition(
                "Programmed",
                programmed.0,
                programmed.1,
                &programmed.2,
                generation,
                now,
            ),
        ]),
        listeners: Some(listeners),
    }
}

/// Two conditions, and they answer different questions.
///
/// `Accepted` is about the object: can this spec name a destination
/// at all. `ResolvedRefs` is about what it points at: is every
/// Secret it names there, with the data key it asked for. The split
/// matters because the second one is the failure an operator hits
/// while everything else is right — a rotated Secret, a mistyped
/// data key — and it is the one that has to say what is wrong
/// without printing what is missing.
fn gateway_backend_status(br: &GatewayBackendResolution<'_>, now: &Time) -> GatewayBackendStatus {
    let generation = br.object.metadata.generation;
    let (accepted, resolved_refs) = match &br.outcome {
        GatewayBackendOutcome::Invalid { reason, message } => (
            (false, *reason, message.clone()),
            // Nothing was looked up, so nothing is claimed about the
            // references either.
            (
                false,
                "InvalidBackend",
                "backend is not accepted".to_string(),
            ),
        ),
        GatewayBackendOutcome::Resolved(resolved) => (
            (true, "Accepted", "backend is accepted".to_string()),
            resolved_refs_condition(resolved),
        ),
    };

    GatewayBackendStatus {
        conditions: vec![
            condition(
                "Accepted",
                accepted.0,
                accepted.1,
                &accepted.2,
                generation,
                now,
            ),
            condition(
                "ResolvedRefs",
                resolved_refs.0,
                resolved_refs.1,
                &resolved_refs.2,
                generation,
                now,
            ),
        ],
    }
}

/// One condition, `Accepted`: can this spec stand in for a claimed
/// ref, and is it the claim's only claimant. Whether the targets it
/// names exist is decided where they are resolved and not reported
/// here yet.
fn backend_binding_status(bb: &BackendBindingResolution<'_>, now: &Time) -> BackendBindingStatus {
    let generation = bb.object.metadata.generation;
    let (ok, reason, message) = match &bb.outcome {
        BackendBindingOutcome::Accepted { .. } => {
            (true, "Accepted", "binding is accepted".to_string())
        }
        BackendBindingOutcome::Conflicted { message } => (false, "Conflicted", message.clone()),
        BackendBindingOutcome::Invalid { reason, message } => (false, *reason, message.clone()),
    };
    BackendBindingStatus {
        conditions: vec![condition("Accepted", ok, reason, &message, generation, now)],
    }
}

/// Every reference a resolved backend makes, in one condition. The
/// message names the reference, never its contents.
fn resolved_refs_condition(resolved: &ResolvedDialable<'_>) -> (bool, &'static str, String) {
    let mut unresolved: Vec<String> = Vec::new();
    if let Some(ca) = resolved.tls.as_ref().and_then(|tls| tls.ca.as_ref())
        && ca.secret.is_none()
    {
        unresolved.push(format!(
            "trust roots {}/{} are not present or carry no certificate",
            ca.namespace, ca.name
        ));
    }
    if let Some(credential) = resolved.auth.as_ref().map(ResolvedBackendAuth::credential) {
        match credential.outcome {
            CredentialOutcome::Present(_) => {}
            CredentialOutcome::SecretMissing => unresolved.push(format!(
                "credential Secret {}/{} is not present",
                credential.namespace, credential.name
            )),
            CredentialOutcome::KeyMissing => unresolved.push(format!(
                "credential Secret {}/{} carries no key `{}`",
                credential.namespace, credential.name, credential.key
            )),
        }
    }
    if unresolved.is_empty() {
        (true, "ResolvedRefs", "all references resolved".to_string())
    } else {
        (false, "InvalidRef", unresolved.join("; "))
    }
}

/// Every route paired with our desired parent entries, one per
/// parentRef naming an owned Gateway, in spec order.
fn http_route_statuses<'a>(
    resolution: &Resolution<'a>,
    now: &Time,
) -> Vec<(&'a HTTPRoute, HttpRouteStatus)> {
    let mut by_route: HashMap<(&str, &str), Vec<HttpRouteStatusParents>> = HashMap::new();
    for rr in resolution
        .routes
        .iter()
        .filter(|rr| rr.gateway_id.is_some())
    {
        by_route
            .entry((rr.route_ns, rr.route_name))
            .or_default()
            .push(route_parent_status(rr, resolution.controller_name, now));
    }
    resolution
        .http_routes
        .iter()
        .map(|hr| {
            let key = (
                hr.metadata.namespace.as_deref().unwrap_or_default(),
                hr.metadata.name.as_deref().unwrap_or_default(),
            );
            let parents = by_route.remove(&key).unwrap_or_default();
            (*hr, HttpRouteStatus { parents })
        })
        .collect()
}

fn route_id(hr: &HTTPRoute) -> Option<GatewayId> {
    Some((hr.metadata.namespace.clone()?, hr.metadata.name.clone()?))
}

fn has_parent_entry(hr: &HTTPRoute, controller_name: &str) -> bool {
    hr.status.as_ref().is_some_and(|s| {
        s.parents
            .iter()
            .any(|p| p.controller_name == controller_name)
    })
}

fn route_parent_status(
    rr: &RouteResolution<'_>,
    controller_name: &str,
    now: &Time,
) -> HttpRouteStatusParents {
    let generation = rr.route.metadata.generation;
    let gateway = rr
        .gateway_id
        .as_ref()
        .map_or_else(String::new, |(ns, name)| format!("{ns}/{name}"));
    let accepted = match rr.outcome {
        RouteParentOutcome::Accepted => (true, "Accepted", "route is accepted".to_string()),
        RouteParentOutcome::NoMatchingParent => (
            false,
            "NoMatchingParent",
            match rr.parent_ref.section_name.as_deref() {
                Some(section) => {
                    format!("gateway {gateway} has no accepted listener named {section:?}")
                }
                None => format!("gateway {gateway} has no accepted listener"),
            },
        ),
        RouteParentOutcome::NoMatchingListenerHostname => (
            false,
            "NoMatchingListenerHostname",
            format!(
                "route hostnames [{}] match no listener hostname on gateway {gateway}",
                rr.route.spec.hostnames.as_deref().unwrap_or(&[]).join(", ")
            ),
        ),
    };
    let resolved_refs = route_resolved_refs(rr);

    let p = rr.parent_ref;
    HttpRouteStatusParents {
        conditions: vec![
            condition(
                "Accepted",
                accepted.0,
                accepted.1,
                &accepted.2,
                generation,
                now,
            ),
            condition(
                "ResolvedRefs",
                resolved_refs.0,
                resolved_refs.1,
                &resolved_refs.2,
                generation,
                now,
            ),
        ],
        controller_name: controller_name.to_string(),
        parent_ref: HttpRouteStatusParentsParentRef {
            group: p.group.clone(),
            kind: p.kind.clone(),
            name: p.name.clone(),
            namespace: p.namespace.clone(),
            port: p.port,
            section_name: p.section_name.clone(),
        },
    }
}

/// `ResolvedRefs` over every rule's backendRefs: the first failure's
/// reason, and a message listing each distinct failure.
fn route_resolved_refs(rr: &RouteResolution<'_>) -> (bool, &'static str, String) {
    let mut reason = None;
    let mut failures: Vec<String> = Vec::new();
    for (i, backends) in rr.rule_backends.iter().enumerate() {
        for b in backends {
            let Some((r, what)) = backend_failure(b, rr.route_ns) else {
                continue;
            };
            let line = format!("rules[{i}]: {what}");
            if !failures.contains(&line) {
                reason.get_or_insert(r);
                failures.push(line);
            }
        }
    }
    let Some(reason) = reason else {
        return (true, "ResolvedRefs", "all references resolved".to_string());
    };
    let more = failures.len().saturating_sub(MAX_LISTED_REFS);
    failures.truncate(MAX_LISTED_REFS);
    let mut message = failures.join("; ");
    if more > 0 {
        let _ = write!(message, "; and {more} more");
    }
    (false, reason, message)
}

/// The `ResolvedRefs` reason and message for one backendRef that the
/// data plane cannot reach as written. `UnsupportedValue` covers the
/// port rules, for which the API defines no reason.
fn backend_failure(b: &BackendResolution<'_>, route_ns: &str) -> Option<(&'static str, String)> {
    let r = b.backend_ref;
    let spec_ref = format!("{}/{}", r.namespace.as_deref().unwrap_or(route_ns), r.name);
    Some(match &b.outcome {
        BackendOutcome::Resolved { .. } | BackendOutcome::Dialable { .. } => return None,
        BackendOutcome::MissingService { key } => {
            ("BackendNotFound", format!("Service {key} not found"))
        }
        BackendOutcome::Headless { key } => (
            "BackendNotFound",
            format!("Service {key} has no cluster IP"),
        ),
        BackendOutcome::MissingDialable { key } => {
            ("BackendNotFound", format!("GatewayBackend {key} not found"))
        }
        BackendOutcome::CrossNamespace => (
            "RefNotPermitted",
            format!("cross-namespace backendRef {spec_ref} is not permitted"),
        ),
        BackendOutcome::NoPort => (
            "UnsupportedValue",
            format!("Service backendRef {spec_ref} has no port"),
        ),
        BackendOutcome::PortNotAllowed => (
            "UnsupportedValue",
            format!("GatewayBackend backendRef {spec_ref} must not set a port"),
        ),
        // Also reached when the only claimants conflict: none is accepted.
        BackendOutcome::UnsupportedKind { .. } => (
            "InvalidKind",
            format!(
                "{}/{} backendRef {spec_ref} is not claimed by any accepted BackendBinding",
                r.group.as_deref().unwrap_or(""),
                r.kind.as_deref().unwrap_or("Service")
            ),
        ),
    })
}

fn listener_status(
    lr: &ListenerResolution<'_>,
    generation: Option<i64>,
    now: &Time,
) -> GatewayStatusListeners {
    let (accepted, conflicted) = match lr.outcome {
        ListenerOutcome::Accepted { .. } => (
            (true, "Accepted", "listener is accepted".to_string()),
            (false, "NoConflicts", "no conflicts".to_string()),
        ),
        ListenerOutcome::UnsupportedProtocol => (
            (
                false,
                "UnsupportedProtocol",
                format!("protocol {} is not supported", lr.listener.protocol),
            ),
            (false, "NoConflicts", "no conflicts".to_string()),
        ),
        ListenerOutcome::ProtocolConflict => (
            (
                false,
                "ProtocolConflict",
                "protocol conflicts with another listener on the port".to_string(),
            ),
            (
                true,
                "ProtocolConflict",
                "protocol conflicts with another listener on the port".to_string(),
            ),
        ),
        ListenerOutcome::HostnameConflict => (
            (
                false,
                "HostnameConflict",
                "hostname conflicts with another listener on the port".to_string(),
            ),
            (
                true,
                "HostnameConflict",
                "hostname conflicts with another listener on the port".to_string(),
            ),
        ),
    };

    let unresolved =
        lr.cert_refs.iter().filter(|c| c.secret.is_none()).count() + lr.rejected_cert_refs as usize;
    let resolved_refs = if unresolved > 0 {
        (
            false,
            "InvalidCertificateRef",
            format!("{unresolved} certificateRef(s) invalid or not found"),
        )
    } else {
        (true, "ResolvedRefs", "all references resolved".to_string())
    };

    let programmed = if lr.outcome.is_accepted() {
        (true, "Programmed", "listener is programmed".to_string())
    } else {
        (false, "Invalid", "listener is not accepted".to_string())
    };

    GatewayStatusListeners {
        name: lr.listener.name.clone(),
        attached_routes: i32::try_from(lr.attached_routes).unwrap_or(i32::MAX),
        supported_kinds: Some(vec![GatewayStatusListenersSupportedKinds {
            group: Some("gateway.networking.k8s.io".to_string()),
            kind: "HTTPRoute".to_string(),
        }]),
        conditions: vec![
            condition(
                "Accepted",
                accepted.0,
                accepted.1,
                &accepted.2,
                generation,
                now,
            ),
            condition(
                "Programmed",
                programmed.0,
                programmed.1,
                &programmed.2,
                generation,
                now,
            ),
            condition(
                "ResolvedRefs",
                resolved_refs.0,
                resolved_refs.1,
                &resolved_refs.2,
                generation,
                now,
            ),
            condition(
                "Conflicted",
                conflicted.0,
                conflicted.1,
                &conflicted.2,
                generation,
                now,
            ),
        ],
    }
}

/// For each desired condition, keep the observed transition time
/// while its status is unchanged: `lastTransitionTime` marks a status
/// flip, not a new reason, message or generation.
fn carry_timestamps(desired: &mut [Condition], observed: &[Condition]) {
    for d in desired {
        if let Some(o) = observed.iter().find(|o| o.type_ == d.type_)
            && o.status == d.status
        {
            d.last_transition_time = o.last_transition_time.clone();
        }
    }
}

fn condition(
    type_: &str,
    ok: bool,
    reason: &str,
    message: &str,
    generation: Option<i64>,
    now: &Time,
) -> Condition {
    Condition {
        type_: type_.to_string(),
        status: if ok { "True" } else { "False" }.to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        observed_generation: generation,
        last_transition_time: now.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_api::apis::standard::gatewayclasses::GatewayClassSpec;
    use gateway_api::apis::standard::gateways::{Gateway, GatewayListeners, GatewaySpec};
    use gateway_api::apis::standard::httproutes::{
        HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs, HttpRouteSpec,
    };
    use k8s_openapi::ByteString;
    use k8s_openapi::api::core::v1::{Secret, Service, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};

    use crate::resolve::resolve;
    use crate::translator::K8sState;

    const OURS: &str = "gateway.buoyant.io/controller";

    fn t(secs: i64) -> Time {
        Time(k8s_openapi::jiff::Timestamp::from_second(secs).unwrap())
    }

    fn fixture_state() -> K8sState {
        let gc = gateway_api::apis::standard::gatewayclasses::GatewayClass {
            metadata: ObjectMeta {
                name: Some("zd".into()),
                generation: Some(3),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: OURS.into(),
                ..Default::default()
            },
            status: None,
        };
        let gw = Gateway {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some("gw".into()),
                uid: Some("uid-1".into()),
                generation: Some(7),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "zd".into(),
                listeners: vec![
                    GatewayListeners {
                        name: "http".into(),
                        protocol: "HTTP".into(),
                        port: 80,
                        ..Default::default()
                    },
                    GatewayListeners {
                        name: "tcp".into(),
                        protocol: "TCP".into(),
                        port: 9000,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
            status: None,
        };
        let route = HTTPRoute {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some("r".into()),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(vec![HttpRouteParentRefs {
                    name: "gw".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            status: None,
        };
        let managed_service = Service {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some("gw-gatewayd".into()),
                labels: Some(
                    [
                        (
                            "app.kubernetes.io/managed-by".to_string(),
                            "gateway.buoyant.io".to_string(),
                        ),
                        (
                            "gateway.networking.k8s.io/gateway-name".to_string(),
                            "gw".to_string(),
                        ),
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
                cluster_ips: Some(vec!["10.96.0.10".into()]),
                ..Default::default()
            }),
            status: None,
        };
        K8sState {
            gateway_classes: vec![gc],
            gateways: vec![gw],
            http_routes: vec![route],
            services: vec![managed_service],
            ..Default::default()
        }
    }

    fn find<'a>(conditions: &'a [Condition], type_: &str) -> &'a Condition {
        conditions
            .iter()
            .find(|c| c.type_ == type_)
            .unwrap_or_else(|| panic!("condition {type_} missing"))
    }

    #[test]
    fn healthy_gateway_and_class_status_shape() {
        let state = fixture_state();
        let resolution = resolve(&state, OURS);
        let set = build(&resolution, &t(100));

        let (name, class_status) = &set.gateway_classes[0];
        assert_eq!(name, "zd");
        let accepted = find(class_status.conditions.as_deref().unwrap(), "Accepted");
        assert_eq!(accepted.status, "True");
        assert_eq!(accepted.observed_generation, Some(3));

        let (id, status) = &set.gateways[0];
        assert_eq!(id, &("demo".to_string(), "gw".to_string()));
        assert_eq!(
            status.addresses.as_deref().unwrap(),
            &[GatewayStatusAddresses {
                r#type: Some("IPAddress".into()),
                value: "10.96.0.10".into(),
            }]
        );

        let conditions = status.conditions.as_deref().unwrap();
        assert_eq!(find(conditions, "Accepted").status, "True");
        let programmed = find(conditions, "Programmed");
        assert_eq!(programmed.status, "True");
        assert_eq!(programmed.observed_generation, Some(7));

        let listeners = status.listeners.as_deref().unwrap();
        assert_eq!(listeners.len(), 2, "every spec listener gets an entry");

        let http = &listeners[0];
        assert_eq!(http.name, "http");
        assert_eq!(http.attached_routes, 1);
        assert_eq!(find(&http.conditions, "Accepted").status, "True");
        assert_eq!(find(&http.conditions, "ResolvedRefs").status, "True");
        assert_eq!(find(&http.conditions, "Conflicted").status, "False");
        assert_eq!(
            http.supported_kinds.as_deref().unwrap()[0].kind,
            "HTTPRoute"
        );

        let tcp = &listeners[1];
        assert_eq!(
            tcp.attached_routes, 1,
            "attachment ignores listener validity"
        );
        let accepted = find(&tcp.conditions, "Accepted");
        assert_eq!(accepted.status, "False");
        assert_eq!(accepted.reason, "UnsupportedProtocol");
        assert_eq!(find(&tcp.conditions, "Programmed").status, "False");
    }

    #[test]
    fn gateway_without_programmable_listeners_is_not_programmed() {
        let mut state = fixture_state();
        state.gateways[0].spec.listeners.remove(0); // only the TCP listener remains
        let resolution = resolve(&state, OURS);
        let set = build(&resolution, &t(100));

        let (_, status) = &set.gateways[0];
        let programmed = find(status.conditions.as_deref().unwrap(), "Programmed");
        assert_eq!(programmed.status, "False");
        assert_eq!(programmed.reason, "Invalid");
    }

    #[test]
    fn reconcile_skips_when_equal_and_writes_when_fresh() {
        let state = fixture_state();
        let resolution = resolve(&state, OURS);

        // Same content, different clocks: no write.
        let observed = build(&resolution, &t(100)).gateways.remove(0).1;
        let desired = build(&resolution, &t(200)).gateways.remove(0).1;
        assert_eq!(reconcile_gateway_status(desired, Some(&observed)), None);

        let observed_class = build(&resolution, &t(100)).gateway_classes.remove(0).1;
        let desired_class = build(&resolution, &t(200)).gateway_classes.remove(0).1;
        assert_eq!(
            reconcile_gateway_class_status(desired_class, Some(&observed_class)),
            None
        );

        // Nothing observed at all: the first write goes out as built.
        let desired = build(&resolution, &t(100)).gateways.remove(0).1;
        let written = reconcile_gateway_status(desired.clone(), None).expect("first write");
        assert_eq!(written, desired);
    }

    #[test]
    fn reconcile_stamps_changes_and_carries_the_rest() {
        let state = fixture_state();
        let resolution = resolve(&state, OURS);
        let observed = build(&resolution, &t(100)).gateways.remove(0).1;

        // The gateway's route count changes: listener conditions are
        // unchanged (carry t=100), the listener entry differs so a
        // write happens.
        let mut changed_state = fixture_state();
        changed_state.http_routes.clear();
        let changed_resolution = resolve(&changed_state, OURS);
        let desired = build(&changed_resolution, &t(200)).gateways.remove(0).1;

        let written =
            reconcile_gateway_status(desired, Some(&observed)).expect("count change writes");
        let listeners = written.listeners.as_deref().unwrap();
        assert_eq!(listeners[0].attached_routes, 0);
        assert_eq!(
            find(&listeners[0].conditions, "Accepted").last_transition_time,
            t(100),
            "unchanged condition keeps its transition time"
        );
        assert_eq!(
            find(written.conditions.as_deref().unwrap(), "Programmed").last_transition_time,
            t(100)
        );
    }

    #[test]
    fn transition_time_moves_only_when_status_flips() {
        let observed = [
            condition(
                "Programmed",
                true,
                "Programmed",
                "1 programmed",
                Some(1),
                &t(100),
            ),
            condition("Accepted", true, "Accepted", "ok", Some(1), &t(100)),
        ];
        let mut desired = [
            condition(
                "Programmed",
                true,
                "Programmed",
                "2 programmed",
                Some(2),
                &t(200),
            ),
            condition("Accepted", false, "Invalid", "ok", Some(2), &t(200)),
        ];
        carry_timestamps(&mut desired, &observed);
        assert_eq!(desired[0].last_transition_time, t(100));
        assert_eq!(desired[1].last_transition_time, t(200));
    }

    // ---------- GatewayBackend ----------

    fn backend_object(ns: &str, name: &str, base_url: &str) -> GatewayBackend {
        GatewayBackend {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                generation: Some(4),
                ..Default::default()
            },
            spec: crate::crd::GatewayBackendSpec {
                base_url: base_url.into(),
                tls: None,
                auth: None,
            },
            status: None,
        }
    }

    fn api_key(secret: &str, key: &str) -> crate::crd::BackendAuth {
        crate::crd::BackendAuth {
            r#type: crate::crd::BackendAuthType::ApiKey,
            api_key: Some(crate::crd::ApiKeyAuth {
                secret_ref: crate::crd::SecretKeyReference {
                    name: secret.into(),
                    key: key.into(),
                },
                header: None,
                prefix: None,
            }),
            oauth2: None,
        }
    }

    fn backend_status(state: &K8sState) -> GatewayBackendStatus {
        let resolution = resolve(state, OURS);
        build(&resolution, &t(100)).gateway_backends.remove(0).1
    }

    #[test]
    fn a_resolved_backend_is_accepted_with_its_refs() {
        let mut state = fixture_state();
        state.gateway_backends = vec![backend_object(
            "demo",
            "provider",
            "https://api.example.com",
        )];

        let status = backend_status(&state);
        let accepted = find(&status.conditions, "Accepted");
        assert_eq!(accepted.status, "True");
        assert_eq!(accepted.observed_generation, Some(4));
        assert_eq!(find(&status.conditions, "ResolvedRefs").status, "True");
    }

    #[test]
    fn an_unusable_spec_is_not_accepted_and_claims_nothing_about_refs() {
        let mut state = fixture_state();
        state.gateway_backends = vec![backend_object("demo", "provider", "api.example.com")];

        let status = backend_status(&state);
        let accepted = find(&status.conditions, "Accepted");
        assert_eq!(accepted.status, "False");
        assert_eq!(accepted.reason, "InvalidBaseURL");
        assert!(accepted.message.contains("baseURL"));
        assert_eq!(find(&status.conditions, "ResolvedRefs").status, "False");
    }

    /// The acceptance criterion of the issue this landed with: break
    /// the secret and the status says so, in a message that names the
    /// reference and never its contents.
    #[test]
    fn a_broken_credential_shows_up_as_resolved_refs_false() {
        let mut state = fixture_state();
        let mut object = backend_object("demo", "provider", "https://api.example.com");
        object.spec.auth = Some(api_key("provider-key", "apiKey"));
        state.gateway_backends = vec![object];

        // No Secret at all.
        let status = backend_status(&state);
        assert_eq!(find(&status.conditions, "Accepted").status, "True");
        let refs = find(&status.conditions, "ResolvedRefs");
        assert_eq!(refs.status, "False");
        assert_eq!(refs.reason, "InvalidRef");
        assert!(refs.message.contains("demo/provider-key"));

        // Present, wrong data key.
        state.secrets = vec![Secret {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some("provider-key".into()),
                ..Default::default()
            },
            data: Some(
                [("apikey".to_string(), ByteString(b"s3cr3t".to_vec()))]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        }];
        let status = backend_status(&state);
        let refs = find(&status.conditions, "ResolvedRefs");
        assert_eq!(refs.status, "False");
        assert!(
            refs.message.contains("carries no key `apiKey`"),
            "the message names the key: {}",
            refs.message
        );
        assert!(
            !refs.message.contains("s3cr3t"),
            "and never the material: {}",
            refs.message
        );
    }

    #[test]
    fn an_unchanged_backend_status_is_not_rewritten() {
        let mut state = fixture_state();
        state.gateway_backends = vec![backend_object(
            "demo",
            "provider",
            "https://api.example.com",
        )];
        let observed = backend_status(&state);

        let resolution = resolve(&state, OURS);
        let desired = build(&resolution, &t(200)).gateway_backends.remove(0).1;
        assert!(
            reconcile_gateway_backend_status(desired, Some(&observed)).is_none(),
            "a later clock alone must not produce a write"
        );
    }

    fn binding_object(refs: Vec<crate::crd::BindingBackendRef>) -> crate::crd::BackendBinding {
        crate::crd::BackendBinding {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some("pool".into()),
                generation: Some(5),
                ..Default::default()
            },
            spec: crate::crd::BackendBindingSpec {
                claim: crate::crd::Claim {
                    group: "kinference.buoyant.io".into(),
                    kind: "InferencePool".into(),
                    name: "pool".into(),
                },
                backend_refs: refs,
                extensions: Vec::new(),
            },
            status: None,
        }
    }

    fn service_binding_ref() -> crate::crd::BindingBackendRef {
        crate::crd::BindingBackendRef {
            name: "workers".into(),
            target: crate::crd::BindingObjectReference {
                namespace: None,
                group: None,
                kind: None,
                name: "workers-svc".into(),
                port: Some(8000),
            },
        }
    }

    fn binding_status(state: &K8sState) -> crate::crd::BackendBindingStatus {
        let resolution = resolve(state, OURS);
        build(&resolution, &t(100)).backend_bindings.remove(0).1
    }

    #[test]
    fn a_valid_binding_is_accepted() {
        let mut state = fixture_state();
        state.backend_bindings = vec![binding_object(vec![service_binding_ref()])];

        let status = binding_status(&state);
        let accepted = find(&status.conditions, "Accepted");
        assert_eq!(accepted.status, "True");
        assert_eq!(accepted.observed_generation, Some(5));
        assert_eq!(status.conditions.len(), 1, "no ResolvedRefs is claimed");
    }

    #[test]
    fn each_binding_malformation_has_its_own_reason() {
        let mut foreign = service_binding_ref();
        foreign.target.group = Some("kinference.buoyant.io".into());
        foreign.target.kind = Some("InferencePool".into());
        let mut no_claim = binding_object(vec![service_binding_ref()]);
        no_claim.spec.claim.group = String::new();

        for (object, reason) in [
            (no_claim, "InvalidClaim"),
            (binding_object(vec![]), "NoBackendRefs"),
            (binding_object(vec![foreign]), "InvalidBackendRef"),
        ] {
            let mut state = fixture_state();
            state.backend_bindings = vec![object];
            let status = binding_status(&state);
            let accepted = find(&status.conditions, "Accepted");
            assert_eq!(accepted.status, "False");
            assert_eq!(accepted.reason, reason);
        }
    }

    #[test]
    fn an_unchanged_binding_status_is_not_rewritten() {
        let mut state = fixture_state();
        state.backend_bindings = vec![binding_object(vec![service_binding_ref()])];
        let observed = binding_status(&state);

        let resolution = resolve(&state, OURS);
        let desired = build(&resolution, &t(200)).backend_bindings.remove(0).1;
        assert!(
            reconcile_backend_binding_status(desired, Some(&observed)).is_none(),
            "a later clock alone must not produce a write"
        );
    }

    #[test]
    fn a_conflicted_binding_is_not_accepted() {
        let mut rival = binding_object(vec![service_binding_ref()]);
        rival.metadata.name = Some("rival".into());
        let mut state = fixture_state();
        state.backend_bindings = vec![binding_object(vec![service_binding_ref()]), rival];

        let status = binding_status(&state);
        let accepted = find(&status.conditions, "Accepted");
        assert_eq!(accepted.status, "False");
        assert_eq!(accepted.reason, "Conflicted");
        assert!(
            accepted.message.contains("demo/rival"),
            "the message names the other claimant: {}",
            accepted.message
        );
    }

    // ---------- HTTPRoute ----------

    fn backend_ref(name: &str, port: Option<i32>) -> HttpRouteRulesBackendRefs {
        HttpRouteRulesBackendRefs {
            name: name.into(),
            port,
            ..Default::default()
        }
    }

    fn echo_service() -> Service {
        Service {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some("echo".into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: Some("10.96.0.20".into()),
                ..Default::default()
            }),
            status: None,
        }
    }

    /// The fixture with route `r` sending its one rule to `refs`.
    fn route_state(refs: Vec<HttpRouteRulesBackendRefs>) -> K8sState {
        let mut state = fixture_state();
        state.services.push(echo_service());
        state.http_routes[0].metadata.generation = Some(2);
        state.http_routes[0].spec.rules = Some(vec![HttpRouteRules {
            backend_refs: Some(refs),
            ..Default::default()
        }]);
        state
    }

    fn route_status(state: &K8sState) -> HttpRouteStatus {
        let resolution = resolve(state, OURS);
        build(&resolution, &t(100)).http_routes.remove(0).1
    }

    fn foreign_entry() -> HttpRouteStatusParents {
        HttpRouteStatusParents {
            conditions: vec![condition(
                "Accepted",
                true,
                "Accepted",
                "theirs",
                Some(1),
                &t(1),
            )],
            controller_name: "other.io/controller".into(),
            parent_ref: HttpRouteStatusParentsParentRef {
                name: "their-gw".into(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn an_attached_route_is_accepted_with_resolved_refs() {
        let state = route_state(vec![backend_ref("echo", Some(8080))]);
        let status = route_status(&state);

        assert_eq!(status.parents.len(), 1);
        let entry = &status.parents[0];
        assert_eq!(entry.controller_name, OURS);
        assert_eq!(entry.parent_ref.name, "gw");
        let accepted = find(&entry.conditions, "Accepted");
        assert_eq!(accepted.status, "True");
        assert_eq!(accepted.observed_generation, Some(2));
        assert_eq!(find(&entry.conditions, "ResolvedRefs").status, "True");
    }

    #[test]
    fn a_parent_ref_to_a_gateway_we_do_not_own_gets_no_entry() {
        let mut state = route_state(vec![backend_ref("echo", Some(8080))]);
        state.http_routes[0].spec.parent_refs.as_mut().unwrap()[0].name = "elsewhere".into();
        let parents = route_status(&state).parents;
        assert!(parents.is_empty(), "{parents:?}");
    }

    #[test]
    fn an_unmatched_section_name_is_no_matching_parent() {
        let mut state = route_state(vec![backend_ref("echo", Some(8080))]);
        state.http_routes[0].spec.parent_refs.as_mut().unwrap()[0].section_name =
            Some("https".into());

        let status = route_status(&state);
        let entry = &status.parents[0];
        assert_eq!(entry.parent_ref.section_name.as_deref(), Some("https"));
        let accepted = find(&entry.conditions, "Accepted");
        assert_eq!(accepted.status, "False");
        assert_eq!(accepted.reason, "NoMatchingParent");
        assert!(
            accepted.message.contains("\"https\""),
            "{}",
            accepted.message
        );
    }

    #[test]
    fn disjoint_hostnames_are_no_matching_listener_hostname() {
        let mut state = route_state(vec![backend_ref("echo", Some(8080))]);
        state.gateways[0].spec.listeners[0].hostname = Some("a.example".into());
        state.http_routes[0].spec.hostnames = Some(vec!["b.example".into()]);

        let status = route_status(&state);
        let accepted = find(&status.parents[0].conditions, "Accepted");
        assert_eq!(accepted.status, "False");
        assert_eq!(accepted.reason, "NoMatchingListenerHostname");
        assert!(
            accepted.message.contains("b.example"),
            "{}",
            accepted.message
        );
    }

    #[test]
    fn each_unresolved_backend_ref_has_its_reason() {
        let mut headless = echo_service();
        headless.metadata.name = Some("headless".into());
        headless.spec.as_mut().unwrap().cluster_ip = Some("None".into());
        let gateway_backend = |port| HttpRouteRulesBackendRefs {
            group: Some("gateway.linkerd.io".into()),
            kind: Some("GatewayBackend".into()),
            ..backend_ref("missing", port)
        };

        for (backend, reason, mentions) in [
            (
                backend_ref("gone", Some(8080)),
                "BackendNotFound",
                "demo/gone:8080",
            ),
            (
                backend_ref("headless", Some(8080)),
                "BackendNotFound",
                "cluster IP",
            ),
            (
                gateway_backend(None),
                "BackendNotFound",
                "GatewayBackend demo/missing",
            ),
            (
                HttpRouteRulesBackendRefs {
                    namespace: Some("other".into()),
                    ..backend_ref("echo", Some(8080))
                },
                "RefNotPermitted",
                "other/echo",
            ),
            (backend_ref("echo", None), "UnsupportedValue", "no port"),
            (
                gateway_backend(Some(443)),
                "UnsupportedValue",
                "must not set a port",
            ),
            (
                HttpRouteRulesBackendRefs {
                    group: Some("example.io".into()),
                    kind: Some("Pool".into()),
                    ..backend_ref("pool", None)
                },
                "InvalidKind",
                "example.io/Pool backendRef demo/pool is not claimed",
            ),
        ] {
            let mut state = route_state(vec![backend]);
            state.services.push(headless.clone());
            let status = route_status(&state);
            let entry = &status.parents[0];
            assert_eq!(find(&entry.conditions, "Accepted").status, "True");
            let refs = find(&entry.conditions, "ResolvedRefs");
            assert_eq!(refs.status, "False");
            assert_eq!(refs.reason, reason, "{}", refs.message);
            assert!(refs.message.contains(mentions), "{}", refs.message);
        }
    }

    #[test]
    fn resolved_refs_lists_every_failure_under_the_first_reason() {
        let state = route_state(vec![
            backend_ref("echo", Some(8080)),
            backend_ref("gone", Some(8080)),
            backend_ref("echo", None),
        ]);
        let status = route_status(&state);
        let refs = find(&status.parents[0].conditions, "ResolvedRefs");
        assert_eq!(refs.reason, "BackendNotFound");
        assert_eq!(
            refs.message,
            "rules[0]: Service demo/gone:8080 not found; \
             rules[0]: Service backendRef demo/echo has no port"
        );
    }

    #[test]
    fn route_reconcile_keeps_foreign_entries_and_replaces_ours() {
        let state = route_state(vec![backend_ref("echo", Some(8080))]);
        let desired = route_status(&state);
        let mut old_entry = desired.parents[0].clone();
        old_entry.parent_ref.name = "old-gw".into();
        let observed = HttpRouteStatus {
            parents: vec![old_entry, foreign_entry()],
        };

        let written = reconcile_http_route_status(desired.clone(), Some(&observed), OURS)
            .expect("our entry changed");
        assert_eq!(
            written.parents,
            vec![foreign_entry(), desired.parents[0].clone()]
        );
    }

    #[test]
    fn route_reconcile_skips_unchanged_entries_in_any_order() {
        let state = route_state(vec![backend_ref("echo", Some(8080))]);
        let observed = HttpRouteStatus {
            parents: vec![route_status(&state).parents.remove(0), foreign_entry()],
        };
        let resolution = resolve(&state, OURS);
        let desired = build(&resolution, &t(200)).http_routes.remove(0).1;
        assert_eq!(
            reconcile_http_route_status(desired, Some(&observed), OURS),
            None
        );
    }

    #[test]
    fn work_clears_our_entry_from_a_detached_route_and_skips_unrelated_ones() {
        let mut state = route_state(vec![backend_ref("echo", Some(8080))]);
        state.http_routes[0].spec.parent_refs = None;
        let mut unrelated = state.http_routes[0].clone();
        unrelated.metadata.name = Some("unrelated".into());
        unrelated.status = Some(HttpRouteStatus {
            parents: vec![foreign_entry()],
        });
        let mut ours = foreign_entry();
        ours.controller_name = OURS.into();
        state.http_routes[0].status = Some(HttpRouteStatus {
            parents: vec![ours, foreign_entry()],
        });
        state.http_routes.push(unrelated);

        let resolution = resolve(&state, OURS);
        let work = build_work(&resolution, &t(100));
        assert_eq!(work.controller_name, OURS);
        assert_eq!(
            work.http_routes.len(),
            1,
            "the unrelated route is left alone"
        );
        let (observed, desired) = &work.http_routes[0];
        let written = reconcile_http_route_status(desired.clone(), observed.status.as_ref(), OURS)
            .expect("our stale entry is removed");
        assert_eq!(written.parents, vec![foreign_entry()]);
    }
}
