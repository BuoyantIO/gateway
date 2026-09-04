//! Desired status values from a [`Resolution`].
//!
//! Pure: [`build`] maps resolution outcomes onto the Gateway API
//! status types, and the `reconcile_*` functions decide whether a
//! write is needed — carrying `lastTransitionTime` forward for
//! semantically unchanged conditions so identical passes compare
//! equal. No API calls here; the writer task owns those. `now` is a
//! parameter so tests run on a fixed clock.

use gateway_api::apis::standard::gatewayclasses::{GatewayClass, GatewayClassStatus};
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayStatus, GatewayStatusAddresses, GatewayStatusListeners,
    GatewayStatusListenersSupportedKinds,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};

use crate::crd::{GatewayBackend, GatewayBackendStatus};
use crate::resolve::{
    AddressKind, CredentialOutcome, GatewayBackendOutcome, GatewayBackendResolution,
    GatewayResolution, ListenerOutcome, ListenerResolution, Resolution, ResolvedBackendAuth,
    ResolvedDialable,
};
use crate::snapshot::GatewayId;

/// Desired statuses for one pass, keyed by object identity.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusSet {
    /// `GatewayClass` name -> desired status.
    pub gateway_classes: Vec<(String, GatewayClassStatus)>,
    pub gateways: Vec<(GatewayId, GatewayStatus)>,
    /// `GatewayBackend` `(namespace, name)` -> desired status.
    pub gateway_backends: Vec<(GatewayId, GatewayBackendStatus)>,
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
/// when the condition is semantically unchanged (same type, status,
/// reason, message, observedGeneration); changed conditions keep the
/// fresh stamp.
fn carry_timestamps(desired: &mut [Condition], observed: &[Condition]) {
    for d in desired {
        if let Some(o) = observed.iter().find(|o| o.type_ == d.type_)
            && o.status == d.status
            && o.reason == d.reason
            && o.message == d.message
            && o.observed_generation == d.observed_generation
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
    use gateway_api::apis::standard::httproutes::{HTTPRoute, HttpRouteParentRefs, HttpRouteSpec};
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
}
