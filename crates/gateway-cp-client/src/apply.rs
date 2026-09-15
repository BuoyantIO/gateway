//! Apply a `ConfigUpdate` batch to `gateway_state::Store`. Pure
//! translation; no caching, no network.

use gateway_cp_proto::v1 as pb;
use gateway_state::{BackendKey, BindKey, ExtensionKey, ListenerKey, RouteKey, SecretKey, Store};

use crate::convert;
use crate::error::Error;

/// Keys touched by one [`apply_update`] call. The stream loop uses
/// it to maintain its known-set without re-walking the proto.
#[derive(Debug, Default, Clone)]
pub struct ApplyOutcome {
    pub upserted: Affected,
    pub removed: Affected,
}

#[derive(Debug, Default, Clone)]
pub struct Affected {
    pub binds: Vec<BindKey>,
    pub listeners: Vec<ListenerKey>,
    pub routes: Vec<RouteKey>,
    pub backends: Vec<BackendKey>,
    pub secrets: Vec<SecretKey>,
    pub extensions: Vec<ExtensionKey>,
}

/// Apply one batched `ConfigUpdate`. Upserts first, then removes.
///
/// # Errors
/// First conversion or Store error; remaining items in the batch are
/// skipped. The outcome reflects only what landed before the error.
pub fn apply_update(store: &Store, update: pb::ConfigUpdate) -> Result<ApplyOutcome, Error> {
    let mut outcome = ApplyOutcome::default();
    for upsert in update.upserts {
        apply_upsert(store, upsert, &mut outcome.upserted)?;
    }
    for remove in update.removes {
        apply_remove(store, remove, &mut outcome.removed);
    }
    Ok(outcome)
}

fn apply_upsert(store: &Store, upsert: pb::Upsert, out: &mut Affected) -> Result<(), Error> {
    let body = upsert.body.ok_or(Error::MissingField("Upsert.body"))?;
    match body {
        pb::upsert::Body::Bind(b) => {
            let bind = convert::bind(b)?;
            let key = BindKey::new(bind.name.clone());
            store.upsert_bind(bind)?;
            out.binds.push(key);
        }
        pb::upsert::Body::Listener(l) => {
            let (parent, listener) = convert::listener(l)?;
            let key = ListenerKey::new(parent.clone(), listener.name().to_string());
            store.upsert_listener(&parent, listener)?;
            out.listeners.push(key);
        }
        pb::upsert::Body::HttpRoute(r) => {
            let (parent, route) = convert::http_route(r)?;
            let key = RouteKey::new(parent.clone(), route.name.clone());
            store.upsert_http_route(&parent, route);
            out.routes.push(key);
        }
        pb::upsert::Body::Backend(b) => {
            let backend = convert::backend(b)?;
            let key = BackendKey::new(backend.name());
            store.upsert_backend(backend);
            out.backends.push(key);
        }
        pb::upsert::Body::Secret(s) => {
            let secret = convert::secret(s)?;
            let key = SecretKey::new(secret.namespace(), secret.name());
            store.upsert_secret(secret);
            out.secrets.push(key);
        }
        pb::upsert::Body::Extension(e) => {
            let ext = convert::extension(e)?;
            let key = ExtensionKey::new(ext.namespace.clone(), ext.name.clone());
            store.upsert_extension(ext);
            out.extensions.push(key);
        }
    }
    Ok(())
}

fn apply_remove(store: &Store, remove: pb::Remove, out: &mut Affected) {
    let Some(key) = remove.key else {
        tracing::warn!("Remove with no key field; skipping");
        return;
    };
    match key {
        pb::remove::Key::Bind(k) => {
            let k = convert::bind_key(k);
            store.remove_bind(&k);
            out.binds.push(k);
        }
        pb::remove::Key::Listener(k) => {
            let k = convert::listener_key(k);
            store.remove_listener(&k);
            out.listeners.push(k);
        }
        pb::remove::Key::HttpRoute(k) => {
            let k = convert::route_key(k);
            store.remove_http_route(&k);
            out.routes.push(k);
        }
        pb::remove::Key::Backend(k) => {
            let k = convert::backend_key(k);
            store.remove_backend(&k);
            out.backends.push(k);
        }
        pb::remove::Key::Secret(k) => {
            let k = convert::secret_key(k);
            store.remove_secret(&k);
            out.secrets.push(k);
        }
        pb::remove::Key::Extension(k) => {
            let k = convert::extension_key(k);
            store.remove_extension(&k);
            out.extensions.push(k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use gateway_config::secret::{SecretValue, TLS_CERT_KEY, TLS_KEY_KEY};
    use gateway_state::{BackendKey, BindKey, ListenerKey, RouteKey};

    /// Stands in for a credential; no test may print it.
    const SENSITIVE: &str = "sk-not-a-real-key";

    // ----- fixture builders -----

    fn bind_upsert(name: &str, port: u32) -> pb::Upsert {
        pb::Upsert {
            body: Some(pb::upsert::Body::Bind(pb::BindUpsert {
                name: name.into(),
                address: "0.0.0.0".into(),
                port,
                bind_protocol: pb::BindProtocol::Http as i32,
            })),
        }
    }

    fn listener_upsert(bind: &str, name: &str, hostname: Option<&str>) -> pb::Upsert {
        let (has_hostname, hostname) = match hostname {
            Some(h) => (true, h.to_string()),
            None => (false, String::new()),
        };
        pb::Upsert {
            body: Some(pb::upsert::Body::Listener(pb::ListenerUpsert {
                key: Some(pb::ListenerKey {
                    bind: bind.into(),
                    name: name.into(),
                }),
                hostname,
                has_hostname,
                tls: None,
            })),
        }
    }

    fn route_upsert(bind: &str, listener: &str, name: &str, backend: &str) -> pb::Upsert {
        pb::Upsert {
            body: Some(pb::upsert::Body::HttpRoute(pb::HttpRouteUpsert {
                key: Some(pb::RouteKey {
                    bind: bind.into(),
                    listener: listener.into(),
                    name: name.into(),
                }),
                matches: vec![pb::HttpMatch {
                    host: String::new(),
                    has_host: false,
                    path: Some(pb::PathMatch {
                        kind: pb::PathMatchKind::PathPrefix as i32,
                        value: "/".into(),
                    }),
                    method: pb::HttpMethod::Unspecified as i32,
                    header_matches: vec![],
                    query_param_matches: vec![],
                }],
                backend_refs: vec![pb::BackendRef {
                    name: backend.into(),
                    weight: 1,
                    origin: None,
                }],
                filters: vec![],
            })),
        }
    }

    fn backend_upsert(name: &str, ip: &str, port: u32) -> pb::Upsert {
        pb::Upsert {
            body: Some(pb::upsert::Body::Backend(pb::BackendUpsert {
                name: name.into(),
                kind: Some(pb::backend_upsert::Kind::EndpointSet(pb::EndpointSet {
                    endpoints: vec![pb::Endpoint {
                        name: format!("{name}/0"),
                        address: ip.into(),
                        port,
                    }],
                    protocol: pb::BackendProtocol::Http1 as i32,
                })),
            })),
        }
    }

    // Throwaway self-signed EC cert + PKCS#8 key.
    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBgjCCASmgAwIBAgIUW/OT9NoEgpMEra4i2ttY/oSsRe0wCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMZ2F0ZXdheS10ZXN0MB4XDTI2MDYyNjEwNTEyOFoXDTM2MDYy\n\
MzEwNTEyOFowFzEVMBMGA1UEAwwMZ2F0ZXdheS10ZXN0MFkwEwYHKoZIzj0CAQYI\n\
KoZIzj0DAQcDQgAEZoF6gHnR0OJdILhqvT75ZE5oX/NkCobjCPRKQmQAvEFeN8ku\n\
f+C449e9U2Gq6S7C72DJWjcsr8gaxjiMRie0H6NTMFEwHQYDVR0OBBYEFKmMFFZT\n\
6oW/R893bFKGDqRaBuoRMB8GA1UdIwQYMBaAFKmMFFZT6oW/R893bFKGDqRaBuoR\n\
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgEdjQ6EJUY9QMrNQy\n\
YhAYK89fjb5J6TE0AJY4QnmcFR0CIHo7A7WYP2hT7rr6orgxEqAVx7DGbd0aCCqe\n\
GkIpYyxV\n\
-----END CERTIFICATE-----\n";

    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcB/ubr8b5gfbp97H\n\
/hzgYBDdRqvQrz6jRyF1kz8TrcChRANCAARmgXqAedHQ4l0guGq9PvlkTmhf82QK\n\
huMI9EpCZAC8QV43yS5/4Ljj171TYarpLsLvYMlaNyyvyBrGOIxGJ7Qf\n\
-----END PRIVATE KEY-----\n";

    fn secret_upsert(name: &str, cert_pem: &str, key_pem: &str) -> pb::Upsert {
        upsert_secret(
            name,
            pb::SecretType::Tls,
            [
                (TLS_CERT_KEY, cert_pem.as_bytes().to_vec()),
                (TLS_KEY_KEY, key_pem.as_bytes().to_vec()),
            ],
        )
    }

    fn opaque_upsert(name: &str, key: &str, value: &str) -> pb::Upsert {
        pb::Upsert {
            body: Some(pb::upsert::Body::Secret(pb::SecretUpsert {
                namespace: String::new(),
                name: name.into(),
                r#type: pb::SecretType::Opaque as i32,
                data: HashMap::from([(key.to_string(), value.as_bytes().to_vec())]),
            })),
        }
    }

    fn upsert_secret<'a>(
        name: &str,
        secret_type: pb::SecretType,
        data: impl IntoIterator<Item = (&'a str, Vec<u8>)>,
    ) -> pb::Upsert {
        pb::Upsert {
            body: Some(pb::upsert::Body::Secret(pb::SecretUpsert {
                namespace: String::new(),
                name: name.into(),
                r#type: secret_type as i32,
                data: data.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
            })),
        }
    }

    fn batch(upserts: Vec<pb::Upsert>, removes: Vec<pb::Remove>) -> pb::ConfigUpdate {
        pb::ConfigUpdate {
            upserts,
            removes,
            sync_complete: true,
        }
    }

    // ----- happy path -----

    #[test]
    fn bind_listener_route_backend_all_in_one_batch() {
        let store = Store::new();
        let update = batch(
            vec![
                bind_upsert("b", 80),
                listener_upsert("b", "l", Some("app.example.com")),
                route_upsert("b", "l", "r", "be"),
                backend_upsert("be", "10.0.0.1", 8080),
            ],
            vec![],
        );

        apply_update(&store, update).expect("apply ok");

        let read = store.read();
        let bind = read.bind(&BindKey::new("b")).expect("bind active");
        assert_eq!(bind.port, 80);
        assert_eq!(bind.listeners.len(), 1);
        let listener = &bind.listeners[0];
        assert_eq!(listener.hostname.as_deref(), Some("app.example.com"));
        assert_eq!(listener.routes.len(), 1);
        let route = &listener.routes[0];
        assert_eq!(route.backends.len(), 1);
        let backend = route.backends[0].backend.as_ref().expect("ref resolves");
        assert_eq!(backend.endpoints()[0].port, 8080);
        assert_eq!(backend.endpoints()[0].address.to_string(), "10.0.0.1");
    }

    #[test]
    fn out_of_order_upserts_converge_via_store_stashing() {
        // Route arrives before its listener and backend; Store stashes
        // it, then promotes once both deps land.
        let store = Store::new();
        let update = batch(
            vec![
                route_upsert("b", "l", "r", "be"),
                listener_upsert("b", "l", None),
                bind_upsert("b", 80),
                backend_upsert("be", "10.0.0.1", 8080),
            ],
            vec![],
        );
        apply_update(&store, update).expect("apply ok");

        let read = store.read();
        let bind = read.bind(&BindKey::new("b")).unwrap();
        assert_eq!(bind.listeners.len(), 1);
        assert_eq!(bind.listeners[0].routes.len(), 1);
    }

    #[test]
    fn route_without_backend_activates_unresolved() {
        let store = Store::new();
        let update = batch(
            vec![
                bind_upsert("b", 80),
                listener_upsert("b", "l", None),
                route_upsert("b", "l", "r", "missing-be"),
            ],
            vec![],
        );
        apply_update(&store, update).expect("apply ok");

        // The missing backend does not hold the route back: it activates
        // with the ref unresolved (the data plane answers 500 for it).
        let read = store.read();
        assert!(read.is_route_active(&RouteKey::new(
            ListenerKey::new(BindKey::new("b"), "l"),
            "r"
        )));
        let bind = read.bind(&BindKey::new("b")).unwrap();
        assert_eq!(bind.listeners.len(), 1);
        assert!(bind.listeners[0].routes[0].backends[0].backend.is_none());
    }

    // ----- removes -----

    #[test]
    fn remove_bind_via_batch() {
        let store = Store::new();
        apply_update(
            &store,
            batch(
                vec![
                    bind_upsert("b", 80),
                    listener_upsert("b", "l", None),
                    route_upsert("b", "l", "r", "be"),
                    backend_upsert("be", "10.0.0.1", 8080),
                ],
                vec![],
            ),
        )
        .unwrap();
        assert!(store.read().bind(&BindKey::new("b")).is_some());

        let removal = pb::ConfigUpdate {
            upserts: vec![],
            removes: vec![pb::Remove {
                key: Some(pb::remove::Key::Bind(pb::BindKey { name: "b".into() })),
            }],
            sync_complete: false,
        };
        apply_update(&store, removal).unwrap();

        assert!(store.read().bind(&BindKey::new("b")).is_none());
    }

    #[test]
    fn remove_backend_unresolves_dependent_refs() {
        let store = Store::new();
        apply_update(
            &store,
            batch(
                vec![
                    bind_upsert("b", 80),
                    listener_upsert("b", "l", None),
                    route_upsert("b", "l", "r", "be"),
                    backend_upsert("be", "10.0.0.1", 8080),
                ],
                vec![],
            ),
        )
        .unwrap();
        let rk = RouteKey::new(ListenerKey::new(BindKey::new("b"), "l"), "r");
        assert!(store.read().is_route_active(&rk));

        apply_update(
            &store,
            pb::ConfigUpdate {
                upserts: vec![],
                removes: vec![pb::Remove {
                    key: Some(pb::remove::Key::Backend(pb::BackendKey {
                        name: "be".into(),
                    })),
                }],
                sync_complete: false,
            },
        )
        .unwrap();

        // The route stays active; the ref rides along unresolved.
        let read = store.read();
        assert!(read.is_route_active(&rk));
        assert!(read.backend(&BackendKey::new("be")).is_none());
        let bind = read.bind(&BindKey::new("b")).unwrap();
        assert!(bind.listeners[0].routes[0].backends[0].backend.is_none());
    }

    #[test]
    fn remove_with_no_key_field_is_skipped() {
        let store = Store::new();
        let update = pb::ConfigUpdate {
            upserts: vec![bind_upsert("b", 80)],
            removes: vec![pb::Remove { key: None }],
            sync_complete: true,
        };
        apply_update(&store, update).expect("apply ok despite empty Remove");
        assert!(store.read().bind(&BindKey::new("b")).is_some());
    }

    // ----- conversion failures -----

    #[test]
    fn invalid_address_rejected() {
        let store = Store::new();
        let update = batch(
            vec![pb::Upsert {
                body: Some(pb::upsert::Body::Bind(pb::BindUpsert {
                    name: "b".into(),
                    address: "not-an-ip".into(),
                    port: 80,
                    bind_protocol: pb::BindProtocol::Http as i32,
                })),
            }],
            vec![],
        );
        let err = apply_update(&store, update).expect_err("must fail");
        assert!(matches!(err, Error::InvalidValue { field, .. } if field == "BindUpsert.address"));
    }

    #[test]
    fn port_overflow_rejected() {
        let store = Store::new();
        let update = batch(
            vec![pb::Upsert {
                body: Some(pb::upsert::Body::Bind(pb::BindUpsert {
                    name: "b".into(),
                    address: "0.0.0.0".into(),
                    port: 70_000,
                    bind_protocol: pb::BindProtocol::Http as i32,
                })),
            }],
            vec![],
        );
        let err = apply_update(&store, update).expect_err("must fail");
        assert!(matches!(err, Error::InvalidValue { field, .. } if field == "BindUpsert.port"));
    }

    #[test]
    fn unspecified_bind_protocol_rejected() {
        let store = Store::new();
        let update = batch(
            vec![pb::Upsert {
                body: Some(pb::upsert::Body::Bind(pb::BindUpsert {
                    name: "b".into(),
                    address: "0.0.0.0".into(),
                    port: 80,
                    bind_protocol: pb::BindProtocol::Unspecified as i32,
                })),
            }],
            vec![],
        );
        let err = apply_update(&store, update).expect_err("must fail");
        assert!(matches!(err, Error::UnsupportedEnum { kind, .. } if kind == "BindProtocol"));
    }

    #[test]
    fn missing_route_key_rejected() {
        let store = Store::new();
        let update = batch(
            vec![pb::Upsert {
                body: Some(pb::upsert::Body::HttpRoute(pb::HttpRouteUpsert {
                    key: None,
                    matches: vec![],
                    backend_refs: vec![],
                    filters: vec![],
                })),
            }],
            vec![],
        );
        let err = apply_update(&store, update).expect_err("must fail");
        assert!(matches!(err, Error::MissingField(s) if s == "HttpRouteUpsert.key"));
    }

    #[test]
    fn upsert_with_no_body_rejected() {
        let store = Store::new();
        let update = batch(vec![pb::Upsert { body: None }], vec![]);
        let err = apply_update(&store, update).expect_err("must fail");
        assert!(matches!(err, Error::MissingField(s) if s == "Upsert.body"));
    }

    // ----- filters -----

    #[test]
    fn extension_ref_filter_round_trips() {
        let store = Store::new();
        let route = pb::Upsert {
            body: Some(pb::upsert::Body::HttpRoute(pb::HttpRouteUpsert {
                key: Some(pb::RouteKey {
                    bind: "b".into(),
                    listener: "l".into(),
                    name: "r".into(),
                }),
                matches: vec![pb::HttpMatch {
                    host: String::new(),
                    has_host: false,
                    path: Some(pb::PathMatch {
                        kind: pb::PathMatchKind::PathPrefix as i32,
                        value: "/".into(),
                    }),
                    method: pb::HttpMethod::Unspecified as i32,
                    header_matches: vec![],
                    query_param_matches: vec![],
                }],
                backend_refs: vec![pb::BackendRef {
                    name: "be".into(),
                    weight: 1,
                    origin: None,
                }],
                filters: vec![pb::HttpFilter {
                    kind: Some(pb::http_filter::Kind::ExtensionRef(pb::ExtensionRef {
                        name: "add-x".into(),
                        namespace: "demo".into(),
                    })),
                }],
            })),
        };
        let update = batch(
            vec![
                bind_upsert("b", 80),
                listener_upsert("b", "l", None),
                route,
                backend_upsert("be", "10.0.0.1", 8080),
            ],
            vec![],
        );
        apply_update(&store, update).unwrap();

        let bind = store.read().bind(&BindKey::new("b")).unwrap();
        let r = &bind.listeners[0].routes[0];
        assert_eq!(r.filters.len(), 1);
    }

    #[test]
    fn http_filter_with_no_kind_is_dropped() {
        let store = Store::new();
        let route = pb::Upsert {
            body: Some(pb::upsert::Body::HttpRoute(pb::HttpRouteUpsert {
                key: Some(pb::RouteKey {
                    bind: "b".into(),
                    listener: "l".into(),
                    name: "r".into(),
                }),
                matches: vec![pb::HttpMatch {
                    host: String::new(),
                    has_host: false,
                    path: Some(pb::PathMatch {
                        kind: pb::PathMatchKind::PathPrefix as i32,
                        value: "/".into(),
                    }),
                    method: pb::HttpMethod::Unspecified as i32,
                    header_matches: vec![],
                    query_param_matches: vec![],
                }],
                backend_refs: vec![pb::BackendRef {
                    name: "be".into(),
                    weight: 1,
                    origin: None,
                }],
                // Unknown / future filter variant — proto would set kind = None
                // from the DP's perspective.
                filters: vec![pb::HttpFilter { kind: None }],
            })),
        };
        let update = batch(
            vec![
                bind_upsert("b", 80),
                listener_upsert("b", "l", None),
                route,
                backend_upsert("be", "10.0.0.1", 8080),
            ],
            vec![],
        );
        apply_update(&store, update).unwrap();

        let bind = store.read().bind(&BindKey::new("b")).unwrap();
        let r = &bind.listeners[0].routes[0];
        assert!(r.filters.is_empty());
    }

    // ----- extensions -----

    fn extension_upsert(name: &str, config_yaml: &str) -> pb::Upsert {
        pb::Upsert {
            body: Some(pb::upsert::Body::Extension(pb::ExtensionUpsert {
                namespace: "ns".into(),
                name: name.into(),
                class: "bllmp_selector".into(),
                failure_mode: pb::FailureMode::Open as i32,
                limits: Some(pb::ExtensionLimits {
                    request_body: pb::RequestBodyLimit::Stream as i32,
                    max_buffer_bytes: 0,
                }),
                config_yaml: config_yaml.into(),
            })),
        }
    }

    #[test]
    fn extension_upsert_lands_in_store() {
        let store = Store::new();
        apply_update(
            &store,
            batch(
                vec![extension_upsert(
                    "picker",
                    "service: bllmp.svc:50051\npool: { namespace: inference, name: p }\n",
                )],
                vec![],
            ),
        )
        .expect("apply ok");
        let ext = store
            .read()
            .extension(&gateway_state::ExtensionKey::new("ns", "picker"))
            .expect("extension present");
        assert_eq!(ext.class, "bllmp_selector");
        assert_eq!(
            ext.failure_mode,
            gateway_config::extension::FailureMode::Open
        );
        assert_eq!(
            ext.limits.request_body,
            Some(gateway_config::extension::RequestBodyLimit::Stream)
        );
        assert!(ext.limits.max_buffer_bytes.is_none());
        // The opaque config parsed into a value, nested keys intact.
        assert_eq!(ext.config["service"], "bllmp.svc:50051");
        assert_eq!(ext.config["pool"]["namespace"], "inference");
    }

    #[test]
    fn extension_defaults_map_to_closed_and_no_limits() {
        let store = Store::new();
        let upsert = pb::Upsert {
            body: Some(pb::upsert::Body::Extension(pb::ExtensionUpsert {
                namespace: String::new(),
                name: "x".into(),
                class: "c".into(),
                failure_mode: pb::FailureMode::Unspecified as i32,
                limits: None,
                config_yaml: String::new(),
            })),
        };
        apply_update(&store, batch(vec![upsert], vec![])).expect("apply ok");
        let ext = store
            .read()
            .extension(&gateway_state::ExtensionKey::local("x"))
            .expect("extension present");
        assert_eq!(
            ext.failure_mode,
            gateway_config::extension::FailureMode::Closed
        );
        assert!(ext.limits.request_body.is_none());
        assert!(ext.config.is_null());
    }

    #[test]
    fn invalid_extension_config_yaml_is_rejected() {
        let store = Store::new();
        let err = apply_update(
            &store,
            batch(vec![extension_upsert("bad", ": not yaml : [")], vec![]),
        )
        .expect_err("bad yaml must fail");
        assert!(err.to_string().contains("invalid extension"), "{err}");
    }

    #[test]
    fn remove_extension_evicts() {
        let store = Store::new();
        apply_update(&store, batch(vec![extension_upsert("picker", "")], vec![])).unwrap();
        apply_update(
            &store,
            pb::ConfigUpdate {
                upserts: vec![],
                removes: vec![pb::Remove {
                    key: Some(pb::remove::Key::Extension(pb::ExtensionKey {
                        namespace: "ns".into(),
                        name: "picker".into(),
                    })),
                }],
                sync_complete: false,
            },
        )
        .unwrap();
        assert!(
            store
                .read()
                .extension(&gateway_state::ExtensionKey::new("ns", "picker"))
                .is_none()
        );
    }

    // ----- secrets -----

    #[test]
    fn secret_upsert_lands_in_store() {
        let store = Store::new();
        apply_update(
            &store,
            batch(vec![secret_upsert("app-tls", CERT_PEM, KEY_PEM)], vec![]),
        )
        .expect("apply ok");
        let s = store
            .read()
            .secret(&gateway_state::SecretKey::local("app-tls"))
            .expect("secret present");
        assert_eq!(s.name(), "app-tls");
        assert!(s.as_tls().is_some(), "TLS material");
    }

    #[test]
    fn remove_secret_evicts() {
        let store = Store::new();
        apply_update(
            &store,
            batch(vec![secret_upsert("app-tls", CERT_PEM, KEY_PEM)], vec![]),
        )
        .unwrap();
        apply_update(
            &store,
            pb::ConfigUpdate {
                upserts: vec![],
                removes: vec![pb::Remove {
                    key: Some(pb::remove::Key::Secret(pb::SecretKey {
                        namespace: String::new(),
                        name: "app-tls".into(),
                    })),
                }],
                sync_complete: false,
            },
        )
        .unwrap();
        assert!(
            store
                .read()
                .secret(&gateway_state::SecretKey::local("app-tls"))
                .is_none()
        );
    }

    /// A secret with no `key_pem` is CA-only material: trust roots a
    /// dialable backend verifies against, not something a listener
    /// terminates with.
    #[test]
    fn secret_without_a_key_lands_as_ca_material() {
        let store = Store::new();
        apply_update(
            &store,
            batch(vec![secret_upsert("provider-ca", CERT_PEM, "")], vec![]),
        )
        .expect("apply ok");
        let s = store
            .read()
            .secret(&gateway_state::SecretKey::local("provider-ca"))
            .expect("secret present");
        let tls = s.as_tls().expect("TLS material");
        assert_eq!(tls.certs.len(), 1);
        assert!(tls.key.is_none());
    }

    /// The whole point of a generic carrier: a credential the
    /// gateway never interprets survives an apply, reachable by the
    /// data key it arrived under, and prints as nothing.
    #[test]
    fn opaque_secret_round_trips_and_never_prints() {
        let store = Store::new();
        apply_update(
            &store,
            batch(
                vec![opaque_upsert("provider-key", "apiKey", SENSITIVE)],
                vec![],
            ),
        )
        .expect("apply ok");
        let s = store
            .read()
            .secret(&gateway_state::SecretKey::local("provider-key"))
            .expect("secret present");
        let opaque = s.as_opaque().expect("opaque material");
        assert_eq!(
            opaque.get("apiKey").and_then(SecretValue::expose_str),
            Some(SENSITIVE)
        );
        assert!(opaque.get("nope").is_none());

        // Nothing on the way out prints the value: not the secret,
        // not the value itself, not the whole store entry.
        let printed = format!(
            "{s:?} {:?} {}",
            opaque.get("apiKey"),
            opaque.get("apiKey").unwrap()
        );
        assert!(!printed.contains(SENSITIVE), "{printed}");
        assert!(
            printed.contains("apiKey"),
            "data keys stay visible: {printed}"
        );
    }

    #[test]
    fn secret_without_a_type_rejected() {
        let store = Store::new();
        let err = apply_update(
            &store,
            batch(
                vec![upsert_secret("typeless", pb::SecretType::Unspecified, [])],
                vec![],
            ),
        )
        .expect_err("must fail");
        assert!(matches!(err, Error::InvalidSecret { name, .. } if name == "typeless"));
    }

    /// A TLS secret that never carried its chain is rejected here,
    /// not at handshake time.
    #[test]
    fn tls_secret_without_cert_data_rejected() {
        let store = Store::new();
        let err = apply_update(
            &store,
            batch(
                vec![upsert_secret("no-cert", pb::SecretType::Tls, [])],
                vec![],
            ),
        )
        .expect_err("must fail");
        assert!(matches!(err, Error::InvalidSecret { name, .. } if name == "no-cert"));
    }

    #[test]
    fn malformed_secret_pem_rejected() {
        let store = Store::new();
        let err = apply_update(
            &store,
            batch(vec![secret_upsert("bad", "not a cert", KEY_PEM)], vec![]),
        )
        .expect_err("must fail");
        assert!(matches!(err, Error::InvalidSecret { name, .. } if name == "bad"));
    }

    // ----- empty sync -----

    #[test]
    fn empty_sync_complete_is_noop() {
        let store = Store::new();
        let update = pb::ConfigUpdate {
            upserts: vec![],
            removes: vec![],
            sync_complete: true,
        };
        apply_update(&store, update).unwrap();
        assert_eq!(store.read().binds().count(), 0);
    }

    // ----- dialable backends -----

    /// The dialable half of a registered backend.
    fn dialable_of(backend: &gateway_state::ActiveBackend) -> &gateway_state::ActiveDialable {
        match &backend.kind {
            gateway_state::ActiveBackendKind::Dialable(d) => d,
            gateway_state::ActiveBackendKind::Endpoints(_) => {
                panic!("expected a dialable backend")
            }
        }
    }

    /// The wire form the control plane sends for a `GatewayBackend`,
    /// with every optional part filled in.
    fn dialable_upsert() -> pb::Upsert {
        pb::Upsert {
            body: Some(pb::upsert::Body::Backend(pb::BackendUpsert {
                name: "demo/provider".into(),
                kind: Some(pb::backend_upsert::Kind::Dialable(pb::Dialable {
                    host: "api.example.com".into(),
                    port: 8443,
                    path_prefix: "/v1".into(),
                    tls: Some(pb::BackendTls {
                        ca: Some(pb::SecretKey {
                            namespace: String::new(),
                            name: "provider-ca".into(),
                        }),
                        sni: "edge.example.com".into(),
                        alpn: vec![pb::AlpnProtocol::Http11 as i32],
                        insecure_skip_verify: false,
                    }),
                    auth: Some(pb::BackendAuth {
                        kind: Some(pb::backend_auth::Kind::ApiKey(pb::ApiKeyAuth {
                            secret: Some(pb::SecretKey {
                                namespace: String::new(),
                                name: "provider-key".into(),
                            }),
                            data_key: "apiKey".into(),
                            header: "x-api-key".into(),
                            prefix: String::new(),
                        })),
                    }),
                })),
            })),
        }
    }

    #[test]
    fn dialable_backend_round_trips() {
        let store = Store::new();
        apply_update(&store, batch(vec![dialable_upsert()], vec![])).expect("apply ok");

        let backend = store
            .read()
            .backend(&BackendKey::new("demo/provider"))
            .expect("backend registered");
        let dialable = dialable_of(&backend);
        assert_eq!(dialable.host, "api.example.com");
        assert_eq!(dialable.port, 8443);
        assert_eq!(dialable.path_prefix.as_deref(), Some("/v1"));

        let tls = dialable.tls.as_deref().expect("tls settings");
        assert_eq!(tls.sni.as_deref(), Some("edge.example.com"));
        assert_eq!(
            tls.alpn,
            vec![gateway_config::backend::AlpnProtocol::Http11]
        );
        assert!(!tls.insecure_skip_verify);
    }

    /// An empty `path_prefix` or `sni` is how the wire says "unset":
    /// neither has a legitimate empty value.
    #[test]
    fn empty_optional_strings_arrive_as_unset() {
        let store = Store::new();
        let mut upsert = dialable_upsert();
        let Some(pb::upsert::Body::Backend(be)) = upsert.body.as_mut() else {
            unreachable!()
        };
        let Some(pb::backend_upsert::Kind::Dialable(d)) = be.kind.as_mut() else {
            unreachable!()
        };
        d.path_prefix = String::new();
        d.tls.as_mut().unwrap().sni = String::new();
        d.tls.as_mut().unwrap().ca = None;

        apply_update(&store, batch(vec![upsert], vec![])).expect("apply ok");
        let backend = store
            .read()
            .backend(&BackendKey::new("demo/provider"))
            .expect("backend registered");
        let dialable = dialable_of(&backend);
        assert!(dialable.path_prefix.is_none());
        let tls = dialable.tls.as_deref().expect("tls settings");
        assert!(tls.sni.is_none());
        assert!(
            matches!(tls.roots, gateway_state::ActiveTrustRoots::System),
            "no CA named means the platform trust store"
        );
    }

    /// A backend whose kind never arrived is a translator bug, and
    /// this is where it surfaces.
    #[test]
    fn backend_without_a_kind_rejected() {
        let store = Store::new();
        let err = apply_update(
            &store,
            batch(
                vec![pb::Upsert {
                    body: Some(pb::upsert::Body::Backend(pb::BackendUpsert {
                        name: "demo/provider".into(),
                        kind: None,
                    })),
                }],
                vec![],
            ),
        )
        .expect_err("must fail");
        assert!(matches!(err, Error::MissingField("BackendUpsert.kind")));
    }

    /// The credential and the backend arrive in the same batch and in
    /// either order; the store resolves the reference once both are
    /// registered.
    #[test]
    fn a_credential_reaches_the_backend_it_belongs_to() {
        let store = Store::new();
        apply_update(
            &store,
            batch(
                vec![
                    dialable_upsert(),
                    opaque_upsert("provider-key", "apiKey", SENSITIVE),
                    secret_upsert("provider-ca", CERT_PEM, ""),
                ],
                vec![],
            ),
        )
        .expect("apply ok");

        let read = store.read();
        let backend = read
            .backend(&BackendKey::new("demo/provider"))
            .expect("backend registered");
        let dialable = dialable_of(&backend);
        let printed = format!("{dialable:?}");
        assert!(!printed.contains(SENSITIVE), "{printed}");
    }
}
