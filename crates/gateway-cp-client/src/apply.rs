//! Apply a `ConfigUpdate` batch to `gateway_state::Store`. Pure
//! translation; no caching, no network.

use gateway_cp_proto::v1 as pb;
use gateway_state::{BackendKey, BindKey, ListenerKey, RouteKey, SecretKey, Store};

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
            let name = match &backend {
                gateway_config::backend::Backend::Static(s) => s.name.clone(),
            };
            store.upsert_backend(backend);
            out.backends.push(BackendKey::new(name));
        }
        pb::upsert::Body::Secret(s) => {
            let secret = convert::secret(s)?;
            let key = SecretKey::new(secret.name.clone());
            store.upsert_secret(secret);
            out.secrets.push(key);
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_state::{BackendKey, BindKey, ListenerKey, RouteKey};

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
                }],
                filters: vec![],
            })),
        }
    }

    fn backend_upsert(name: &str, ip: &str, port: u32) -> pb::Upsert {
        pb::Upsert {
            body: Some(pb::upsert::Body::Backend(pb::BackendUpsert {
                name: name.into(),
                endpoints: vec![pb::Endpoint {
                    name: format!("{name}/0"),
                    address: ip.into(),
                    port,
                }],
                protocol: pb::BackendProtocol::Http1 as i32,
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
        pb::Upsert {
            body: Some(pb::upsert::Body::Secret(pb::SecretUpsert {
                name: name.into(),
                cert_pem: cert_pem.into(),
                key_pem: key_pem.into(),
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
        assert_eq!(route.backends[0].backend.endpoints[0].port, 8080);
        assert_eq!(
            route.backends[0].backend.endpoints[0].address.to_string(),
            "10.0.0.1"
        );
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
    fn route_without_backend_stays_pending() {
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

        let read = store.read();
        assert!(!read.is_route_active(&RouteKey::new(
            ListenerKey::new(BindKey::new("b"), "l"),
            "r"
        )));
        // Bind is still active but listener has no active routes yet,
        // so the bind's listener list is empty.
        let bind = read.bind(&BindKey::new("b")).unwrap();
        assert!(bind.listeners.is_empty());
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
    fn remove_backend_demotes_dependent_routes() {
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

        assert!(!store.read().is_route_active(&rk));
        assert!(store.read().backend(&BackendKey::new("be")).is_none());
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
    fn request_header_modifier_filter_round_trips() {
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
                }],
                filters: vec![pb::HttpFilter {
                    kind: Some(pb::http_filter::Kind::RequestHeaderModifier(
                        pb::RequestHeaderModifier {
                            name: "add-x".into(),
                            request_headers: Some(pb::HeaderOps {
                                add: vec![pb::HeaderPair {
                                    name: "x-test".into(),
                                    value: "yes".into(),
                                }],
                                set: vec![],
                                remove: vec![],
                            }),
                        },
                    )),
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
            .secret(&gateway_state::SecretKey::new("app-tls"))
            .expect("secret present");
        assert_eq!(s.name, "app-tls");
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
                .secret(&gateway_state::SecretKey::new("app-tls"))
                .is_none()
        );
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
}
