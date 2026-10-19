//! Protobuf and tonic-generated types for the gateway control-plane
//! protocol. Imported by `gateway-cp` (server side) and
//! `gateway-cp-client` (data plane side).
//!
//! The generated module corresponds to the `gateway.controlplane.v1`
//! proto package and is re-exported as the `v1` module.

pub mod v1 {
    #![allow(clippy::pedantic, clippy::nursery, clippy::all, missing_docs)]
    tonic::include_proto!("gateway.controlplane.v1");
}

#[cfg(test)]
mod tests {
    use super::v1;

    // Sanity test: construct every message variant. Catches proto
    // breakage at unit-test time rather than at first integration.

    #[test]
    fn hello_constructs() {
        let _ = v1::Hello {
            client_id: "demo/api-gateway".into(),
        };
    }

    #[test]
    fn config_request_hello_oneof_constructs() {
        let _ = v1::ConfigRequest {
            kind: Some(v1::config_request::Kind::Hello(v1::Hello {
                client_id: "demo/api-gateway".into(),
            })),
        };
    }

    #[test]
    fn path_match_kind_variants_construct() {
        let _ = v1::PathMatch {
            kind: v1::PathMatchKind::PathPrefix as i32,
            value: "/".into(),
        };
        let _ = v1::PathMatch {
            kind: v1::PathMatchKind::Exact as i32,
            value: "/healthz".into(),
        };
    }

    #[test]
    #[allow(clippy::too_many_lines)] // sanity test that constructs every variant
    fn config_update_with_upserts_and_removes_constructs() {
        let extension_upsert = v1::ExtensionUpsert {
            namespace: "inference".into(),
            name: "picker".into(),
            class: "kinference_selector".into(),
            failure_mode: v1::FailureMode::Closed as i32,
            limits: Some(v1::ExtensionLimits {
                request_body: v1::RequestBodyLimit::Stream as i32,
                max_buffer_bytes: 1_048_576,
            }),
            config_yaml: "service: kinference.svc:50051".into(),
        };
        let _ = v1::Upsert {
            body: Some(v1::upsert::Body::Extension(extension_upsert)),
        };
        let _ = v1::Remove {
            key: Some(v1::remove::Key::Extension(v1::ExtensionKey {
                namespace: "inference".into(),
                name: "picker".into(),
            })),
        };
        let _ = v1::HttpFilter {
            kind: Some(v1::http_filter::Kind::ExtensionRef(v1::ExtensionRef {
                name: "picker".into(),
                namespace: "inference".into(),
            })),
        };

        let bind_upsert = v1::BindUpsert {
            name: "demo/api-gw/http".into(),
            address: "0.0.0.0".into(),
            port: 80,
            bind_protocol: v1::BindProtocol::Http as i32,
        };
        let listener_upsert = v1::ListenerUpsert {
            key: Some(v1::ListenerKey {
                bind: "demo/api-gw/http".into(),
                name: "demo/api-gw/http".into(),
            }),
            hostname: "app.example.com".into(),
            has_hostname: true,
            tls: None,
        };
        let route_upsert = v1::HttpRouteUpsert {
            key: Some(v1::RouteKey {
                bind: "demo/api-gw/http".into(),
                listener: "demo/api-gw/http".into(),
                name: "demo/app-route/rule0".into(),
            }),
            matches: vec![v1::HttpMatch {
                host: String::new(),
                has_host: false,
                path: Some(v1::PathMatch {
                    kind: v1::PathMatchKind::PathPrefix as i32,
                    value: "/api".into(),
                }),
                method: v1::HttpMethod::Unspecified as i32,
                header_matches: vec![],
                query_param_matches: vec![],
            }],
            backend_refs: vec![v1::BackendRef {
                name: "demo/api-svc:8080".into(),
                weight: 1,
                origin: Some(v1::BackendOrigin {
                    group: String::new(),
                    kind: "Service".into(),
                    namespace: "demo".into(),
                    name: "api-svc".into(),
                }),
            }],
            filters: vec![v1::HttpFilter {
                kind: Some(v1::http_filter::Kind::ExtensionRef(v1::ExtensionRef {
                    name: "add-gateway-header".into(),
                    namespace: "demo".into(),
                })),
            }],
        };
        let backend_upsert = v1::BackendUpsert {
            name: "demo/api-svc:8080".into(),
            kind: Some(v1::backend_upsert::Kind::EndpointSet(v1::EndpointSet {
                endpoints: vec![v1::Endpoint {
                    name: "demo/api-svc".into(),
                    address: "10.96.0.42".into(),
                    port: 8080,
                }],
                protocol: v1::BackendProtocol::Http1 as i32,
            })),
        };

        let upserts = vec![
            v1::Upsert {
                body: Some(v1::upsert::Body::Bind(bind_upsert)),
            },
            v1::Upsert {
                body: Some(v1::upsert::Body::Listener(listener_upsert)),
            },
            v1::Upsert {
                body: Some(v1::upsert::Body::HttpRoute(route_upsert)),
            },
            v1::Upsert {
                body: Some(v1::upsert::Body::Backend(backend_upsert)),
            },
        ];

        let removes = vec![
            v1::Remove {
                key: Some(v1::remove::Key::Bind(v1::BindKey {
                    name: "demo/old-gw/http".into(),
                })),
            },
            v1::Remove {
                key: Some(v1::remove::Key::Listener(v1::ListenerKey {
                    bind: "demo/old-gw/http".into(),
                    name: "demo/old-gw/http".into(),
                })),
            },
            v1::Remove {
                key: Some(v1::remove::Key::HttpRoute(v1::RouteKey {
                    bind: "demo/old-gw/http".into(),
                    listener: "demo/old-gw/http".into(),
                    name: "demo/old-route/rule0".into(),
                })),
            },
            v1::Remove {
                key: Some(v1::remove::Key::Backend(v1::BackendKey {
                    name: "demo/old-svc:8080".into(),
                })),
            },
        ];

        let update = v1::ConfigUpdate {
            upserts,
            removes,
            sync_complete: true,
        };

        assert_eq!(update.upserts.len(), 4);
        assert_eq!(update.removes.len(), 4);
        assert!(update.sync_complete);
    }

    #[test]
    fn empty_sync_complete_constructs() {
        // Empty initial snapshot for a Gateway that doesn't exist yet.
        let update = v1::ConfigUpdate {
            upserts: vec![],
            removes: vec![],
            sync_complete: true,
        };
        assert!(update.sync_complete);
        assert!(update.upserts.is_empty(), "{:?}", update.upserts);
        assert!(update.removes.is_empty(), "{:?}", update.removes);
    }
}
