//! Typed builders over `gateway_api::*` for `Gateway` / `HTTPRoute`,
//! plus `Deployment` + `Service` helpers for the data plane and the
//! echo backend.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use gateway_api::apis::standard::gateways::{
    Gateway, GatewayListeners, GatewayListenersAllowedRoutes,
    GatewayListenersAllowedRoutesNamespaces, GatewayListenersTls,
    GatewayListenersTlsCertificateRefs, GatewayListenersTlsMode, GatewaySpec,
};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs,
    HttpRouteRulesFilters, HttpRouteRulesFiltersExtensionRef,
    HttpRouteRulesFiltersRequestHeaderModifier, HttpRouteRulesFiltersRequestHeaderModifierAdd,
    HttpRouteRulesFiltersRequestRedirect, HttpRouteRulesFiltersRequestRedirectScheme,
    HttpRouteRulesFiltersResponseHeaderModifier, HttpRouteRulesFiltersResponseHeaderModifierAdd,
    HttpRouteRulesFiltersType, HttpRouteRulesMatches, HttpRouteRulesMatchesHeaders,
    HttpRouteRulesMatchesHeadersType, HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPath,
    HttpRouteRulesMatchesPathType, HttpRouteRulesMatchesQueryParams,
    HttpRouteRulesMatchesQueryParamsType, HttpRouteSpec,
};
use gateway_cp::crd::{
    ApiKeyAuth, BackendAuth, BackendAuthType, BackendBinding, BackendBindingSpec,
    BindingBackendRef, BindingObjectReference, Claim, Extension, ExtensionSpec, FailureMode,
    GatewayBackend, GatewayBackendSpec, Limits, SecretKeyReference,
};
use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, Pod, PodSpec, PodTemplateSpec, Secret, Service, ServicePort,
    ServiceSpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{DeleteParams, ListParams, ObjectMeta, Patch, PatchParams, PostParams};
use kube::{Api, Client};

/// Build a `Gateway` attached to the in-tree `buoyant-gateway`
/// `GatewayClass`, with one HTTP listener on `port`. The provisioned
/// Service takes its `LoadBalancer` default; the cluster's
/// `LoadBalancer` implementation assigns the address.
pub fn gateway(ns: &str, name: &str, port: i32, hostname: Option<&str>) -> Gateway {
    Gateway {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            ..Default::default()
        },
        spec: GatewaySpec {
            gateway_class_name: "buoyant-gateway".into(),
            listeners: vec![GatewayListeners {
                name: "http".into(),
                protocol: "HTTP".into(),
                port,
                hostname: hostname.map(String::from),
                tls: None,
                allowed_routes: Some(GatewayListenersAllowedRoutes {
                    namespaces: Some(GatewayListenersAllowedRoutesNamespaces {
                        from: Some(gateway_api::apis::standard::gateways::GatewayListenersAllowedRoutesNamespacesFrom::Same),
                        selector: None,
                    }),
                    kinds: None,
                }),
            }],
            ..Default::default()
        },
        status: None,
    }
}

/// Throwaway self-signed EC cert + PKCS#8 key (CN `gateway-test`, no
/// SANs). The e2e TLS client trusts any cert, so this only needs to be
/// a structurally valid `kubernetes.io/tls` pair.
pub const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
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

pub const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcB/ubr8b5gfbp97H\n\
/hzgYBDdRqvQrz6jRyF1kz8TrcChRANCAARmgXqAedHQ4l0guGq9PvlkTmhf82QK\n\
huMI9EpCZAC8QV43yS5/4Ljj171TYarpLsLvYMlaNyyvyBrGOIxGJ7Qf\n\
-----END PRIVATE KEY-----\n";

/// Build a `Gateway` with one HTTPS (`Terminate`) listener on `port`,
/// terminating with the named same-namespace `Secret`.
pub fn gateway_https(
    ns: &str,
    name: &str,
    port: i32,
    hostname: Option<&str>,
    secret: &str,
) -> Gateway {
    gateway_https_with_cert_ns(ns, name, port, hostname, None, secret)
}

/// [`gateway_https`] with an explicit certificate namespace — the
/// cross-namespace certificateRef shape.
pub fn gateway_https_with_cert_ns(
    ns: &str,
    name: &str,
    port: i32,
    hostname: Option<&str>,
    secret_ns: Option<&str>,
    secret: &str,
) -> Gateway {
    Gateway {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            ..Default::default()
        },
        spec: GatewaySpec {
            gateway_class_name: "buoyant-gateway".into(),
            listeners: vec![GatewayListeners {
                name: "https".into(),
                protocol: "HTTPS".into(),
                port,
                hostname: hostname.map(String::from),
                tls: Some(GatewayListenersTls {
                    mode: Some(GatewayListenersTlsMode::Terminate),
                    options: None,
                    certificate_refs: Some(vec![GatewayListenersTlsCertificateRefs {
                        group: None,
                        kind: Some("Secret".into()),
                        name: secret.into(),
                        namespace: secret_ns.map(String::from),
                    }]),
                }),
                allowed_routes: Some(GatewayListenersAllowedRoutes {
                    namespaces: Some(GatewayListenersAllowedRoutesNamespaces {
                        from: Some(gateway_api::apis::standard::gateways::GatewayListenersAllowedRoutesNamespacesFrom::Same),
                        selector: None,
                    }),
                    kinds: None,
                }),
            }],
            ..Default::default()
        },
        status: None,
    }
}

/// Create a `kubernetes.io/tls` `Secret` carrying `tls.crt` / `tls.key`.
///
/// # Errors
/// Returns an error if the create call fails.
pub async fn deploy_tls_secret(
    client: &Client,
    ns: &str,
    name: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<()> {
    let mut data = BTreeMap::new();
    data.insert(
        "tls.crt".to_owned(),
        ByteString(cert_pem.as_bytes().to_vec()),
    );
    data.insert(
        "tls.key".to_owned(),
        ByteString(key_pem.as_bytes().to_vec()),
    );

    let secret = Secret {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            ..Default::default()
        },
        type_: Some("kubernetes.io/tls".into()),
        data: Some(data),
        ..Default::default()
    };

    Api::<Secret>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), &secret)
        .await
        .with_context(|| format!("creating TLS secret {name}"))?;
    Ok(())
}

/// Chainable builder for an `HTTPRoute` with one rule. Multiple rules
/// land via repeated calls to `add_rule()`. Consume with `build()`;
/// dropping a partially-built `HttpRouteBuilder` discards the route.
#[must_use = "HttpRouteBuilder is consumed by .build() — drop discards the route"]
pub struct HttpRouteBuilder {
    ns: String,
    name: String,
    parent: String,
    hostnames: Option<Vec<String>>,
    rules: Vec<HttpRouteRules>,
    pending: HttpRouteRules,
}

pub fn http_route(ns: &str, parent_gw: &str, name: &str) -> HttpRouteBuilder {
    HttpRouteBuilder {
        ns: ns.into(),
        name: name.into(),
        parent: parent_gw.into(),
        hostnames: None,
        rules: Vec::new(),
        pending: empty_rule(),
    }
}

fn empty_rule() -> HttpRouteRules {
    HttpRouteRules {
        matches: Some(vec![HttpRouteRulesMatches {
            path: None,
            headers: None,
            query_params: None,
            method: None,
        }]),
        backend_refs: None,
        filters: Some(Vec::new()),
        name: None,
        timeouts: None,
    }
}

impl HttpRouteBuilder {
    pub fn hostnames<I, S>(mut self, hostnames: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.hostnames = Some(hostnames.into_iter().map(Into::into).collect());
        self
    }

    /// Drop the rule's `matches` entirely — the spec-default catch-all
    /// shape (`backendRefs` only) that tooling commonly generates.
    pub fn no_matches(mut self) -> Self {
        self.pending.matches = None;
        self
    }

    fn current_match(&mut self) -> &mut HttpRouteRulesMatches {
        let matches = self.pending.matches.as_mut().expect("matches initialized");
        matches.first_mut().expect("at least one match entry")
    }

    pub fn path_prefix(mut self, value: &str) -> Self {
        self.current_match().path = Some(HttpRouteRulesMatchesPath {
            r#type: Some(HttpRouteRulesMatchesPathType::PathPrefix),
            value: Some(value.into()),
        });
        self
    }

    pub fn path_exact(mut self, value: &str) -> Self {
        self.current_match().path = Some(HttpRouteRulesMatchesPath {
            r#type: Some(HttpRouteRulesMatchesPathType::Exact),
            value: Some(value.into()),
        });
        self
    }

    pub fn path_regex(mut self, value: &str) -> Self {
        self.current_match().path = Some(HttpRouteRulesMatchesPath {
            r#type: Some(HttpRouteRulesMatchesPathType::RegularExpression),
            value: Some(value.into()),
        });
        self
    }

    pub fn method(mut self, m: HttpRouteRulesMatchesMethod) -> Self {
        self.current_match().method = Some(m);
        self
    }

    pub fn header_exact(mut self, name: &str, value: &str) -> Self {
        let entry = HttpRouteRulesMatchesHeaders {
            name: name.into(),
            value: value.into(),
            r#type: Some(HttpRouteRulesMatchesHeadersType::Exact),
        };
        self.current_match()
            .headers
            .get_or_insert_with(Vec::new)
            .push(entry);
        self
    }

    pub fn query_exact(mut self, name: &str, value: &str) -> Self {
        let entry = HttpRouteRulesMatchesQueryParams {
            name: name.into(),
            value: value.into(),
            r#type: Some(HttpRouteRulesMatchesQueryParamsType::Exact),
        };
        self.current_match()
            .query_params
            .get_or_insert_with(Vec::new)
            .push(entry);
        self
    }

    /// Reach into `self.pending.filters` and find or create the
    /// single `RequestHeaderModifier` filter for this rule. Gateway
    /// API CRD validation rejects more than one of each filter type
    /// per rule, so multiple `filter_request_header_*` calls must
    /// merge into one filter.
    fn req_header_mod(&mut self) -> &mut HttpRouteRulesFiltersRequestHeaderModifier {
        let filters = self.pending.filters.get_or_insert_with(Vec::new);
        if !filters
            .iter()
            .any(|f| matches!(f.r#type, HttpRouteRulesFiltersType::RequestHeaderModifier))
        {
            filters.push(HttpRouteRulesFilters {
                r#type: HttpRouteRulesFiltersType::RequestHeaderModifier,
                request_header_modifier: Some(HttpRouteRulesFiltersRequestHeaderModifier {
                    add: None,
                    set: None,
                    remove: None,
                }),
                response_header_modifier: None,
                request_redirect: None,
                url_rewrite: None,
                request_mirror: None,
                cors: None,
                extension_ref: None,
            });
        }
        filters
            .iter_mut()
            .find_map(|f| f.request_header_modifier.as_mut())
            .expect("just inserted")
    }

    /// Same idea for the response-side filter.
    fn resp_header_mod(&mut self) -> &mut HttpRouteRulesFiltersResponseHeaderModifier {
        let filters = self.pending.filters.get_or_insert_with(Vec::new);
        if !filters
            .iter()
            .any(|f| matches!(f.r#type, HttpRouteRulesFiltersType::ResponseHeaderModifier))
        {
            filters.push(HttpRouteRulesFilters {
                r#type: HttpRouteRulesFiltersType::ResponseHeaderModifier,
                request_header_modifier: None,
                response_header_modifier: Some(HttpRouteRulesFiltersResponseHeaderModifier {
                    add: None,
                    set: None,
                    remove: None,
                }),
                request_redirect: None,
                url_rewrite: None,
                request_mirror: None,
                cors: None,
                extension_ref: None,
            });
        }
        filters
            .iter_mut()
            .find_map(|f| f.response_header_modifier.as_mut())
            .expect("just inserted")
    }

    pub fn filter_request_header_add(mut self, name: &str, value: &str) -> Self {
        let m = self.req_header_mod();
        m.add
            .get_or_insert_with(Vec::new)
            .push(HttpRouteRulesFiltersRequestHeaderModifierAdd {
                name: name.into(),
                value: value.into(),
            });
        self
    }

    pub fn filter_response_header_add(mut self, name: &str, value: &str) -> Self {
        let m = self.resp_header_mod();
        m.add
            .get_or_insert_with(Vec::new)
            .push(HttpRouteRulesFiltersResponseHeaderModifierAdd {
                name: name.into(),
                value: value.into(),
            });
        self
    }

    pub fn filter_response_header_remove(mut self, name: &str) -> Self {
        let m = self.resp_header_mod();
        m.remove.get_or_insert_with(Vec::new).push(name.into());
        self
    }

    /// Attach a `RequestRedirect` filter. `scheme` is `"http"` or
    /// `"https"`; a redirect route needs no backend.
    ///
    /// # Panics
    /// Panics if `scheme` is not `"http"` or `"https"`.
    pub fn filter_request_redirect(mut self, scheme: &str, status_code: i64) -> Self {
        let scheme = match scheme {
            "http" => HttpRouteRulesFiltersRequestRedirectScheme::Http,
            "https" => HttpRouteRulesFiltersRequestRedirectScheme::Https,
            other => panic!("unsupported redirect scheme {other}"),
        };
        self.pending
            .filters
            .get_or_insert_with(Vec::new)
            .push(HttpRouteRulesFilters {
                r#type: HttpRouteRulesFiltersType::RequestRedirect,
                request_header_modifier: None,
                response_header_modifier: None,
                request_redirect: Some(HttpRouteRulesFiltersRequestRedirect {
                    scheme: Some(scheme),
                    hostname: None,
                    port: None,
                    path: None,
                    status_code: Some(status_code),
                }),
                url_rewrite: None,
                request_mirror: None,
                cors: None,
                extension_ref: None,
            });
        self
    }

    /// Attach an `ExtensionRef` filter pointing at a same-namespace
    /// `Extension` object.
    pub fn filter_extension_ref(mut self, name: &str) -> Self {
        self.pending
            .filters
            .get_or_insert_with(Vec::new)
            .push(HttpRouteRulesFilters {
                r#type: HttpRouteRulesFiltersType::ExtensionRef,
                request_header_modifier: None,
                response_header_modifier: None,
                request_redirect: None,
                url_rewrite: None,
                request_mirror: None,
                cors: None,
                extension_ref: Some(HttpRouteRulesFiltersExtensionRef {
                    group: "gateway.linkerd.io".into(),
                    kind: "Extension".into(),
                    name: name.into(),
                }),
            });
        self
    }

    pub fn backend(mut self, name: &str, port: i32) -> Self {
        let br = HttpRouteRulesBackendRefs {
            name: name.into(),
            port: Some(port),
            namespace: None,
            group: None,
            kind: None,
            weight: None,
            filters: None,
        };
        self.pending
            .backend_refs
            .get_or_insert_with(Vec::new)
            .push(br);
        self
    }

    /// A `backendRefs` entry naming a `GatewayBackend`: our group
    /// and kind, and no port — the port is part of its `baseURL`.
    /// A backendRef of a kind the gateway has no schema for — the
    /// shape a `BackendBinding` claims.
    pub fn foreign_backend(mut self, group: &str, kind: &str, name: &str) -> Self {
        let br = HttpRouteRulesBackendRefs {
            name: name.into(),
            port: None,
            namespace: None,
            group: Some(group.into()),
            kind: Some(kind.into()),
            weight: None,
            filters: None,
        };
        self.pending
            .backend_refs
            .get_or_insert_with(Vec::new)
            .push(br);
        self
    }

    pub fn dialable_backend(mut self, name: &str) -> Self {
        let br = HttpRouteRulesBackendRefs {
            name: name.into(),
            port: None,
            namespace: None,
            group: Some("gateway.linkerd.io".into()),
            kind: Some("GatewayBackend".into()),
            weight: None,
            filters: None,
        };
        self.pending
            .backend_refs
            .get_or_insert_with(Vec::new)
            .push(br);
        self
    }

    /// Commit the rule under construction and start a fresh one.
    pub fn add_rule(mut self) -> Self {
        let done = std::mem::replace(&mut self.pending, empty_rule());
        self.rules.push(done);
        self
    }

    pub fn build(mut self) -> HTTPRoute {
        // commit any pending rule
        if self
            .pending
            .backend_refs
            .as_ref()
            .is_some_and(|v| !v.is_empty())
            || self.pending.filters.as_ref().is_some_and(|v| !v.is_empty())
            || self.pending.matches.as_ref().is_some_and(|matches| {
                matches.iter().any(|m| {
                    m.path.is_some()
                        || m.method.is_some()
                        || m.headers.is_some()
                        || m.query_params.is_some()
                })
            })
        {
            self.rules
                .push(std::mem::replace(&mut self.pending, empty_rule()));
        }

        HTTPRoute {
            metadata: ObjectMeta {
                namespace: Some(self.ns),
                name: Some(self.name),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(vec![HttpRouteParentRefs {
                    name: self.parent,
                    namespace: None,
                    section_name: None,
                    group: None,
                    kind: None,
                    port: None,
                }]),
                hostnames: self.hostnames,
                rules: Some(self.rules),
            },
            status: None,
        }
    }
}

/// Wait for the Gateway's `LoadBalancer` address — the same read any
/// external client (or the gateway-api-bench harness) performs
/// before sending traffic.
///
/// # Errors
/// Returns an error if no address appears within the deadline.
/// The deadline is sized for CI, where the cluster's `LoadBalancer`
/// implementation has been observed to take well over a minute to
/// assign an address under container churn.
pub async fn gateway_address(client: &Client, ns: &str, gw_name: &str) -> Result<String> {
    let api: Api<Gateway> = Api::namespaced(client.clone(), ns);
    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(3);
    loop {
        if let Some(gw) = api.get_opt(gw_name).await?
            && let Some(addr) = gw
                .status
                .as_ref()
                .and_then(|s| s.addresses.as_ref())
                .and_then(|a| a.first())
        {
            return Ok(addr.value.clone());
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "timed out waiting for an address on gateway {ns}/{gw_name}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

/// Deploy an echo backend `Deployment` + `Service` in `ns`.
/// `app_protocol` is set on the `ServicePort` if provided
/// (e.g. `Some("h2c")` for the `appProtocol` test).
///
/// # Errors
/// Returns an error if any create call fails.
pub async fn deploy_echo(
    client: &Client,
    ns: &str,
    name: &str,
    app_protocol: Option<&str>,
) -> Result<()> {
    deploy_backend(client, ns, name, app_protocol, None).await
}

/// Deploy the gRPC echo server (same test image, second binary) with
/// a Service whose `appProtocol: grpc` makes the gateway dial it over
/// h2c.
///
/// # Errors
/// Returns an error if a create call fails.
pub async fn deploy_grpc_echo(client: &Client, ns: &str, name: &str) -> Result<()> {
    deploy_backend(
        client,
        ns,
        name,
        Some("grpc"),
        Some(vec!["/usr/local/bin/grpc_echo".to_string()]),
    )
    .await
}

async fn deploy_backend(
    client: &Client,
    ns: &str,
    name: &str,
    app_protocol: Option<&str>,
    command: Option<Vec<String>>,
) -> Result<()> {
    let labels: BTreeMap<String, String> =
        [("app".to_owned(), name.to_owned())].into_iter().collect();

    let deployment = Deployment {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            labels: Some(labels.clone()),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels.clone()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "echo".into(),
                        image: Some("gateway-test-echo:e2e".into()),
                        image_pull_policy: Some("IfNotPresent".into()),
                        command,
                        ports: Some(vec![ContainerPort {
                            name: Some("http".into()),
                            container_port: 8080,
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    Api::<Deployment>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), &deployment)
        .await
        .with_context(|| format!("creating echo deployment {name}"))?;

    let svc = Service {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels),
            ports: Some(vec![ServicePort {
                name: Some("http".into()),
                port: 8080,
                target_port: Some(IntOrString::String("http".into())),
                protocol: Some("TCP".into()),
                app_protocol: app_protocol.map(String::from),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        status: None,
    };

    Api::<Service>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), &svc)
        .await
        .with_context(|| format!("creating echo service {name}"))?;

    Ok(())
}

/// Merge-patch one annotation on an existing `Gateway`; `None`
/// removes the key.
///
/// # Errors
/// Returns an error if the patch call fails.
pub async fn annotate_gateway(
    client: &Client,
    ns: &str,
    name: &str,
    key: &str,
    value: Option<&str>,
) -> Result<()> {
    let patch = serde_json::json!({ "metadata": { "annotations": { key: value } } });
    Api::<Gateway>::namespaced(client.clone(), ns)
        .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .with_context(|| format!("annotating Gateway {ns}/{name}"))?;
    Ok(())
}

/// GET a path from a provisioned DP pod's admin server (:15021)
/// through the apiserver's pod proxy subresource — the admin port is
/// not exposed on any Service, so the proxy is how tests reach it.
/// Targets the first pod carrying `gw_name`'s gateway-name label.
///
/// # Errors
/// Returns an error if no DP pod exists or the proxied request fails.
pub async fn dp_admin_get(client: &Client, ns: &str, gw_name: &str, path: &str) -> Result<String> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), ns);
    let selector = format!("gateway.networking.k8s.io/gateway-name={gw_name}");
    let pod = pods
        .list(&ListParams::default().labels(&selector))
        .await?
        .items
        .into_iter()
        .next()
        .with_context(|| format!("no DP pod labeled {selector}"))?;
    let pod_name = pod.metadata.name.context("pod has no name")?;

    let uri = format!("/api/v1/namespaces/{ns}/pods/{pod_name}:15021/proxy{path}");
    let req = http::Request::get(&uri)
        .body(Vec::new())
        .context("building pod proxy request")?;
    client
        .request_text(req)
        .await
        .with_context(|| format!("GET {uri}"))
}

/// Scale an existing `Deployment` to `replicas`.
///
/// # Errors
/// Returns an error if the patch call fails.
pub async fn scale_deployment(client: &Client, ns: &str, name: &str, replicas: i32) -> Result<()> {
    let patch = serde_json::json!({ "spec": { "replicas": replicas } });
    Api::<Deployment>::namespaced(client.clone(), ns)
        .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .with_context(|| format!("scaling deployment {name} to {replicas}"))?;
    Ok(())
}

/// Apply a typed `Gateway` to the cluster.
///
/// # Errors
/// Returns an error if the create call fails.
pub async fn apply_gateway(client: &Client, gw: &Gateway) -> Result<()> {
    let ns = gw
        .metadata
        .namespace
        .as_deref()
        .context("gateway has no namespace")?;
    Api::<Gateway>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), gw)
        .await
        .with_context(|| {
            format!(
                "creating Gateway {}",
                gw.metadata.name.as_deref().unwrap_or("?")
            )
        })?;
    Ok(())
}

/// Apply a typed `HTTPRoute` to the cluster.
///
/// # Errors
/// Returns an error if the create call fails.
pub async fn apply_http_route(client: &Client, hr: &HTTPRoute) -> Result<()> {
    let ns = hr
        .metadata
        .namespace
        .as_deref()
        .context("HTTPRoute has no namespace")?;
    Api::<HTTPRoute>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), hr)
        .await
        .with_context(|| {
            format!(
                "creating HTTPRoute {}",
                hr.metadata.name.as_deref().unwrap_or("?")
            )
        })?;
    Ok(())
}

/// Delete an `HTTPRoute` by name.
///
/// # Errors
/// Returns an error if the delete call fails.
pub async fn delete_http_route(client: &Client, ns: &str, name: &str) -> Result<()> {
    Api::<HTTPRoute>::namespaced(client.clone(), ns)
        .delete(name, &DeleteParams::default())
        .await
        .with_context(|| format!("deleting HTTPRoute {ns}/{name}"))?;
    Ok(())
}

/// Build an `Extension` object with default `failureMode` / `limits`.
/// `config` is the class-specific object, passed through verbatim.
#[must_use]
pub fn extension(ns: &str, name: &str, class: &str, config: serde_json::Value) -> Extension {
    let mut ext = Extension::new(
        name,
        ExtensionSpec {
            class: class.into(),
            failure_mode: FailureMode::default(),
            limits: Limits::default(),
            config,
        },
    );
    ext.metadata.namespace = Some(ns.into());
    ext
}

/// Create an `Extension` object.
///
/// # Errors
/// Returns an error if the create call fails.
pub async fn apply_extension(client: &Client, ext: &Extension) -> Result<()> {
    let ns = ext
        .metadata
        .namespace
        .as_deref()
        .context("Extension has no namespace")?;
    Api::<Extension>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), ext)
        .await
        .with_context(|| {
            format!(
                "creating Extension {}",
                ext.metadata.name.as_deref().unwrap_or("?")
            )
        })?;
    Ok(())
}

/// Delete an `Extension` by name.
///
/// # Errors
/// Returns an error if the delete call fails.
pub async fn delete_extension(client: &Client, ns: &str, name: &str) -> Result<()> {
    Api::<Extension>::namespaced(client.clone(), ns)
        .delete(name, &DeleteParams::default())
        .await
        .with_context(|| format!("deleting Extension {ns}/{name}"))?;
    Ok(())
}

/// Build a `GatewayBackend` with no TLS and no auth.
#[must_use]
pub fn gateway_backend(ns: &str, name: &str, base_url: &str) -> GatewayBackend {
    let mut object = GatewayBackend::new(
        name,
        GatewayBackendSpec {
            base_url: base_url.into(),
            tls: None,
            auth: None,
        },
    );
    object.metadata.namespace = Some(ns.into());
    object
}

/// The same, authenticating with an API key from `secret`'s `key`
/// data key.
#[must_use]
pub fn gateway_backend_with_api_key(
    ns: &str,
    name: &str,
    base_url: &str,
    secret: &str,
    key: &str,
    header: &str,
) -> GatewayBackend {
    let mut object = gateway_backend(ns, name, base_url);
    object.spec.auth = Some(BackendAuth {
        r#type: BackendAuthType::ApiKey,
        api_key: Some(ApiKeyAuth {
            secret_ref: SecretKeyReference {
                name: secret.into(),
                key: key.into(),
            },
            header: Some(header.into()),
            prefix: None,
        }),
        oauth2: None,
    });
    object
}

/// Create a `GatewayBackend`.
///
/// # Errors
/// Returns an error if the create call fails.
pub async fn apply_gateway_backend(client: &Client, object: &GatewayBackend) -> Result<()> {
    let ns = object
        .metadata
        .namespace
        .as_deref()
        .context("GatewayBackend has no namespace")?;
    Api::<GatewayBackend>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), object)
        .await
        .with_context(|| {
            format!(
                "creating GatewayBackend {}",
                object.metadata.name.as_deref().unwrap_or("?")
            )
        })?;
    Ok(())
}

/// A `BackendBinding` claiming `(group, kind, name)`, resolving to
/// one Service ref per `(name, service, port)` entry, with
/// `extensions` prepended to using rules. Empty `refs` builds the
/// spec the control plane rejects with `NoBackendRefs`.
pub fn backend_binding(
    ns: &str,
    name: &str,
    claim: (&str, &str, &str),
    refs: &[(&str, &str, u16)],
    extensions: &[&str],
) -> BackendBinding {
    let mut object = BackendBinding::new(
        name,
        BackendBindingSpec {
            claim: Claim {
                group: claim.0.into(),
                kind: claim.1.into(),
                name: claim.2.into(),
            },
            backend_refs: refs
                .iter()
                .map(|(ref_name, service, port)| BindingBackendRef {
                    name: (*ref_name).into(),
                    target: BindingObjectReference {
                        namespace: None,
                        group: None,
                        kind: None,
                        name: (*service).into(),
                        port: Some(*port),
                    },
                })
                .collect(),
            extensions: extensions.iter().map(|e| (*e).to_string()).collect(),
        },
    );
    object.metadata.namespace = Some(ns.into());
    object
}

/// Create a `BackendBinding`.
///
/// # Errors
/// Returns an error if the create call fails.
pub async fn apply_backend_binding(client: &Client, object: &BackendBinding) -> Result<()> {
    let ns = object
        .metadata
        .namespace
        .as_deref()
        .context("BackendBinding has no namespace")?;
    Api::<BackendBinding>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), object)
        .await
        .with_context(|| {
            format!(
                "creating BackendBinding {}",
                object.metadata.name.as_deref().unwrap_or("?")
            )
        })?;
    Ok(())
}

/// Merge-patch a `BackendBinding`'s whole spec. A merge patch
/// replaces arrays wholesale, so a refs or extensions swap lands as
/// written.
///
/// # Errors
/// Returns an error if the patch call fails.
pub async fn update_backend_binding_spec(
    client: &Client,
    ns: &str,
    name: &str,
    spec: &BackendBindingSpec,
) -> Result<()> {
    let patch = serde_json::json!({ "spec": spec });
    Api::<BackendBinding>::namespaced(client.clone(), ns)
        .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .with_context(|| format!("updating BackendBinding {ns}/{name}"))?;
    Ok(())
}

/// Delete a `BackendBinding`.
///
/// # Errors
/// Returns an error if the delete call fails.
pub async fn delete_backend_binding(client: &Client, ns: &str, name: &str) -> Result<()> {
    Api::<BackendBinding>::namespaced(client.clone(), ns)
        .delete(name, &DeleteParams::default())
        .await
        .with_context(|| format!("deleting BackendBinding {ns}/{name}"))?;
    Ok(())
}

/// An `Opaque` Secret carrying one credential under `key` — the
/// shape secret tooling produces, and the shape a `GatewayBackend`
/// auth block names.
///
/// # Errors
/// Returns an error if the create call fails.
pub async fn deploy_credential_secret(
    client: &Client,
    ns: &str,
    name: &str,
    key: &str,
    value: &str,
) -> Result<()> {
    let secret = Secret {
        metadata: ObjectMeta {
            namespace: Some(ns.into()),
            name: Some(name.into()),
            ..Default::default()
        },
        type_: Some("Opaque".into()),
        data: Some(BTreeMap::from([(
            key.to_owned(),
            ByteString(value.as_bytes().to_vec()),
        )])),
        ..Default::default()
    };
    Api::<Secret>::namespaced(client.clone(), ns)
        .create(&PostParams::default(), &secret)
        .await
        .with_context(|| format!("creating Secret {ns}/{name}"))?;
    Ok(())
}

/// Delete a Secret by name.
///
/// # Errors
/// Returns an error if the delete call fails.
pub async fn delete_secret(client: &Client, ns: &str, name: &str) -> Result<()> {
    Api::<Secret>::namespaced(client.clone(), ns)
        .delete(name, &DeleteParams::default())
        .await
        .with_context(|| format!("deleting Secret {ns}/{name}"))?;
    Ok(())
}
