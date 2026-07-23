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
    HttpRouteRulesFilters, HttpRouteRulesFiltersRequestHeaderModifier,
    HttpRouteRulesFiltersRequestHeaderModifierAdd, HttpRouteRulesFiltersRequestRedirect,
    HttpRouteRulesFiltersRequestRedirectScheme, HttpRouteRulesFiltersResponseHeaderModifier,
    HttpRouteRulesFiltersResponseHeaderModifierAdd, HttpRouteRulesFiltersType,
    HttpRouteRulesMatches, HttpRouteRulesMatchesHeaders, HttpRouteRulesMatchesHeadersType,
    HttpRouteRulesMatchesMethod, HttpRouteRulesMatchesPath, HttpRouteRulesMatchesPathType,
    HttpRouteRulesMatchesQueryParams, HttpRouteRulesMatchesQueryParamsType, HttpRouteSpec,
};
use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, PodSpec, PodTemplateSpec, Secret, Service, ServicePort, ServiceSpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{DeleteParams, ObjectMeta, Patch, PatchParams, PostParams};
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
                        namespace: None,
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
