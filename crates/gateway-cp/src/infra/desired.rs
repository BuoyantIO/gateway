//! Desired per-Gateway data-plane objects.
//!
//! Pure functions from a `Gateway` to the `ServiceAccount`,
//! `Deployment`, and `Service` the CP provisions for it. No API
//! calls here — the writer task owns those.

use std::collections::BTreeMap;

use gateway_api::apis::standard::gateways::Gateway;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, EnvVar, HTTPGetAction, PodSpec, PodTemplateSpec, Probe, Service,
    ServiceAccount, ServicePort, ServiceSpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::Resource;

use super::{
    GATEWAY_NAME_LABEL, MANAGED_BY_LABEL, MANAGED_BY_VALUE, PROVISIONING_ANNOTATION,
    PROVISIONING_DISABLED, SERVICE_TYPE_ANNOTATION,
};

/// Kubernetes object-name length cap (RFC 1123 label).
const MAX_NAME: usize = 63;

/// Readiness endpoint served by gatewayd's admin server.
const READY_PATH: &str = "/healthz/ready";

/// Everything the CP provisions for one Gateway.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayInfra {
    pub service_account: ServiceAccount,
    pub deployment: Deployment,
    pub service: Service,
}

/// Provisioner-level knobs, carried from CP flags.
#[derive(Debug, Clone)]
pub struct InfraConfig {
    /// gatewayd image the provisioned Deployment runs.
    pub dp_image: String,
    /// Control-plane gRPC URL the DP dials
    /// (e.g. `http://gateway-cp.gateway-system.svc:8443`).
    pub cp_url: String,
    /// Admin port for the readiness probe.
    pub admin_port: u16,
}

/// The full desired set for one translate pass: infra for every
/// Gateway owned by `controller_name`, sorted by `(namespace, name)`
/// so equal states compare equal and the publish channel can dedup.
pub fn desired_set(
    state: &crate::translator::K8sState,
    controller_name: &str,
    cfg: &InfraConfig,
) -> Vec<GatewayInfra> {
    let owned = crate::resolve::collect_owned_classes(state, controller_name);
    let mut set: Vec<GatewayInfra> = state
        .gateways
        .iter()
        .filter(|gw| owned.contains(gw.spec.gateway_class_name.as_str()))
        .filter_map(|gw| desired(gw, cfg))
        .collect();
    set.sort_by_key(|i| {
        (
            i.deployment.metadata.namespace.clone(),
            i.deployment.metadata.name.clone(),
        )
    });
    set
}

/// Build the desired infra for `gw`. Returns `None` when the
/// Gateway is self-managed (opt-out annotation) or lacks the
/// identity fields (name, namespace, uid) needed to own objects —
/// both mean "provision nothing", never an error.
pub fn desired(gw: &Gateway, cfg: &InfraConfig) -> Option<GatewayInfra> {
    let name = gw.meta().name.as_deref()?;
    let namespace = gw.meta().namespace.as_deref()?;
    let uid = gw.meta().uid.as_deref()?;

    let self_managed = gw
        .meta()
        .annotations
        .as_ref()
        .and_then(|a| a.get(PROVISIONING_ANNOTATION))
        .is_some_and(|v| v == PROVISIONING_DISABLED);
    if self_managed {
        return None;
    }

    let object_name = object_name(name);
    let selector_labels: BTreeMap<String, String> =
        [(GATEWAY_NAME_LABEL.to_string(), name.to_string())].into();

    // Gateway.spec.infrastructure labels/annotations go onto every
    // created object (spec: Extended support); ours win on conflict.
    let infrastructure = gw.spec.infrastructure.as_ref();
    let mut labels: BTreeMap<String, String> = infrastructure
        .and_then(|i| i.labels.clone())
        .unwrap_or_default();
    labels.extend(selector_labels.clone());
    labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string());
    let annotations = infrastructure.and_then(|i| i.annotations.clone());

    let owner = OwnerReference {
        api_version: Gateway::api_version(&()).into_owned(),
        kind: Gateway::kind(&()).into_owned(),
        name: name.to_string(),
        uid: uid.to_string(),
        controller: Some(true),
        ..Default::default()
    };
    let metadata = ObjectMeta {
        name: Some(object_name),
        namespace: Some(namespace.to_string()),
        labels: Some(labels.clone()),
        annotations: annotations.clone(),
        owner_references: Some(vec![owner]),
        ..Default::default()
    };

    let ports = listener_ports(gw);

    Some(GatewayInfra {
        service_account: ServiceAccount {
            metadata: metadata.clone(),
            ..Default::default()
        },
        deployment: deployment(
            gw,
            cfg,
            metadata.clone(),
            &selector_labels,
            &labels,
            annotations,
            &ports,
        ),
        service: service(gw, metadata, &selector_labels, &ports),
    })
}

fn deployment(
    gw: &Gateway,
    cfg: &InfraConfig,
    metadata: ObjectMeta,
    selector_labels: &BTreeMap<String, String>,
    labels: &BTreeMap<String, String>,
    annotations: Option<BTreeMap<String, String>>,
    ports: &[(String, i32)],
) -> Deployment {
    let client_id = format!(
        "{}/{}",
        gw.meta().namespace.as_deref().unwrap_or_default(),
        gw.meta().name.as_deref().unwrap_or_default(),
    );
    let service_account_name = metadata.name.clone();
    let admin_port = i32::from(cfg.admin_port);

    let mut container_ports: Vec<ContainerPort> = ports
        .iter()
        .map(|(name, port)| ContainerPort {
            name: Some(name.clone()),
            container_port: *port,
            ..Default::default()
        })
        .collect();
    // A listener on the admin port is a config error the DP surfaces
    // at bind time; here we only avoid emitting a duplicate entry.
    if ports.iter().all(|(_, p)| *p != admin_port) {
        container_ports.push(ContainerPort {
            name: Some("admin".into()),
            container_port: admin_port,
            ..Default::default()
        });
    }

    Deployment {
        metadata,
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(selector_labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels.clone()),
                    annotations,
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name,
                    containers: vec![Container {
                        name: "gatewayd".into(),
                        image: Some(cfg.dp_image.clone()),
                        image_pull_policy: Some("IfNotPresent".into()),
                        args: Some(vec![
                            format!("--control-plane={}", cfg.cp_url),
                            format!("--client-id={client_id}"),
                            format!("--admin-addr=0.0.0.0:{}", cfg.admin_port),
                        ]),
                        env: Some(vec![EnvVar {
                            name: "RUST_LOG".into(),
                            value: Some("info".into()),
                            ..Default::default()
                        }]),
                        ports: Some(container_ports),
                        readiness_probe: Some(ready_probe(admin_port, 10, None)),
                        startup_probe: Some(ready_probe(admin_port, 1, Some(60))),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The Service types the annotation may select. Anything else falls
/// back to the default with a warning — passing a bad value through
/// would produce a Service the apiserver never accepts and wedge the
/// apply loop on permanent retries.
const SERVICE_TYPES: [&str; 3] = ["ClusterIP", "NodePort", "LoadBalancer"];

const DEFAULT_SERVICE_TYPE: &str = "LoadBalancer";

fn service(
    gw: &Gateway,
    metadata: ObjectMeta,
    selector_labels: &BTreeMap<String, String>,
    ports: &[(String, i32)],
) -> Service {
    let annotated = gw
        .meta()
        .annotations
        .as_ref()
        .and_then(|a| a.get(SERVICE_TYPE_ANNOTATION));
    let service_type = match annotated {
        Some(v) if SERVICE_TYPES.contains(&v.as_str()) => v.clone(),
        Some(v) => {
            let gateway = format!(
                "{}/{}",
                gw.meta().namespace.as_deref().unwrap_or_default(),
                gw.meta().name.as_deref().unwrap_or_default(),
            );
            tracing::warn!(
                gateway,
                value = %v,
                annotation = SERVICE_TYPE_ANNOTATION,
                "unsupported service type; using {DEFAULT_SERVICE_TYPE}"
            );
            DEFAULT_SERVICE_TYPE.to_string()
        }
        None => DEFAULT_SERVICE_TYPE.to_string(),
    };

    Service {
        metadata,
        spec: Some(ServiceSpec {
            type_: Some(service_type),
            selector: Some(selector_labels.clone()),
            ports: Some(
                ports
                    .iter()
                    .map(|(name, port)| ServicePort {
                        name: Some(name.clone()),
                        port: *port,
                        target_port: Some(IntOrString::Int(*port)),
                        protocol: Some("TCP".into()),
                        ..Default::default()
                    })
                    .collect(),
            ),
            ..Default::default()
        }),
        status: None,
    }
}

/// `{gateway-name}-gatewayd`, capped at 63 chars with no trailing
/// `-` (the suffix avoids colliding with a user Service that shares
/// the Gateway's name). `pub(crate)`: the resolution pass uses it to
/// find the managed Service a Gateway's address comes from.
pub(crate) fn object_name(gateway_name: &str) -> String {
    let mut name = format!("{gateway_name}-gatewayd");
    while name.len() > MAX_NAME {
        name.pop();
    }
    name.trim_end_matches('-').to_string()
}

/// Unique listener ports in first-seen order, each named after the
/// first listener's protocol (`http-80` style; the IANA service-name
/// cap is 15 chars).
fn listener_ports(gw: &Gateway) -> Vec<(String, i32)> {
    let mut out: Vec<(String, i32)> = Vec::new();
    for l in &gw.spec.listeners {
        if out.iter().any(|(_, p)| *p == l.port) {
            continue;
        }
        out.push((port_name(&l.protocol, l.port), l.port));
    }
    out
}

/// `{protocol}-{port}`, lowercased and sanitized into the 15-char
/// IANA service-name cap. Only the protocol part is truncated — the
/// port suffix always survives, so two ports sharing a long
/// (implementation-specific) protocol can never collide on the name.
fn port_name(protocol: &str, port: i32) -> String {
    let suffix = port.to_string();
    let budget = 15 - suffix.len() - 1;
    let mut proto: String = protocol
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    proto.truncate(budget);
    let proto = proto.trim_matches('-');
    // A port name must contain a letter; an all-symbol protocol
    // (nothing left after sanitizing) gets a neutral stand-in.
    if proto.is_empty() {
        return format!("port-{suffix}");
    }
    format!("{proto}-{suffix}")
}

fn ready_probe(admin_port: i32, period_seconds: i32, failure_threshold: Option<i32>) -> Probe {
    Probe {
        http_get: Some(HTTPGetAction {
            path: Some(READY_PATH.into()),
            port: IntOrString::Int(admin_port),
            ..Default::default()
        }),
        period_seconds: Some(period_seconds),
        failure_threshold,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_api::apis::standard::gatewayclasses::{GatewayClass, GatewayClassSpec};
    use gateway_api::apis::standard::gateways::{
        GatewayInfrastructure, GatewayListeners, GatewaySpec,
    };

    use crate::translator::K8sState;

    fn listener(name: &str, protocol: &str, port: i32) -> GatewayListeners {
        GatewayListeners {
            name: name.into(),
            protocol: protocol.into(),
            port,
            ..Default::default()
        }
    }

    fn gateway(ns: &str, name: &str, listeners: Vec<GatewayListeners>) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                uid: Some("uid-1234".into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "buoyant-gateway".into(),
                listeners,
                ..Default::default()
            },
            status: None,
        }
    }

    fn config() -> InfraConfig {
        InfraConfig {
            dp_image: "gateway-data-plane:latest".into(),
            cp_url: "http://gateway-cp.gateway-system.svc:8443".into(),
            admin_port: 15021,
        }
    }

    fn container(infra: &GatewayInfra) -> &Container {
        &infra
            .deployment
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap()
            .containers[0]
    }

    #[test]
    fn desired_set_filters_by_class_ownership_and_sorts() {
        let ours = "gateway.buoyant.io/controller";
        let gc = |name: &str, controller: &str| GatewayClass {
            metadata: ObjectMeta {
                name: Some(name.into()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: controller.into(),
                ..Default::default()
            },
            status: None,
        };
        let gw_of_class = |ns: &str, name: &str, class: &str| {
            let mut gw = gateway(ns, name, vec![listener("http", "HTTP", 80)]);
            gw.spec.gateway_class_name = class.into();
            gw
        };

        let state = K8sState {
            gateway_classes: vec![
                gc("buoyant-gateway", ours),
                gc("other", "example.com/other"),
            ],
            gateways: vec![
                gw_of_class("zz", "late", "buoyant-gateway"),
                gw_of_class("demo", "foreign", "other"),
                gw_of_class("aa", "early", "buoyant-gateway"),
            ],
            ..Default::default()
        };

        let set = desired_set(&state, ours, &config());
        let names: Vec<&str> = set
            .iter()
            .map(|i| i.deployment.metadata.name.as_deref().unwrap())
            .collect();
        assert_eq!(names, vec!["early-gatewayd", "late-gatewayd"]);
    }

    #[test]
    fn objects_carry_identity_labels_and_owner() {
        let gw = gateway("demo", "web", vec![listener("http", "HTTP", 80)]);
        let infra = desired(&gw, &config()).expect("provisioned");

        for meta in [
            &infra.service_account.metadata,
            &infra.deployment.metadata,
            &infra.service.metadata,
        ] {
            assert_eq!(meta.name.as_deref(), Some("web-gatewayd"));
            assert_eq!(meta.namespace.as_deref(), Some("demo"));
            let labels = meta.labels.as_ref().unwrap();
            assert_eq!(labels.get(GATEWAY_NAME_LABEL).unwrap(), "web");
            assert_eq!(labels.get(MANAGED_BY_LABEL).unwrap(), MANAGED_BY_VALUE);
            let owner = &meta.owner_references.as_ref().unwrap()[0];
            assert_eq!(owner.kind, "Gateway");
            assert_eq!(owner.api_version, "gateway.networking.k8s.io/v1");
            assert_eq!(owner.name, "web");
            assert_eq!(owner.uid, "uid-1234");
            assert_eq!(owner.controller, Some(true));
        }
    }

    #[test]
    fn self_managed_annotation_provisions_nothing() {
        let mut gw = gateway("demo", "web", vec![listener("http", "HTTP", 80)]);
        gw.metadata.annotations = Some(
            [(
                PROVISIONING_ANNOTATION.to_string(),
                PROVISIONING_DISABLED.to_string(),
            )]
            .into(),
        );
        assert!(desired(&gw, &config()).is_none());

        // Any other value keeps provisioning on.
        gw.metadata.annotations =
            Some([(PROVISIONING_ANNOTATION.to_string(), "on".to_string())].into());
        assert!(desired(&gw, &config()).is_some());
    }

    #[test]
    fn missing_uid_provisions_nothing() {
        let mut gw = gateway("demo", "web", vec![listener("http", "HTTP", 80)]);
        gw.metadata.uid = None;
        assert!(desired(&gw, &config()).is_none());
    }

    #[test]
    fn long_names_are_capped_without_trailing_dash() {
        // 62-char gateway name: the cap lands right after the joining
        // '-', which must then be trimmed.
        let long = "a".repeat(62);
        let gw = gateway("demo", &long, vec![listener("http", "HTTP", 80)]);
        let infra = desired(&gw, &config()).unwrap();

        let name = infra.deployment.metadata.name.as_deref().unwrap();
        assert!(name.len() <= 63, "{name}");
        assert!(!name.ends_with('-'), "{name}");
        assert_eq!(name, long);
    }

    #[test]
    fn ports_dedup_and_admin_is_added() {
        let gw = gateway(
            "demo",
            "web",
            vec![
                listener("http", "HTTP", 80),
                listener("a-example", "HTTPS", 443),
                listener("b-example", "HTTPS", 443),
            ],
        );
        let infra = desired(&gw, &config()).unwrap();

        let container_ports: Vec<(Option<&str>, i32)> = container(&infra)
            .ports
            .as_ref()
            .unwrap()
            .iter()
            .map(|p| (p.name.as_deref(), p.container_port))
            .collect();
        assert_eq!(
            container_ports,
            vec![
                (Some("http-80"), 80),
                (Some("https-443"), 443),
                (Some("admin"), 15021),
            ]
        );

        // The Service exposes listener ports only — never admin.
        let svc_ports = infra.service.spec.as_ref().unwrap().ports.as_ref().unwrap();
        let seen: Vec<(Option<&str>, i32, &IntOrString)> = svc_ports
            .iter()
            .map(|p| (p.name.as_deref(), p.port, p.target_port.as_ref().unwrap()))
            .collect();
        assert_eq!(
            seen,
            vec![
                (Some("http-80"), 80, &IntOrString::Int(80)),
                (Some("https-443"), 443, &IntOrString::Int(443)),
            ]
        );
    }

    #[test]
    fn long_protocol_port_names_keep_the_port_suffix() {
        // Implementation-specific protocols can exceed the 15-char
        // port-name cap; truncation must never eat the port suffix
        // or two such ports collide on the same name.
        let a = port_name("example.com/custom-proto", 8080);
        let b = port_name("example.com/custom-proto", 8443);
        assert_eq!(a, "example-co-8080");
        assert_eq!(b, "example-co-8443");
    }

    #[test]
    fn symbol_only_protocol_gets_a_neutral_port_name() {
        assert_eq!(port_name("///", 80), "port-80");
    }

    #[test]
    fn listener_on_admin_port_does_not_duplicate_container_port() {
        let gw = gateway("demo", "web", vec![listener("odd", "HTTP", 15021)]);
        let infra = desired(&gw, &config()).unwrap();

        let ports = container(&infra).ports.as_ref().unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].container_port, 15021);
    }

    #[test]
    fn args_env_and_probes() {
        let gw = gateway("demo", "web", vec![listener("http", "HTTP", 80)]);
        let infra = desired(&gw, &config()).unwrap();
        let c = container(&infra);

        assert_eq!(
            c.args.as_ref().unwrap(),
            &vec![
                "--control-plane=http://gateway-cp.gateway-system.svc:8443".to_string(),
                "--client-id=demo/web".to_string(),
                "--admin-addr=0.0.0.0:15021".to_string(),
            ]
        );
        assert_eq!(c.image.as_deref(), Some("gateway-data-plane:latest"));

        let ready = c.readiness_probe.as_ref().unwrap();
        assert_eq!(ready.period_seconds, Some(10));
        assert_eq!(ready.failure_threshold, None);
        let get = ready.http_get.as_ref().unwrap();
        assert_eq!(get.path.as_deref(), Some(READY_PATH));
        assert_eq!(get.port, IntOrString::Int(15021));

        let startup = c.startup_probe.as_ref().unwrap();
        assert_eq!(startup.period_seconds, Some(1));
        assert_eq!(startup.failure_threshold, Some(60));
    }

    #[test]
    fn pod_uses_the_provisioned_service_account() {
        let gw = gateway("demo", "web", vec![listener("http", "HTTP", 80)]);
        let infra = desired(&gw, &config()).unwrap();
        let pod = infra
            .deployment
            .spec
            .as_ref()
            .unwrap()
            .template
            .spec
            .as_ref()
            .unwrap();
        assert_eq!(pod.service_account_name.as_deref(), Some("web-gatewayd"));
    }

    #[test]
    fn service_type_defaults_to_loadbalancer_and_honors_annotation() {
        let gw = gateway("demo", "web", vec![listener("http", "HTTP", 80)]);
        let infra = desired(&gw, &config()).unwrap();
        assert_eq!(
            infra.service.spec.as_ref().unwrap().type_.as_deref(),
            Some("LoadBalancer")
        );

        let mut gw = gateway("demo", "web", vec![listener("http", "HTTP", 80)]);
        gw.metadata.annotations =
            Some([(SERVICE_TYPE_ANNOTATION.to_string(), "ClusterIP".to_string())].into());
        let infra = desired(&gw, &config()).unwrap();
        assert_eq!(
            infra.service.spec.as_ref().unwrap().type_.as_deref(),
            Some("ClusterIP")
        );
    }

    #[test]
    fn unsupported_service_type_annotation_falls_back_to_default() {
        let mut gw = gateway("demo", "web", vec![listener("http", "HTTP", 80)]);
        // Wrong case: Kubernetes Service types are case-sensitive, so
        // this would be rejected by the apiserver on every apply.
        gw.metadata.annotations =
            Some([(SERVICE_TYPE_ANNOTATION.to_string(), "clusterip".to_string())].into());
        let infra = desired(&gw, &config()).unwrap();
        assert_eq!(
            infra.service.spec.as_ref().unwrap().type_.as_deref(),
            Some("LoadBalancer")
        );
    }

    #[test]
    fn selector_stays_minimal_under_infrastructure_labels() {
        let mut gw = gateway("demo", "web", vec![listener("http", "HTTP", 80)]);
        gw.spec.infrastructure = Some(GatewayInfrastructure {
            labels: Some(
                [
                    ("team".to_string(), "edge".to_string()),
                    // Attempts to override our identity labels lose.
                    (GATEWAY_NAME_LABEL.to_string(), "spoof".to_string()),
                ]
                .into(),
            ),
            annotations: Some([("note".to_string(), "hi".to_string())].into()),
            ..Default::default()
        });
        let infra = desired(&gw, &config()).unwrap();

        let labels = infra.deployment.metadata.labels.as_ref().unwrap();
        assert_eq!(labels.get("team").unwrap(), "edge");
        assert_eq!(labels.get(GATEWAY_NAME_LABEL).unwrap(), "web");
        assert_eq!(
            infra
                .deployment
                .metadata
                .annotations
                .as_ref()
                .unwrap()
                .get("note")
                .unwrap(),
            "hi"
        );

        // Selector and Service selector carry only the gateway-name
        // label — user labels must not widen or churn them.
        let selector = infra
            .deployment
            .spec
            .as_ref()
            .unwrap()
            .selector
            .match_labels
            .as_ref()
            .unwrap();
        assert_eq!(selector.len(), 1);
        assert_eq!(selector.get(GATEWAY_NAME_LABEL).unwrap(), "web");
        let svc_selector = infra
            .service
            .spec
            .as_ref()
            .unwrap()
            .selector
            .as_ref()
            .unwrap();
        assert_eq!(svc_selector.len(), 1);

        // Pod template carries the full label set.
        let pod_labels = infra
            .deployment
            .spec
            .as_ref()
            .unwrap()
            .template
            .metadata
            .as_ref()
            .unwrap()
            .labels
            .as_ref()
            .unwrap();
        assert_eq!(pod_labels.get("team").unwrap(), "edge");
        assert_eq!(pod_labels.get(GATEWAY_NAME_LABEL).unwrap(), "web");
    }
}
