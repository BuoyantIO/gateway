//! Micro-benchmark backing `docs/research/beating-agentgateway.md`:
//! measures the real cost of one full CP pass at bench scale, to
//! ground the competitive analysis in numbers. Run with:
//!   `cargo test --release -p gateway-cp --test probe_scale_cost -- --nocapture`

use std::time::Instant;

use gateway_api::apis::standard::gatewayclasses::{GatewayClass, GatewayClassSpec};
use gateway_api::apis::standard::gateways::{Gateway, GatewayListeners, GatewaySpec};
use gateway_api::apis::standard::httproutes::{
    HTTPRoute, HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs,
    HttpRouteRulesFilters, HttpRouteRulesFiltersRequestHeaderModifier,
    HttpRouteRulesFiltersRequestHeaderModifierAdd, HttpRouteRulesFiltersType,
    HttpRouteRulesMatches, HttpRouteRulesMatchesPath, HttpRouteRulesMatchesPathType, HttpRouteSpec,
};
use k8s_openapi::api::core::v1::{Service, ServiceSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use gateway_cp::diff::diff;
use gateway_cp::resolve::resolve;
use gateway_cp::status::build::build_work;
use gateway_cp::translator::{K8sState, translate_resolution};

const OURS: &str = "gateway.buoyant.io/controller";

fn bench_route(i: usize) -> HTTPRoute {
    // Mirrors gateway-api-bench's probe route template: unique
    // hostname, two rules (real backend on /{i}, invalid backend on /),
    // request-header-modifier filter on each rule.
    let filter = HttpRouteRulesFilters {
        r#type: HttpRouteRulesFiltersType::RequestHeaderModifier,
        request_header_modifier: Some(HttpRouteRulesFiltersRequestHeaderModifier {
            add: Some(vec![HttpRouteRulesFiltersRequestHeaderModifierAdd {
                name: "added-header".into(),
                value: "added-value".into(),
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let rule = |path: String, backend: &str| HttpRouteRules {
        matches: Some(vec![HttpRouteRulesMatches {
            path: Some(HttpRouteRulesMatchesPath {
                r#type: Some(HttpRouteRulesMatchesPathType::PathPrefix),
                value: Some(path),
            }),
            ..Default::default()
        }]),
        backend_refs: Some(vec![HttpRouteRulesBackendRefs {
            name: backend.into(),
            port: Some(80),
            ..Default::default()
        }]),
        filters: Some(vec![filter.clone()]),
        ..Default::default()
    };
    HTTPRoute {
        metadata: ObjectMeta {
            namespace: Some("default".into()),
            name: Some(format!("{i}-route")),
            ..Default::default()
        },
        spec: HttpRouteSpec {
            parent_refs: Some(vec![HttpRouteParentRefs {
                name: "buoyant".into(),
                namespace: Some("buoyant".into()),
                ..Default::default()
            }]),
            hostnames: Some(vec![format!("{i}-route.example.com")]),
            rules: Some(vec![
                rule(format!("/{i}"), "backend"),
                rule("/".into(), "invalid-backend"),
            ]),
        },
        status: None,
    }
}

fn state_with(n: usize) -> K8sState {
    K8sState {
        gateway_classes: vec![GatewayClass {
            metadata: ObjectMeta {
                name: Some("buoyant-gateway".into()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: OURS.into(),
                ..Default::default()
            },
            status: None,
        }],
        gateways: vec![Gateway {
            metadata: ObjectMeta {
                namespace: Some("buoyant".into()),
                name: Some("buoyant".into()),
                uid: Some("uid-1".into()),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "buoyant-gateway".into(),
                listeners: vec![GatewayListeners {
                    name: "http".into(),
                    protocol: "HTTP".into(),
                    port: 80,
                    ..Default::default()
                }],
                ..Default::default()
            },
            status: None,
        }],
        http_routes: (0..n).map(bench_route).collect(),
        services: vec![Service {
            metadata: ObjectMeta {
                namespace: Some("default".into()),
                name: Some("backend".into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: Some("10.96.0.50".into()),
                ..Default::default()
            }),
            status: None,
        }],
        secrets: vec![],
    }
}

fn time<T>(label: &str, iters: u32, mut f: impl FnMut() -> T) {
    // Warm up once, then take the minimum over `iters` runs.
    let _ = f();
    let mut best = f64::MAX;
    for _ in 0..iters {
        let t = Instant::now();
        let out = f();
        let el = t.elapsed().as_secs_f64() * 1000.0;
        std::hint::black_box(out);
        if el < best {
            best = el;
        }
    }
    println!("  {label:<28} {best:9.3} ms");
}

#[test]
fn full_pass_cost() {
    for n in [20usize, 2000, 10000] {
        println!("N = {n} routes:");
        let state = state_with(n);
        let state_plus = state_with(n + 1);

        // collect_state() clones every object out of the reflector
        // stores into fresh Vecs; cloning the component Vecs measures
        // the same work.
        time("clone state (collect_state)", 10, || {
            (
                state.gateway_classes.clone(),
                state.gateways.clone(),
                state.http_routes.clone(),
                state.services.clone(),
                state.secrets.clone(),
            )
        });
        time("resolve", 10, || resolve(&state, OURS));

        let resolution = resolve(&state, OURS);
        time("translate_resolution", 10, || {
            translate_resolution(&resolution)
        });

        let world = translate_resolution(&resolution);
        let resolution_plus = resolve(&state_plus, OURS);
        let world_plus = translate_resolution(&resolution_plus);
        time("clone world (publish)", 10, || world.clone());

        let (prev, next) = (
            world.values().next().unwrap(),
            world_plus.values().next().unwrap(),
        );
        time("diff N vs N+1", 10, || diff(prev, next));

        let now = k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            k8s_openapi::jiff::Timestamp::now(),
        );
        time("build_work (status)", 10, || build_work(&resolution, &now));
        println!();
    }
}
