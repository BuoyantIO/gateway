//! Incremental world state for the watch loop.
//!
//! The cache owns a copy of the Kubernetes state. For a route change
//! it exploits one invariant: everything that is not a route only
//! changes through a full pass, so between full passes the rest of
//! the world is frozen. That means a route's old output can be
//! *recomputed* from its old spec instead of remembered:
//!
//! 1. resolve + translate just the route, before swapping it — its
//!    old snapshot entries;
//! 2. swap the route into the state, resolve + translate again — its
//!    new entries;
//! 3. `diff` the two, per gateway — the delta to broadcast.
//!
//! The only state carried across events is two small maps that can't
//! be derived from a single route: the `attachedRoutes` counters
//! (recounting would visit every route) and per-backend reference
//! counts (several routes can share a backend, and its snapshot
//! entry may only be removed with the last reference).
//!
//! Both maps are rebuilt from scratch on every full pass, so any
//! drift ends at the next non-route event. A test below applies
//! hundreds of random route changes and checks, after every one,
//! that this shortcut produces exactly the same world as
//! recomputing everything from scratch.

use std::collections::{HashMap, HashSet};

use gateway_api::apis::standard::httproutes::HTTPRoute;
use gateway_cp_proto::v1 as pb;
use gateway_state::BackendKey;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

use crate::diff::diff;
use crate::resolve::{Resolution, resolve, resolve_scoped};
use crate::snapshot::{GatewayId, Snapshot};
use crate::status::{StatusWork, build_work};
use crate::translator::{K8sState, RouteId, translate_resolution};

#[derive(Default)]
pub struct WorldCache {
    state: K8sState,
    /// `attachedRoutes` per gateway listener, in spec order.
    counters: HashMap<GatewayId, Vec<u32>>,
    /// Routes referencing each backend in each gateway's snapshot.
    backend_refs: HashMap<(GatewayId, BackendKey), u32>,
}

impl WorldCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> &K8sState {
        &self.state
    }

    /// Recompute the world from `state` and rebuild the counters and
    /// backend refcounts. Returns the snapshots (for
    /// [`crate::ServerState::publish`]) and the desired status.
    pub fn full_pass(
        &mut self,
        state: K8sState,
        controller_name: &str,
        now: &Time,
    ) -> (HashMap<GatewayId, Snapshot>, StatusWork) {
        self.state = state;
        let resolution = resolve(&self.state, controller_name);
        let world = translate_resolution(&resolution);

        self.counters = counters_of(&resolution);
        self.backend_refs.clear();
        for (gw, bk) in backend_refs_of(&resolution) {
            *self.backend_refs.entry((gw, bk)).or_default() += 1;
        }

        let status = build_work(&resolution, now);
        (world, status)
    }

    /// Apply one route change. `route` is `None` for a delete.
    /// Returns per-gateway deltas and the refreshed status.
    pub fn route_event(
        &mut self,
        route_id: &RouteId,
        route: Option<HTTPRoute>,
        controller_name: &str,
        now: &Time,
    ) -> (Vec<(GatewayId, pb::ConfigUpdate)>, StatusWork) {
        let scope = Some((route_id.0.as_str(), route_id.1.as_str()));

        // The route's old output, recomputed from its old spec.
        let (old_world, old_counts, old_backends) = {
            let scoped = resolve_scoped(&self.state, controller_name, scope);
            (
                translate_resolution(&scoped),
                counters_of(&scoped),
                backend_refs_of(&scoped),
            )
        };

        // Swap the route, then its new output the same way.
        self.state.http_routes.retain(|r| {
            r.metadata.namespace.as_deref() != Some(route_id.0.as_str())
                || r.metadata.name.as_deref() != Some(route_id.1.as_str())
        });
        if let Some(r) = route {
            self.state.http_routes.push(r);
        }
        let mut scoped = resolve_scoped(&self.state, controller_name, scope);
        let new_world = translate_resolution(&scoped);
        let new_counts = counters_of(&scoped);
        let new_backends = backend_refs_of(&scoped);

        // Counters: the scoped counts are this route's 0/1
        // contribution per listener; shift the totals by the change.
        for (gw, counts) in &old_counts {
            for (idx, n) in counts.iter().enumerate() {
                if let Some(c) = self.counters.get_mut(gw).and_then(|v| v.get_mut(idx)) {
                    *c = c.saturating_sub(*n);
                }
            }
        }
        for (gw, counts) in &new_counts {
            for (idx, n) in counts.iter().enumerate() {
                if let Some(c) = self.counters.get_mut(gw).and_then(|v| v.get_mut(idx)) {
                    *c += *n;
                }
            }
        }
        sync_counters(&mut scoped, &self.counters);
        let status = build_work(&scoped, now);
        drop(scoped);

        // Backend refcounts shift the same way.
        for (gw, bk) in old_backends {
            if let Some(slot) = self.backend_refs.get_mut(&(gw.clone(), bk.clone())) {
                *slot = slot.saturating_sub(1);
                if *slot == 0 {
                    self.backend_refs.remove(&(gw, bk));
                }
            }
        }
        for (gw, bk) in new_backends {
            *self.backend_refs.entry((gw, bk)).or_default() += 1;
        }

        // Delta per gateway = plain diff of the route's old and new
        // output. The gateway-level entries (binds, listeners,
        // secrets) are identical on both sides and cancel out. The
        // one correction: a backend leaving this route's output may
        // still be referenced by other routes — drop its remove.
        let empty = Snapshot::default();
        let ids: HashSet<&GatewayId> = old_world.keys().chain(new_world.keys()).collect();
        let mut deltas = Vec::new();
        for id in ids {
            let old_slice = old_world.get(id).unwrap_or(&empty);
            let new_slice = new_world.get(id).unwrap_or(&empty);
            let Some(mut delta) = diff(old_slice, new_slice) else {
                continue;
            };
            delta.removes.retain(|rm| match &rm.key {
                Some(pb::remove::Key::Backend(k)) => !self
                    .backend_refs
                    .contains_key(&(id.clone(), BackendKey::new(&k.name))),
                _ => true,
            });
            if delta.upserts.is_empty() && delta.removes.is_empty() {
                continue;
            }
            deltas.push((id.clone(), delta));
        }
        (deltas, status)
    }
}

/// `attachedRoutes` per gateway listener, in spec order.
fn counters_of(resolution: &Resolution<'_>) -> HashMap<GatewayId, Vec<u32>> {
    resolution
        .gateways
        .iter()
        .map(|g| {
            (
                g.id.clone(),
                g.listeners.iter().map(|l| l.attached_routes).collect(),
            )
        })
        .collect()
}

/// One entry per (route x gateway) backend reference in the
/// resolution — the unit the refcounts count.
fn backend_refs_of(resolution: &Resolution<'_>) -> Vec<(GatewayId, BackendKey)> {
    use crate::resolve::BackendOutcome;
    let mut out = Vec::new();
    for route in &resolution.routes {
        let Some(id) = route.gateway_id.as_ref() else {
            continue;
        };
        let mut seen: HashSet<&str> = HashSet::new();
        for rule in &route.rule_backends {
            for backend in rule {
                if let BackendOutcome::Resolved { key, .. } = &backend.outcome
                    && backend.backend_ref.port.is_some()
                    && seen.insert(key)
                {
                    out.push((id.clone(), BackendKey::new(key)));
                }
            }
        }
    }
    out
}

/// Overwrite the scoped resolution's per-route counts with the
/// authoritative totals so status reports the real numbers.
fn sync_counters(resolution: &mut Resolution<'_>, counters: &HashMap<GatewayId, Vec<u32>>) {
    for gw in &mut resolution.gateways {
        if let Some(totals) = counters.get(&gw.id) {
            for (lr, total) in gw.listeners.iter_mut().zip(totals) {
                lr.attached_routes = *total;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_api::apis::standard::gatewayclasses::{GatewayClass, GatewayClassSpec};
    use gateway_api::apis::standard::gateways::{Gateway, GatewayListeners, GatewaySpec};
    use gateway_api::apis::standard::httproutes::{
        HttpRouteParentRefs, HttpRouteRules, HttpRouteRulesBackendRefs, HttpRouteSpec,
    };
    use k8s_openapi::api::core::v1::{Service, ServiceSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    use crate::server::apply_delta_to;
    use crate::translator::translate;

    const OURS: &str = "gateway.test/controller";

    /// Deterministic PRNG (xorshift) so failures reproduce.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self, bound: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % bound
        }
    }

    fn base_state() -> K8sState {
        let gc = GatewayClass {
            metadata: ObjectMeta {
                name: Some("cls".into()),
                ..Default::default()
            },
            spec: GatewayClassSpec {
                controller_name: OURS.into(),
                ..Default::default()
            },
            status: None,
        };
        let gw = |ns: &str, name: &str, listeners: Vec<GatewayListeners>| Gateway {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                uid: Some(format!("uid-{name}")),
                ..Default::default()
            },
            spec: GatewaySpec {
                gateway_class_name: "cls".into(),
                listeners,
                ..Default::default()
            },
            status: None,
        };
        let listener = |name: &str, port: i32, hostname: Option<&str>| GatewayListeners {
            name: name.into(),
            protocol: "HTTP".into(),
            port,
            hostname: hostname.map(String::from),
            ..Default::default()
        };
        let svc = |ns: &str, name: &str| Service {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: Some("10.0.0.1".into()),
                ..Default::default()
            }),
            status: None,
        };
        K8sState {
            gateway_classes: vec![gc],
            gateways: vec![
                gw(
                    "demo",
                    "gw-a",
                    vec![
                        listener("web", 80, Some("a.example.com")),
                        listener("api", 8080, None),
                    ],
                ),
                gw("demo", "gw-b", vec![listener("web", 80, None)]),
            ],
            http_routes: vec![],
            services: vec![svc("demo", "svc-1"), svc("demo", "svc-2")],
            secrets: vec![],
        }
    }

    fn random_route(rng: &mut Rng, i: u64) -> HTTPRoute {
        let parents = match rng.next(4) {
            0 => vec![("gw-a", None)],
            1 => vec![("gw-b", None)],
            2 => vec![("gw-a", Some("web")), ("gw-b", None)],
            _ => vec![("gw-missing", None)],
        };
        let hostnames = match rng.next(3) {
            0 => None,
            1 => Some(vec!["a.example.com".to_string()]),
            _ => Some(vec!["other.example.com".to_string()]),
        };
        let backend = match rng.next(3) {
            0 => ("svc-1", Some(8080)),
            1 => ("svc-missing", Some(8080)),
            _ => ("svc-2", None),
        };
        HTTPRoute {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some(format!("route-{i}")),
                ..Default::default()
            },
            spec: HttpRouteSpec {
                parent_refs: Some(
                    parents
                        .into_iter()
                        .map(|(name, section)| HttpRouteParentRefs {
                            name: name.into(),
                            section_name: section.map(String::from),
                            ..Default::default()
                        })
                        .collect(),
                ),
                hostnames,
                rules: Some(vec![HttpRouteRules {
                    backend_refs: Some(vec![HttpRouteRulesBackendRefs {
                        name: backend.0.into(),
                        port: backend.1,
                        ..Default::default()
                    }]),
                    ..Default::default()
                }]),
            },
            status: None,
        }
    }

    /// After every randomized step, the incrementally maintained
    /// world and counters must equal a from-scratch resolve +
    /// translate of the same state. The full recompute is the
    /// reference; the shortcut must never disagree with it.
    #[test]
    fn incremental_matches_full_recompute() {
        let mut rng = Rng(0x5eed);
        let now = Time(k8s_openapi::jiff::Timestamp::from_second(0).unwrap());

        let mut cache = WorldCache::new();
        let mut model = base_state();

        // Initial full pass, as the loop would run on InitDone.
        let (mut shadow, _) = cache.full_pass(clone_state(&model), OURS, &now);

        for step in 0..400u64 {
            let roll = rng.next(10);
            if roll == 9 {
                // A non-route event: full pass, shadow reset.
                let (world, _) = cache.full_pass(clone_state(&model), OURS, &now);
                shadow = world;
            } else {
                let i = rng.next(12); // small id space forces updates
                let id: RouteId = ("demo".to_string(), format!("route-{i}"));
                let route = if roll < 7 {
                    Some(random_route(&mut rng, i))
                } else {
                    None // delete (may target a route that doesn't exist)
                };
                model
                    .http_routes
                    .retain(|r| r.metadata.name.as_deref() != Some(id.1.as_str()));
                if let Some(r) = &route {
                    model.http_routes.push(r.clone());
                }
                let (deltas, status) = cache.route_event(&id, route, OURS, &now);
                for (gw_id, delta) in deltas {
                    apply_delta_to(shadow.entry(gw_id).or_default(), &delta);
                }
                // Status must report the authoritative counters.
                let reference = resolve(&model, OURS);
                for (og, sg) in reference.gateways.iter().zip(&status.gateways) {
                    let want: Vec<u32> = og.listeners.iter().map(|l| l.attached_routes).collect();
                    let got: Vec<u32> =
                        sg.1.listeners
                            .as_deref()
                            .unwrap_or(&[])
                            .iter()
                            .map(|l| u32::try_from(l.attached_routes).unwrap_or(0))
                            .collect();
                    assert_eq!(want, got, "attachedRoutes diverged at step {step}");
                }
            }

            let expected = translate(&model, OURS);
            assert_eq!(
                non_empty(&expected),
                non_empty(&shadow),
                "world diverged at step {step}"
            );
        }
    }

    /// Snapshot maps can legitimately differ in empty entries (a
    /// gateway whose routes all left keeps an empty slice on one side
    /// only); compare content, not presence of empties.
    fn non_empty(world: &HashMap<GatewayId, Snapshot>) -> HashMap<&GatewayId, &Snapshot> {
        world
            .iter()
            .filter(|(_, s)| *s != &Snapshot::default())
            .collect()
    }

    fn clone_state(s: &K8sState) -> K8sState {
        K8sState {
            gateway_classes: s.gateway_classes.clone(),
            gateways: s.gateways.clone(),
            http_routes: s.http_routes.clone(),
            services: s.services.clone(),
            secrets: s.secrets.clone(),
        }
    }
}
