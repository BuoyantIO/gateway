//! Route instances configured once per route revision. The store
//! stamps a fresh revision on every route rebuild; anything derived
//! from the route's filter config is valid for exactly one revision,
//! so the cache invalidates itself. Per request only `build()` runs.

use std::collections::HashMap;
use std::sync::Arc;

use gateway_state::{ActiveHttpRoute, RouteKey};
use parking_lot::RwLock;

use gateway_config::extension::FailureMode;
use gateway_config::filter::HttpFilter;

use crate::extension::{Declarations, ExtensionBuilder, Registry};

/// One filter of a route, configured: the builder plus its
/// declarations.
pub(crate) struct ResolvedExtension {
    pub decl: Declarations,
    pub failure_mode: FailureMode,
    pub builder: Arc<dyn ExtensionBuilder>,
}

// Hand-written: the builder is not `Debug`.
impl std::fmt::Debug for ResolvedExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedExtension")
            .field("decl", &self.decl)
            .field("failure_mode", &self.failure_mode)
            .finish_non_exhaustive()
    }
}

type Resolved = Arc<Vec<ResolvedExtension>>;
type ResolveResult = Result<Resolved, Arc<str>>;

/// Configured instances per route, keyed by route and validated by
/// revision.
#[derive(Default)]
pub(crate) struct ExtensionCache {
    routes: RwLock<HashMap<RouteKey, CachedRoute>>,
}

struct CachedRoute {
    revision: u64,
    /// Failures cache too: an invalid filter logs once per revision
    /// and answers 500 cheaply afterwards.
    result: ResolveResult,
}

impl ExtensionCache {
    /// The route's configured instances — cached, or configured now and
    /// cached for the route's current revision.
    ///
    /// # Errors
    /// The resolution failure, already logged once when it was
    /// cached.
    pub(crate) fn for_route(&self, registry: &Registry, route: &ActiveHttpRoute) -> ResolveResult {
        let hit = {
            let routes = self.routes.read();
            routes
                .get(&route.key)
                .and_then(|c| (c.revision == route.revision).then(|| c.result.clone()))
        };
        if let Some(result) = hit {
            return result;
        }

        let result = resolve(registry, route);
        if let Err(e) = &result {
            tracing::error!(route = ?route.key, error = %e, "filter resolution failed");
        }
        self.routes.write().insert(
            route.key.clone(),
            CachedRoute {
                revision: route.revision,
                result: result.clone(),
            },
        );
        result
    }
}

/// Configure every filter of `route`, in order. Every filter is a
/// ref, resolving through the route's `Extension` objects (the
/// ride-along the store attaches).
fn resolve(registry: &Registry, route: &ActiveHttpRoute) -> ResolveResult {
    let mut extensions = Vec::with_capacity(route.filters.len());
    for (i, filter) in route.filters.iter().enumerate() {
        let HttpFilter::ExtensionRef { name, namespace } = filter;
        let object = route
            .extensions
            .iter()
            .find(|e| e.key.name == *name && e.key.namespace == *namespace)
            .and_then(|e| e.object.as_ref())
            .ok_or_else(|| {
                Arc::<str>::from(format!("filter {i}: extension `{name}` is not registered"))
            })?;
        let configured = registry
            .configure(object)
            .map_err(|e| Arc::<str>::from(format!("filter {i}: {e}")))?;
        extensions.push(ResolvedExtension {
            decl: configured.decl,
            failure_mode: configured.failure_mode,
            builder: configured.builder,
        });
    }

    // At most one selector per rule: checked here so the failure is
    // cached with the resolution; the request path keeps a defensive
    // check.
    let selectors: Vec<&str> = route
        .filters
        .iter()
        .zip(&extensions)
        .filter(|(_, e)| e.decl.selects_targets)
        .map(|(f, _)| f.name())
        .collect();
    if selectors.len() > 1 {
        return Err(Arc::from(format!(
            "route declares more than one selecting extension: {selectors:?}"
        )));
    }

    Ok(Arc::new(extensions))
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_config::extension::{ConfigValue, Extension as ExtensionObject, Limits};
    use gateway_config::filter::HttpFilter;
    use gateway_state::{ActiveExtensionRef, BindKey, ExtensionKey, ListenerKey};

    use crate::extension::{
        BodyMode, Declarations, Error, Extension as ExtensionInstance, ExtensionClass,
    };

    struct FixedClass {
        declares: Declarations,
    }

    impl ExtensionClass for FixedClass {
        fn configure(&self, _config: &ConfigValue) -> Result<Arc<dyn ExtensionBuilder>, Error> {
            Ok(Arc::new(FixedBuilder {
                declares: self.declares,
            }))
        }
    }

    struct FixedBuilder {
        declares: Declarations,
    }

    impl ExtensionBuilder for FixedBuilder {
        fn declares(&self) -> Declarations {
            self.declares
        }

        fn build(&self) -> Box<dyn ExtensionInstance> {
            unreachable!("resolution never builds instances")
        }
    }

    fn selector_registry() -> Registry {
        let mut registry = Registry::new();
        registry
            .register(
                "selector",
                Arc::new(FixedClass {
                    declares: Declarations {
                        request_body: BodyMode::Stream,
                        selects_targets: true,
                        ..Default::default()
                    },
                }),
            )
            .unwrap();
        registry
    }

    fn object(name: &str, limits: Limits) -> Arc<ExtensionObject> {
        Arc::new(ExtensionObject {
            namespace: String::new(),
            name: name.into(),
            class: "selector".into(),
            failure_mode: FailureMode::default(),
            limits,
            config: ConfigValue::Null,
        })
    }

    fn route_with_refs(refs: &[(&str, Option<Arc<ExtensionObject>>)]) -> ActiveHttpRoute {
        ActiveHttpRoute {
            key: gateway_state::RouteKey::new(ListenerKey::new(BindKey::new("b"), "l"), "r"),
            revision: 1,
            matches: vec![],
            filters: refs
                .iter()
                .map(|(name, _)| HttpFilter::ExtensionRef {
                    name: (*name).to_owned(),
                    namespace: String::new(),
                })
                .collect(),
            backends: vec![],
            extensions: refs
                .iter()
                .map(|(name, object)| ActiveExtensionRef {
                    key: ExtensionKey::local(*name),
                    object: object.clone(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_missing_object_fails_resolution() {
        let cache = ExtensionCache::default();
        let route = route_with_refs(&[("ghost", None)]);
        let err = cache.for_route(&selector_registry(), &route).unwrap_err();
        assert!(err.contains("extension `ghost` is not registered"), "{err}");
    }

    #[test]
    fn two_selectors_fail_resolution_naming_both() {
        let cache = ExtensionCache::default();
        let route = route_with_refs(&[
            ("one", Some(object("one", Limits::default()))),
            ("two", Some(object("two", Limits::default()))),
        ]);
        let err = cache.for_route(&selector_registry(), &route).unwrap_err();
        assert!(err.contains("one") && err.contains("two"), "{err}");
    }

    #[test]
    fn an_object_over_its_ceiling_fails_resolution() {
        let cache = ExtensionCache::default();
        let limits = Limits {
            request_body: Some(gateway_config::extension::RequestBodyLimit::None),
            max_buffer_bytes: None,
        };
        let route = route_with_refs(&[("clamped", Some(object("clamped", limits)))]);
        let err = cache.for_route(&selector_registry(), &route).unwrap_err();
        assert!(err.contains("ceiling"), "{err}");
    }

    #[test]
    fn a_resolved_object_carries_its_declarations() {
        let cache = ExtensionCache::default();
        let route = route_with_refs(&[("ok", Some(object("ok", Limits::default())))]);
        let resolved = cache.for_route(&selector_registry(), &route).unwrap();
        assert_eq!(resolved.len(), 1);
        assert!(resolved[0].decl.selects_targets);
    }
}
