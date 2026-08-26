//! Route members configured once per route revision. The store
//! stamps a fresh revision on every route rebuild; anything derived
//! from the route's filter config is valid for exactly one revision,
//! so the cache invalidates itself. Per request only `build()` runs.

use std::collections::HashMap;
use std::sync::Arc;

use gateway_state::{ActiveHttpRoute, RouteKey};
use parking_lot::RwLock;

use crate::extension::builtin::class_and_config;
use crate::extension::{Declarations, ExtensionBuilder, Registry};

/// One filter of a route, configured: the builder plus its
/// declarations.
pub(crate) struct ResolvedMember {
    pub decl: Declarations,
    pub builder: Arc<dyn ExtensionBuilder>,
}

type Members = Arc<Vec<ResolvedMember>>;
type ResolveResult = Result<Members, Arc<str>>;

/// Configured members per route, keyed by route and validated by
/// revision.
#[derive(Default)]
pub(crate) struct MemberCache {
    routes: RwLock<HashMap<RouteKey, CachedRoute>>,
}

struct CachedRoute {
    revision: u64,
    /// Failures cache too: an invalid filter logs once per revision
    /// and answers 500 cheaply afterwards.
    result: ResolveResult,
}

impl MemberCache {
    /// The route's configured members — cached, or configured now and
    /// cached for the route's current revision.
    ///
    /// # Errors
    /// The resolution failure, already logged once when it was
    /// cached.
    pub(crate) fn members_for(
        &self,
        registry: &Registry,
        route: &ActiveHttpRoute,
    ) -> ResolveResult {
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

/// Configure every filter of `route`, in order.
fn resolve(registry: &Registry, route: &ActiveHttpRoute) -> ResolveResult {
    let mut members = Vec::with_capacity(route.filters.len());
    for (i, filter) in route.filters.iter().enumerate() {
        let (class, config) =
            class_and_config(filter).map_err(|e| Arc::<str>::from(format!("filter {i}: {e}")))?;
        let class_impl = registry.get(class).ok_or_else(|| {
            Arc::<str>::from(format!(
                "filter {i}: no extension class registered under `{class}`"
            ))
        })?;
        let builder = class_impl.configure(&config).map_err(|e| {
            Arc::<str>::from(format!(
                "filter {i}: class `{class}` rejected the config: {e}"
            ))
        })?;
        members.push(ResolvedMember {
            decl: builder.declares(),
            builder,
        });
    }
    Ok(Arc::new(members))
}
