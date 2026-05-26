use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::{RwLock, RwLockReadGuard};
use tokio::sync::broadcast;

use gateway_config::GatewayConfig;
use gateway_config::backend::{Backend, BackendRef};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::listener::{HttpListener, Listener};
use gateway_config::route::HttpRoute;

use crate::active::{
    ActiveBackend, ActiveBackendRef, ActiveBind, ActiveHttpListener, ActiveHttpRoute,
};
use crate::error::{ApplyReport, StoreError};
use crate::event::BindEvent;
use crate::key::{BackendKey, BindKey, ListenerKey, RouteKey};

const EVENT_CHANNEL_CAPACITY: usize = 256;

pub struct Store {
    inner: Arc<RwLock<Inner>>,
    events: broadcast::Sender<BindEvent>,
}

impl Clone for Store {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            events: self.events.clone(),
        }
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

// Strict partition: every known entity lives in EXACTLY ONE of
// `pending_*` or `active_*`.
//
// Promotion rules — an entity is active iff every precondition holds;
// otherwise it stays in `pending_*`:
//
//   * Bind:     registered.
//   * Backend:  registered.
//   * Route:    parent bind registered AND parent listener registered
//               AND every backend ref names a registered backend.
//   * Listener: parent bind registered AND AT LEAST ONE active route
//               under it (HTTP fans out across path / host).
//
// "Registered" means upserted at least once. Bind and backend have no
// preconditions, so they are always active when registered — there are
// no `pending_binds` / `pending_backends` maps.
#[derive(Default)]
struct Inner {
    /// Registered binds.
    bind_meta: HashMap<BindKey, BindMeta>,
    /// Registered backends.
    backends: HashMap<BackendKey, Arc<ActiveBackend>>,

    /// HTTP listeners whose preconditions are NOT currently met.
    pending_listeners: HashMap<ListenerKey, HttpListener>,
    /// HTTP routes whose preconditions are NOT currently met.
    pending_routes: HashMap<RouteKey, HttpRoute>,

    /// Resolved bind graph that readers walk.
    binds: HashMap<BindKey, Arc<ActiveBind>>,
    /// Listeners that satisfy every precondition right now.
    active_listeners: HashMap<ListenerKey, Arc<ActiveHttpListener>>,
    /// Routes that satisfy every precondition right now.
    active_routes: HashMap<RouteKey, Arc<ActiveHttpRoute>>,

    /// Index: listeners under a bind, active OR pending.
    listeners_by_parent: HashMap<BindKey, HashSet<ListenerKey>>,
    /// Index: routes under a listener, active OR pending.
    routes_by_parent: HashMap<ListenerKey, HashSet<RouteKey>>,
    /// Index: routes naming a given backend in their `backend_refs`.
    routes_by_backend: HashMap<BackendKey, HashSet<RouteKey>>,
}

#[derive(Debug, Clone)]
struct BindMeta {
    address: IpAddr,
    port: u16,
    bind_protocol: BindProtocol,
}

impl Store {
    pub fn new() -> Self {
        //TODO: reconsider chan choie
        let (events, _rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            events,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<BindEvent> {
        self.events.subscribe()
    }

    pub fn read(&self) -> StoreRead<'_> {
        StoreRead {
            guard: self.inner.read(),
        }
    }

    /// # Errors
    /// Returns `StoreError::UnsupportedProtocol` if the bind protocol is
    /// not HTTP, or if any embedded listener is not HTTP.
    pub fn upsert_bind(&self, bind: Bind) -> Result<(), StoreError> {
        let events = self.inner.write().upsert_bind(bind)?;
        self.dispatch(events);
        Ok(())
    }

    pub fn remove_bind(&self, key: &BindKey) {
        let events = self.inner.write().remove_bind(key);
        self.dispatch(events);
    }

    /// # Errors
    /// Returns `StoreError::UnsupportedProtocol` for any non-HTTP listener.
    pub fn upsert_listener(&self, parent: &BindKey, listener: Listener) -> Result<(), StoreError> {
        let events = self.inner.write().upsert_listener(parent, listener)?;
        self.dispatch(events);
        Ok(())
    }

    pub fn remove_listener(&self, key: &ListenerKey) {
        let events = self.inner.write().remove_listener(key);
        self.dispatch(events);
    }

    pub fn upsert_http_route(&self, parent: &ListenerKey, route: HttpRoute) {
        let events = self.inner.write().upsert_http_route(parent, route);
        self.dispatch(events);
    }

    pub fn remove_http_route(&self, key: &RouteKey) {
        let events = self.inner.write().remove_http_route(key);
        self.dispatch(events);
    }

    pub fn upsert_backend(&self, backend: Backend) {
        let events = self.inner.write().upsert_backend(backend);
        self.dispatch(events);
    }

    pub fn remove_backend(&self, key: &BackendKey) {
        let events = self.inner.write().remove_backend(key);
        self.dispatch(events);
    }

    pub fn apply(&self, cfg: &GatewayConfig) -> ApplyReport {
        let (report, events) = self.inner.write().apply(cfg);
        self.dispatch(events);
        report
    }

    fn dispatch(&self, events: Vec<BindEvent>) {
        for evt in events {
            let _ = self.events.send(evt);
        }
    }
}

pub struct StoreRead<'a> {
    guard: RwLockReadGuard<'a, Inner>,
}

impl StoreRead<'_> {
    pub fn bind(&self, key: &BindKey) -> Option<Arc<ActiveBind>> {
        self.guard.binds.get(key).cloned()
    }

    pub fn binds(&self) -> impl Iterator<Item = Arc<ActiveBind>> + '_ {
        self.guard.binds.values().cloned()
    }

    pub fn backend(&self, key: &BackendKey) -> Option<Arc<ActiveBackend>> {
        self.guard.backends.get(key).cloned()
    }

    pub fn is_listener_active(&self, key: &ListenerKey) -> bool {
        self.guard.active_listeners.contains_key(key)
    }

    pub fn is_route_active(&self, key: &RouteKey) -> bool {
        self.guard.active_routes.contains_key(key)
    }
}

// ==================== Inner mutation methods ====================

impl Inner {
    fn upsert_bind(&mut self, bind: Bind) -> Result<Vec<BindEvent>, StoreError> {
        if bind.bind_protocol != BindProtocol::Http {
            return Err(StoreError::UnsupportedProtocol {
                kind: "bind",
                name: bind.name,
            });
        }
        for listener in &bind.listeners {
            if !matches!(listener, Listener::Http(_)) {
                return Err(StoreError::UnsupportedProtocol {
                    kind: "listener",
                    name: listener.name().to_string(),
                });
            }
        }

        let key = BindKey::new(bind.name.clone());
        let is_new = !self.bind_meta.contains_key(&key);
        self.bind_meta.insert(
            key.clone(),
            BindMeta {
                address: bind.address,
                port: bind.port,
                bind_protocol: bind.bind_protocol,
            },
        );

        for listener in bind.listeners {
            let Listener::Http(http) = listener else {
                unreachable!("already validated above")
            };
            self.upsert_listener_raw(&key, http);
        }

        // Re-evaluate orphan listeners under this bind that weren't in
        // the embedded set. Their routes also need re-evaluation since
        // "parent bind known" just became true.
        let lkeys: Vec<ListenerKey> = self
            .listeners_by_parent
            .get(&key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        for lkey in lkeys {
            let rkeys: Vec<RouteKey> = self
                .routes_by_parent
                .get(&lkey)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect();
            for rkey in rkeys {
                self.re_resolve_route(&rkey);
            }
            self.re_resolve_listener(&lkey);
        }

        self.rebuild_bind(&key);

        let evt = if is_new {
            BindEvent::Added(key)
        } else {
            BindEvent::Updated(key)
        };
        Ok(vec![evt])
    }

    fn remove_bind(&mut self, key: &BindKey) -> Vec<BindEvent> {
        if self.bind_meta.remove(key).is_none() {
            return Vec::new();
        }
        self.binds.remove(key);
        let lkeys: Vec<ListenerKey> = self
            .listeners_by_parent
            .get(key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        for lkey in lkeys {
            let rkeys: Vec<RouteKey> = self
                .routes_by_parent
                .get(&lkey)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .collect();
            for rkey in rkeys {
                self.re_resolve_route(&rkey);
            }
            self.re_resolve_listener(&lkey);
        }
        vec![BindEvent::Removed(key.clone())]
    }

    fn upsert_listener(
        &mut self,
        parent: &BindKey,
        listener: Listener,
    ) -> Result<Vec<BindEvent>, StoreError> {
        let Listener::Http(http) = listener else {
            return Err(StoreError::UnsupportedProtocol {
                kind: "listener",
                name: listener.name().to_string(),
            });
        };
        self.upsert_listener_raw(parent, http);
        if self.bind_meta.contains_key(parent) {
            self.rebuild_bind(parent);
            Ok(vec![BindEvent::Updated(parent.clone())])
        } else {
            Ok(Vec::new())
        }
    }

    /// Shared core: drop the listener's old placement (if any), index
    /// it, place embedded routes, then place the listener itself.
    /// Does NOT rebuild the parent bind — callers batch that at the
    /// outer level.
    fn upsert_listener_raw(&mut self, parent: &BindKey, http: HttpListener) {
        let lkey = ListenerKey::new(parent.clone(), http.name.clone());
        let _ = self.pending_listeners.remove(&lkey);
        let _ = self.active_listeners.remove(&lkey);

        self.listeners_by_parent
            .entry(parent.clone())
            .or_default()
            .insert(lkey.clone());

        let mut shell = http;
        let routes_to_insert = std::mem::take(&mut shell.routes);
        for r in routes_to_insert {
            self.upsert_route_raw(&lkey, r);
        }
        self.place_listener(shell, &lkey);
    }

    fn remove_listener(&mut self, key: &ListenerKey) -> Vec<BindEvent> {
        let had = self.pending_listeners.remove(key).is_some()
            || self.active_listeners.remove(key).is_some();
        if !had {
            return Vec::new();
        }
        if let Some(set) = self.listeners_by_parent.get_mut(&key.bind) {
            set.remove(key);
        }
        let rkeys: Vec<RouteKey> = self
            .routes_by_parent
            .get(key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        for rkey in rkeys {
            self.re_resolve_route(&rkey);
        }
        if self.bind_meta.contains_key(&key.bind) {
            self.rebuild_bind(&key.bind);
            return vec![BindEvent::Updated(key.bind.clone())];
        }
        Vec::new()
    }

    fn upsert_http_route(&mut self, parent: &ListenerKey, route: HttpRoute) -> Vec<BindEvent> {
        self.upsert_route_raw(parent, route);
        self.re_resolve_listener(parent);
        if self.bind_meta.contains_key(&parent.bind) {
            self.rebuild_bind(&parent.bind);
            return vec![BindEvent::Updated(parent.bind.clone())];
        }
        Vec::new()
    }

    fn upsert_route_raw(&mut self, parent: &ListenerKey, route: HttpRoute) {
        let rkey = RouteKey::new(parent.clone(), route.name.clone());

        self.clear_route_backend_index(&rkey);
        let _ = self.pending_routes.remove(&rkey);
        let _ = self.active_routes.remove(&rkey);

        self.routes_by_parent
            .entry(parent.clone())
            .or_default()
            .insert(rkey.clone());
        for br in &route.backend_refs {
            let bkey = BackendKey::new(br.name.clone());
            self.routes_by_backend
                .entry(bkey)
                .or_default()
                .insert(rkey.clone());
        }
        self.place_route(route, &rkey);
    }

    fn remove_http_route(&mut self, key: &RouteKey) -> Vec<BindEvent> {
        if self.pending_routes.remove(key).is_none() && self.active_routes.remove(key).is_none() {
            return Vec::new();
        }
        if let Some(set) = self.routes_by_parent.get_mut(&key.listener) {
            set.remove(key);
        }
        let backend_keys: Vec<BackendKey> = self
            .routes_by_backend
            .iter()
            .filter(|(_, set)| set.contains(key))
            .map(|(bk, _)| bk.clone())
            .collect();
        for bk in backend_keys {
            if let Some(set) = self.routes_by_backend.get_mut(&bk) {
                set.remove(key);
            }
        }
        self.re_resolve_listener(&key.listener);
        if self.bind_meta.contains_key(&key.listener.bind) {
            self.rebuild_bind(&key.listener.bind);
            return vec![BindEvent::Updated(key.listener.bind.clone())];
        }
        Vec::new()
    }

    fn upsert_backend(&mut self, backend: Backend) -> Vec<BindEvent> {
        let Backend::Static(s) = backend;
        let key = BackendKey::new(s.name.clone());
        let new = Arc::new(ActiveBackend {
            key: key.clone(),
            endpoints: s.endpoints,
        });
        self.backends.insert(key.clone(), new);
        self.cascade_routes_by_backend(&key)
    }

    fn remove_backend(&mut self, key: &BackendKey) -> Vec<BindEvent> {
        if self.backends.remove(key).is_none() {
            return Vec::new();
        }
        self.cascade_routes_by_backend(key)
    }

    fn cascade_routes_by_backend(&mut self, key: &BackendKey) -> Vec<BindEvent> {
        let rkeys: Vec<RouteKey> = self
            .routes_by_backend
            .get(key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let affected_listeners: HashSet<ListenerKey> =
            rkeys.iter().map(|rk| rk.listener.clone()).collect();
        for rkey in &rkeys {
            self.re_resolve_route(rkey);
        }
        let mut affected_binds: HashSet<BindKey> = HashSet::new();
        for lk in &affected_listeners {
            self.re_resolve_listener(lk);
            if self.bind_meta.contains_key(&lk.bind) {
                affected_binds.insert(lk.bind.clone());
            }
        }
        for bk in &affected_binds {
            self.rebuild_bind(bk);
        }
        affected_binds.into_iter().map(BindEvent::Updated).collect()
    }

    /// Replace the entire store with the contents of `cfg`. Naive
    /// clear-and-rebuild; deltas can come later.
    fn apply(&mut self, cfg: &GatewayConfig) -> (ApplyReport, Vec<BindEvent>) {
        let prev_keys: HashSet<BindKey> = self.bind_meta.keys().cloned().collect();
        self.clear();
        let mut report = ApplyReport::default();
        let mut events: Vec<BindEvent> = Vec::new();

        for bind in &cfg.binds {
            match self.upsert_bind(bind.clone()) {
                Ok(mut e) => {
                    report.applied += 1;
                    events.append(&mut e);
                }
                Err(e) => {
                    report.skipped.push(format!("binds[{}]: {e}", bind.name));
                }
            }
        }
        for backend in &cfg.backends {
            let mut e = self.upsert_backend(backend.clone());
            report.applied += 1;
            events.append(&mut e);
        }
        for secret in &cfg.secrets {
            report.skipped.push(format!(
                "secrets[{}]: not supported in this slice",
                secret.name()
            ));
        }

        let new_keys: HashSet<BindKey> = self.bind_meta.keys().cloned().collect();
        for k in prev_keys.difference(&new_keys) {
            events.push(BindEvent::Removed(k.clone()));
        }

        (report, events)
    }

    fn clear(&mut self) {
        self.bind_meta.clear();
        self.backends.clear();
        self.pending_listeners.clear();
        self.pending_routes.clear();
        self.binds.clear();
        self.active_listeners.clear();
        self.active_routes.clear();
        self.listeners_by_parent.clear();
        self.routes_by_parent.clear();
        self.routes_by_backend.clear();
    }

    /// Is the listener known at all (active or pending)?
    fn listener_known(&self, key: &ListenerKey) -> bool {
        self.pending_listeners.contains_key(key) || self.active_listeners.contains_key(key)
    }

    /// Strip backend-index entries for a route key (used before
    /// re-indexing with the new `backend_refs` on update).
    fn clear_route_backend_index(&mut self, key: &RouteKey) {
        let backend_keys: Vec<BackendKey> = self
            .routes_by_backend
            .iter()
            .filter(|(_, set)| set.contains(key))
            .map(|(bk, _)| bk.clone())
            .collect();
        for bk in backend_keys {
            if let Some(set) = self.routes_by_backend.get_mut(&bk) {
                set.remove(key);
            }
        }
    }

    /// Take a route's raw form back from whichever map currently holds
    /// it. Used by `re_resolve_route` to re-place under updated state.
    fn take_route_raw(&mut self, key: &RouteKey) -> Option<HttpRoute> {
        if let Some(raw) = self.pending_routes.remove(key) {
            return Some(raw);
        }
        self.active_routes.remove(key).map(|active| HttpRoute {
            name: key.name.clone(),
            matches: active.matches.clone(),
            backend_refs: active
                .backends
                .iter()
                .map(|abr| BackendRef {
                    name: abr.backend.key.0.clone(),
                    weight: abr.weight,
                })
                .collect(),
            filters: active.filters.clone(),
        })
    }

    /// Take a listener's raw form.
    fn take_listener_raw(&mut self, key: &ListenerKey) -> Option<HttpListener> {
        if let Some(raw) = self.pending_listeners.remove(key) {
            return Some(raw);
        }
        self.active_listeners
            .remove(key)
            .map(|active| HttpListener {
                name: key.name.clone(),
                hostname: active.hostname.clone(),
                routes: vec![],
            })
    }

    /// Decide the new placement of `route` under `key`. Active iff
    /// parent bind known, parent listener known (active or pending),
    /// and every `backend_refs[i].name` resolves.
    fn place_route(&mut self, route: HttpRoute, key: &RouteKey) {
        if !self.bind_meta.contains_key(&key.listener.bind) || !self.listener_known(&key.listener) {
            self.pending_routes.insert(key.clone(), route);
            return;
        }
        let mut resolved = Vec::with_capacity(route.backend_refs.len());
        for br in &route.backend_refs {
            let bkey = BackendKey::new(br.name.clone());
            if let Some(b) = self.backends.get(&bkey) {
                resolved.push(ActiveBackendRef {
                    backend: Arc::clone(b),
                    weight: br.weight,
                });
            } else {
                self.pending_routes.insert(key.clone(), route);
                return;
            }
        }
        let active = Arc::new(ActiveHttpRoute {
            key: key.clone(),
            matches: route.matches,
            filters: route.filters,
            backends: resolved,
        });
        self.active_routes.insert(key.clone(), active);
    }

    /// Decide the new placement of `listener`. Two phases:
    /// speculatively park in pending so child routes can read
    /// "listener known"; re-resolve every child route; then promote
    /// to active iff parent bind exists and **at least one** child
    /// route is active.
    fn place_listener(&mut self, listener: HttpListener, key: &ListenerKey) {
        self.active_listeners.remove(key);
        self.pending_listeners.insert(key.clone(), listener);

        let rkeys: Vec<RouteKey> = self
            .routes_by_parent
            .get(key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        for rk in rkeys {
            self.re_resolve_route(&rk);
        }

        if !self.bind_meta.contains_key(&key.bind) {
            return;
        }
        let mut active_route_keys: Vec<RouteKey> = self
            .routes_by_parent
            .get(key)
            .map(|set| {
                set.iter()
                    .filter(|rk| self.active_routes.contains_key(rk))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        if active_route_keys.is_empty() {
            return;
        }
        active_route_keys.sort_by(|a, b| a.name.cmp(&b.name));
        let routes: Vec<Arc<ActiveHttpRoute>> = active_route_keys
            .into_iter()
            .map(|rk| Arc::clone(&self.active_routes[&rk]))
            .collect();
        let Some(raw) = self.pending_listeners.remove(key) else {
            return;
        };
        let active = Arc::new(ActiveHttpListener {
            key: key.clone(),
            hostname: raw.hostname,
            routes,
        });
        self.active_listeners.insert(key.clone(), active);
    }

    fn re_resolve_route(&mut self, key: &RouteKey) {
        if let Some(raw) = self.take_route_raw(key) {
            self.place_route(raw, key);
        }
    }

    fn re_resolve_listener(&mut self, key: &ListenerKey) {
        if let Some(raw) = self.take_listener_raw(key) {
            self.place_listener(raw, key);
        }
    }

    fn rebuild_bind(&mut self, key: &BindKey) {
        let Some(meta) = self.bind_meta.get(key).cloned() else {
            self.binds.remove(key);
            return;
        };
        let mut lkeys: Vec<ListenerKey> = self
            .listeners_by_parent
            .get(key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|lk| self.active_listeners.contains_key(lk))
            .collect();
        lkeys.sort_by(|a, b| a.name.cmp(&b.name));
        let listeners: Vec<Arc<ActiveHttpListener>> = lkeys
            .into_iter()
            .map(|lk| Arc::clone(&self.active_listeners[&lk]))
            .collect();
        let active = Arc::new(ActiveBind {
            key: key.clone(),
            address: meta.address,
            port: meta.port,
            bind_protocol: meta.bind_protocol,
            listeners,
        });
        self.binds.insert(key.clone(), active);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};

    use gateway_config::backend::{Backend, BackendRef, Endpoint, StaticBackend};
    use gateway_config::bind::{Bind, BindProtocol};
    use gateway_config::filter::{HeaderPair, HttpFilter, RequestHeaderOps};
    use gateway_config::listener::{
        HttpListener, HttpsListener, Listener, TcpListener, TlsConfig, TlsMode,
    };
    use gateway_config::route::{HttpMatch, HttpRoute, PathMatch, PathMatchKind};

    // --- fixture builders ---

    fn http_bind(name: &str, port: u16) -> Bind {
        Bind {
            name: name.into(),
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port,
            bind_protocol: BindProtocol::Http,
            listeners: vec![],
        }
    }

    fn tcp_bind(name: &str, port: u16) -> Bind {
        Bind {
            name: name.into(),
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port,
            bind_protocol: BindProtocol::Tcp,
            listeners: vec![],
        }
    }

    fn tls_bind(name: &str, port: u16) -> Bind {
        Bind {
            name: name.into(),
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port,
            bind_protocol: BindProtocol::Tls,
            listeners: vec![],
        }
    }

    fn http_listener(name: &str) -> Listener {
        Listener::Http(HttpListener {
            name: name.into(),
            hostname: None,
            routes: vec![],
        })
    }

    fn http_listener_with_host(name: &str, host: &str) -> Listener {
        Listener::Http(HttpListener {
            name: name.into(),
            hostname: Some(host.into()),
            routes: vec![],
        })
    }

    fn tcp_listener(name: &str) -> Listener {
        Listener::Tcp(TcpListener {
            name: name.into(),
            routes: vec![],
        })
    }

    fn https_listener(name: &str) -> Listener {
        Listener::Https(HttpsListener {
            name: name.into(),
            hostname: None,
            tls: TlsConfig {
                mode: TlsMode::Terminate,
                certificates: vec![],
            },
            routes: vec![],
        })
    }

    fn http_route(name: &str, path_prefix: &str, backends: &[&str]) -> HttpRoute {
        HttpRoute {
            name: name.into(),
            matches: vec![HttpMatch {
                host: None,
                path: PathMatch {
                    kind: PathMatchKind::PathPrefix,
                    value: path_prefix.into(),
                },
            }],
            backend_refs: backends
                .iter()
                .map(|b| BackendRef {
                    name: (*b).into(),
                    weight: 1,
                })
                .collect(),
            filters: vec![],
        }
    }

    fn static_backend(name: &str, endpoints: &[(&str, &str, u16)]) -> Backend {
        Backend::Static(StaticBackend {
            name: name.into(),
            endpoints: endpoints
                .iter()
                .map(|(n, a, p)| Endpoint {
                    name: (*n).into(),
                    address: a.parse().unwrap(),
                    port: *p,
                })
                .collect(),
        })
    }

    fn bkey(s: &str) -> BindKey {
        BindKey::new(s)
    }
    fn lkey(b: &str, l: &str) -> ListenerKey {
        ListenerKey::new(BindKey::new(b), l)
    }
    fn rkey(b: &str, l: &str, r: &str) -> RouteKey {
        RouteKey::new(ListenerKey::new(BindKey::new(b), l), r)
    }
    fn backendkey(s: &str) -> BackendKey {
        BackendKey::new(s)
    }

    // --- tests ---

    #[test]
    fn empty_store_reads_empty() {
        let store = Store::new();
        let read = store.read();
        assert!(read.bind(&bkey("nope")).is_none());
        assert_eq!(read.binds().count(), 0);
    }

    #[test]
    fn in_order_bind_listener_route_backend() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));

        let read = store.read();
        let bind = read.bind(&bkey("b")).expect("bind active");
        assert_eq!(bind.bind_protocol, BindProtocol::Http);
        assert_eq!(bind.listeners.len(), 1);
        let listener = &bind.listeners[0];
        assert!(listener.hostname.is_none());
        assert_eq!(listener.routes.len(), 1);
        let route = &listener.routes[0];
        assert_eq!(route.backends.len(), 1);
        assert_eq!(route.backends[0].backend.endpoints[0].port, 8080);
    }

    #[test]
    fn reverse_order_backend_route_listener_bind() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_bind(http_bind("b", 80)).unwrap();

        let bind = store.read().bind(&bkey("b")).expect("bind active");
        assert_eq!(bind.listeners.len(), 1);
        assert_eq!(bind.listeners[0].routes.len(), 1);
    }

    #[test]
    fn listener_stashed_without_bind() {
        let store = Store::new();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        let read = store.read();
        assert!(read.bind(&bkey("b")).is_none());
        assert!(!read.is_listener_active(&lkey("b", "l")));
    }

    #[test]
    fn route_stashed_without_listener() {
        let store = Store::new();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        let read = store.read();
        assert!(!read.is_route_active(&rkey("b", "l", "r")));
        assert!(!read.is_listener_active(&lkey("b", "l")));
    }

    #[test]
    fn route_stashed_without_backend_then_promoted() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));

        assert!(!store.read().is_route_active(&rkey("b", "l", "r")));
        assert!(store.read().bind(&bkey("b")).unwrap().listeners.is_empty());

        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));

        assert!(store.read().is_route_active(&rkey("b", "l", "r")));
        let bind = store.read().bind(&bkey("b")).unwrap();
        assert_eq!(bind.listeners.len(), 1);
    }

    #[test]
    fn cascade_on_bind_remove() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));

        store.remove_bind(&bkey("b"));
        {
            let read = store.read();
            assert!(read.bind(&bkey("b")).is_none());
            assert!(!read.is_listener_active(&lkey("b", "l")));
        }

        store.upsert_bind(http_bind("b", 80)).unwrap();
        let bind = store.read().bind(&bkey("b")).unwrap();
        assert_eq!(bind.listeners.len(), 1);
    }

    #[test]
    fn cascade_on_listener_remove() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));

        store.remove_listener(&lkey("b", "l"));
        let bind = store.read().bind(&bkey("b")).unwrap();
        assert!(bind.listeners.is_empty());
    }

    #[test]
    fn cascade_on_backend_remove() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));

        store.remove_backend(&backendkey("be"));
        assert!(!store.read().is_route_active(&rkey("b", "l", "r")));
        assert!(store.read().bind(&bkey("b")).unwrap().listeners.is_empty());

        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.99", 9999)]));
        let bind = store.read().bind(&bkey("b")).unwrap();
        let route = &bind.listeners[0].routes[0];
        assert_eq!(route.backends[0].backend.endpoints[0].port, 9999);
    }

    #[test]
    fn backend_update_propagates_new_endpoints() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));

        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.2", 9090)]));
        let bind = store.read().bind(&bkey("b")).unwrap();
        let route = &bind.listeners[0].routes[0];
        assert_eq!(route.backends[0].backend.endpoints[0].port, 9090);
    }

    #[test]
    fn embedded_listeners_and_routes_via_upsert_bind() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        let mut b = http_bind("b", 80);
        b.listeners.push(Listener::Http(HttpListener {
            name: "l".into(),
            hostname: Some("svc.local".into()),
            routes: vec![http_route("r", "/", &["be"])],
        }));
        store.upsert_bind(b).unwrap();
        let bind = store.read().bind(&bkey("b")).unwrap();
        let listener = &bind.listeners[0];
        assert_eq!(listener.hostname.as_deref(), Some("svc.local"));
        assert_eq!(listener.routes.len(), 1);
        assert_eq!(
            listener.routes[0].backends[0].backend.endpoints[0].port,
            8080
        );
    }

    // --- protocol acceptance / rejection ---

    #[test]
    fn tcp_bind_rejected() {
        let store = Store::new();
        let err = store.upsert_bind(tcp_bind("b", 7000)).unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedProtocol { .. }));
    }

    #[test]
    fn tls_bind_rejected() {
        let store = Store::new();
        let err = store.upsert_bind(tls_bind("b", 443)).unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedProtocol { .. }));
    }

    #[test]
    fn https_listener_rejected() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        let err = store
            .upsert_listener(&bkey("b"), https_listener("l"))
            .unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedProtocol { .. }));
    }

    #[test]
    fn embedded_non_http_listener_rejected() {
        let store = Store::new();
        let mut b = http_bind("b", 80);
        b.listeners.push(tcp_listener("l"));
        let err = store.upsert_bind(b).unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedProtocol { .. }));
    }

    #[test]
    fn http_listener_with_zero_routes_not_active() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        assert!(!store.read().is_listener_active(&lkey("b", "l")));
        assert!(store.read().bind(&bkey("b")).unwrap().listeners.is_empty());
    }

    #[test]
    fn http_listener_with_multiple_routes_active() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r0", "/api", &["be"]));
        store.upsert_http_route(&lkey("b", "l"), http_route("r1", "/api/v2", &["be"]));

        assert!(store.read().is_listener_active(&lkey("b", "l")));
        let bind = store.read().bind(&bkey("b")).unwrap();
        let listener = &bind.listeners[0];
        assert_eq!(listener.routes.len(), 2);
        assert_eq!(listener.routes[0].key.name, "r0");
        assert_eq!(listener.routes[1].key.name, "r1");
    }

    #[test]
    fn http_listener_hostname_preserved() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener_with_host("l", "example.com"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));

        let bind = store.read().bind(&bkey("b")).unwrap();
        assert_eq!(bind.listeners[0].hostname.as_deref(), Some("example.com"));
    }

    #[test]
    fn http_route_with_multiple_backends_all_resolve() {
        let store = Store::new();
        store.upsert_backend(static_backend("be0", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_backend(static_backend("be1", &[("e0", "10.0.0.2", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be0", "be1"]));

        let bind = store.read().bind(&bkey("b")).unwrap();
        assert_eq!(bind.listeners[0].routes[0].backends.len(), 2);
    }

    #[test]
    fn route_with_one_missing_backend_stays_pending() {
        let store = Store::new();
        store.upsert_backend(static_backend("be0", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be0", "be1"]));
        assert!(!store.read().is_route_active(&rkey("b", "l", "r")));

        store.upsert_backend(static_backend("be1", &[("e0", "10.0.0.2", 8080)]));
        assert!(store.read().is_route_active(&rkey("b", "l", "r")));
    }

    #[test]
    fn http_remove_route_demotes_listener_when_last() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));
        assert!(store.read().is_listener_active(&lkey("b", "l")));

        store.remove_http_route(&rkey("b", "l", "r"));
        assert!(!store.read().is_listener_active(&lkey("b", "l")));
    }

    #[test]
    fn http_route_filters_round_trip() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        let route = HttpRoute {
            name: "r".into(),
            matches: vec![HttpMatch {
                host: None,
                path: PathMatch {
                    kind: PathMatchKind::PathPrefix,
                    value: "/".into(),
                },
            }],
            backend_refs: vec![BackendRef {
                name: "be".into(),
                weight: 1,
            }],
            filters: vec![HttpFilter::RequestHeaderModifier {
                name: "add-hdr".into(),
                request_headers: RequestHeaderOps {
                    add: vec![HeaderPair {
                        name: "x-test".into(),
                        value: "yes".into(),
                    }],
                    set: vec![],
                    remove: vec![],
                },
            }],
        };
        store.upsert_http_route(&lkey("b", "l"), route);

        let bind = store.read().bind(&bkey("b")).unwrap();
        assert_eq!(bind.listeners[0].routes[0].filters.len(), 1);
    }

    #[test]
    fn apply_bootstrap_from_config() {
        let cfg = gateway_config::parse_yaml(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          hostname: example.com
          routes:
            - name: r
              matches:
                - path: { type: PathPrefix, value: / }
              backendRefs: [{ name: be }]
  backends:
    - name: be
      type: Static
      endpoints: [{ name: e0, address: 10.0.0.1, port: 8080 }]
",
        )
        .unwrap();
        let store = Store::new();
        let report = store.apply(&cfg);
        assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
        assert!(store.read().bind(&bkey("b")).is_some());
        assert!(store.read().is_listener_active(&lkey("b", "l")));
        assert!(store.read().is_route_active(&rkey("b", "l", "r")));
    }

    #[test]
    fn apply_skips_non_http() {
        let cfg = gateway_config::parse_yaml(
            r"
gatewayConfig:
  name: g
  binds:
    - name: http-bind
      port: 80
      bindProtocol: HTTP
      listeners:
        - name: l
          listenerProtocol: HTTP
          routes:
            - name: r
              matches:
                - path: { type: PathPrefix, value: / }
              backendRefs: [{ name: be }]
    - name: tcp-bind
      port: 5432
      bindProtocol: TCP
    - name: tls-bind
      port: 443
      bindProtocol: TLS
  backends:
    - name: be
      type: Static
      endpoints: [{ name: e0, address: 10.0.0.1, port: 8080 }]
",
        )
        .unwrap();
        let store = Store::new();
        let report = store.apply(&cfg);
        assert_eq!(report.skipped.len(), 2);
        assert!(report.skipped.iter().any(|s| s.contains("tcp-bind")));
        assert!(report.skipped.iter().any(|s| s.contains("tls-bind")));
        assert!(store.read().bind(&bkey("http-bind")).is_some());
        assert!(store.read().bind(&bkey("tcp-bind")).is_none());
        assert!(store.read().bind(&bkey("tls-bind")).is_none());
    }

    #[test]
    fn subscribe_emits_added_on_new_bind() {
        let store = Store::new();
        let mut rx = store.subscribe();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        let evt = rx.try_recv().expect("event");
        assert_eq!(evt, BindEvent::Added(bkey("b")));
    }

    #[test]
    fn subscribe_emits_updated_on_listener_change() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        let mut rx = store.subscribe();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        let evt = rx.try_recv().expect("event");
        assert_eq!(evt, BindEvent::Updated(bkey("b")));
    }

    #[test]
    fn subscribe_emits_removed() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        let mut rx = store.subscribe();
        store.remove_bind(&bkey("b"));
        let evt = rx.try_recv().expect("event");
        assert_eq!(evt, BindEvent::Removed(bkey("b")));
    }

    #[test]
    fn store_clone_shares_state() {
        let s1 = Store::new();
        let s2 = s1.clone();
        s1.upsert_bind(http_bind("b", 80)).unwrap();
        assert!(s2.read().bind(&bkey("b")).is_some());
    }
}
