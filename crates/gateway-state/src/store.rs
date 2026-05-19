use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::{RwLock, RwLockReadGuard};
use tokio::sync::broadcast;

use gateway_config::GatewayConfig;
use gateway_config::backend::{Backend, BackendRef};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::listener::{Listener, TcpListener};
use gateway_config::route::TcpRoute;

use crate::active::{
    ActiveBackend, ActiveBackendRef, ActiveBind, ActiveListener, ActiveListenerKind,
    ActiveTcpListener, ActiveTcpRoute,
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
// `pending_*` or `active_*` (or in neither, meaning unknown).
//
// Promotion rules — an entity is active iff every precondition holds;
// otherwise it stays in `pending_*`:
//
//   * Bind:     registered.
//   * Backend:  registered.
//   * Route:    parent bind registered AND parent listener registered
//               AND every backend ref names a registered backend.
//   * Listener: parent bind registered AND exactly one active route
//               under it.
//
// "Registered" means upserted at least once. Bind and backend have no
// preconditions, so they are always active when registered — there are
// no `pending_binds` / `pending_backends` maps.
//
// The listener-vs-route asymmetry is intentional: a listener needs an
// ACTIVE child route, but a route only needs its parent listener to
// be REGISTERED. This breaks an otherwise-circular precondition (a
// brand-new listener would never get its first active route
// otherwise).
//
// Reverse-direction indexes (`*_by_parent`, `routes_by_backend`) hold
// keys regardless of active/pending state so dependents can be found
// quickly when a precondition changes. The pending map holds the raw
// schema value so we can re-evaluate later; the active map holds the
// `Arc`-wrapped resolved value that readers walk.
#[derive(Default)]
struct Inner {
    /// Registered binds. Binds have no upward deps so being registered
    /// is the only precondition for being active; this map is therefore
    /// always paired 1:1 with `binds` (the Arc view).
    bind_meta: HashMap<BindKey, BindMeta>,
    /// Registered backends. Same story as `bind_meta`: no upward deps,
    /// always active when registered.
    backends: HashMap<BackendKey, Arc<ActiveBackend>>,

    /// Listeners whose preconditions are NOT currently met (parent bind
    /// missing, or no/multiple active routes under them). The raw value
    /// is kept here so we can promote without re-receiving it.
    pending_listeners: HashMap<ListenerKey, TcpListener>,
    /// Routes whose preconditions are NOT currently met.
    pending_routes: HashMap<RouteKey, TcpRoute>,

    /// Resolved bind graph that readers walk. Each `Arc<ActiveBind>`
    /// embeds the current `Arc<ActiveListener>`s, which embed the
    /// current `Arc<ActiveTcpRoute>`s.
    binds: HashMap<BindKey, Arc<ActiveBind>>,
    /// Listeners that satisfy every precondition right now.
    active_listeners: HashMap<ListenerKey, Arc<ActiveListener>>,
    /// Routes that satisfy every precondition right now.
    active_routes: HashMap<RouteKey, Arc<ActiveTcpRoute>>,

    /// Index: listeners under a bind, active OR pending. Used to find
    /// dependents when a bind is added or removed.
    listeners_by_parent: HashMap<BindKey, HashSet<ListenerKey>>,
    /// Index: routes under a listener, active OR pending.
    routes_by_parent: HashMap<ListenerKey, HashSet<RouteKey>>,
    /// Index: routes naming a given backend in their `backend_refs`.
    /// Used to find dependents when a backend is added, updated, or
    /// removed.
    routes_by_backend: HashMap<BackendKey, HashSet<RouteKey>>,
}

#[derive(Debug, Clone)]
struct BindMeta {
    address: IpAddr,
    port: u16,
}

impl Store {
    #[must_use]
    pub fn new() -> Self {
        let (events, _rx) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
            events,
        }
    }

    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<BindEvent> {
        self.events.subscribe()
    }

    #[must_use]
    pub fn read(&self) -> StoreRead<'_> {
        StoreRead {
            guard: self.inner.read(),
        }
    }

    /// # Errors
    /// Returns `StoreError::UnsupportedProtocol` if the bind or any of its embedded
    /// listeners are not TCP.
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
    /// Returns `StoreError::UnsupportedProtocol` for non-TCP listeners.
    pub fn upsert_listener(&self, parent: &BindKey, listener: Listener) -> Result<(), StoreError> {
        let events = self.inner.write().upsert_listener(parent, listener)?;
        self.dispatch(events);
        Ok(())
    }

    pub fn remove_listener(&self, key: &ListenerKey) {
        let events = self.inner.write().remove_listener(key);
        self.dispatch(events);
    }

    pub fn upsert_tcp_route(&self, parent: &ListenerKey, route: TcpRoute) {
        let events = self.inner.write().upsert_tcp_route(parent, route);
        self.dispatch(events);
    }

    pub fn remove_tcp_route(&self, key: &RouteKey) {
        let events = self.inner.write().remove_tcp_route(key);
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

    #[must_use]
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
    #[must_use]
    pub fn bind(&self, key: &BindKey) -> Option<Arc<ActiveBind>> {
        self.guard.binds.get(key).cloned()
    }

    pub fn binds(&self) -> impl Iterator<Item = Arc<ActiveBind>> + '_ {
        self.guard.binds.values().cloned()
    }

    #[must_use]
    pub fn backend(&self, key: &BackendKey) -> Option<Arc<ActiveBackend>> {
        self.guard.backends.get(key).cloned()
    }

    #[must_use]
    pub fn is_listener_active(&self, key: &ListenerKey) -> bool {
        self.guard.active_listeners.contains_key(key)
    }

    #[must_use]
    pub fn is_route_active(&self, key: &RouteKey) -> bool {
        self.guard.active_routes.contains_key(key)
    }
}

// ==================== Inner mutation methods ====================

impl Inner {
    /// Register or update a TCP bind. Embedded listeners (and their
    /// embedded routes) are processed as if `upsert_listener` /
    /// `upsert_tcp_route` had been called separately for each. Listeners
    /// that were previously pending under this bind key are re-evaluated
    /// (they may now promote, since `bind_meta` just got the entry).
    fn upsert_bind(&mut self, bind: Bind) -> Result<Vec<BindEvent>, StoreError> {
        if bind.bind_protocol != BindProtocol::Tcp {
            return Err(StoreError::UnsupportedProtocol {
                kind: "bind",
                name: bind.name,
            });
        }
        for listener in &bind.listeners {
            if !matches!(listener, Listener::Tcp(_)) {
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
            },
        );

        for listener in bind.listeners {
            let Listener::Tcp(tcp) = listener else {
                unreachable!("already validated above")
            };
            self.upsert_tcp_listener_raw(&key, tcp);
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

    /// Remove a bind. Listeners under it lose "parent bind active" and
    /// demote to pending; routes under those listeners likewise demote
    /// (they require "parent bind active" transitively). Source data is
    /// preserved so the whole subtree reactivates if the bind comes back.
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

    /// Register or update a listener under `parent`. If `parent` isn't
    /// in `bind_meta` yet, the listener simply lands in
    /// `pending_listeners` and no event fires; a later
    /// `upsert_bind(parent)` will re-evaluate it.
    fn upsert_listener(
        &mut self,
        parent: &BindKey,
        listener: Listener,
    ) -> Result<Vec<BindEvent>, StoreError> {
        let tcp = match listener {
            Listener::Tcp(tcp) => tcp,
            other => {
                return Err(StoreError::UnsupportedProtocol {
                    kind: "listener",
                    name: other.name().to_string(),
                });
            }
        };
        self.upsert_tcp_listener_raw(parent, tcp);
        if self.bind_meta.contains_key(parent) {
            self.rebuild_bind(parent);
            Ok(vec![BindEvent::Updated(parent.clone())])
        } else {
            Ok(Vec::new())
        }
    }

    /// Shared core: drop the listener's old placement (if any), index
    /// it, place embedded routes, then place the listener itself.
    /// `place_listener` handles activation against current state. Does
    /// NOT rebuild the parent bind — callers batch that at the outer level.
    fn upsert_tcp_listener_raw(&mut self, parent: &BindKey, tcp: TcpListener) {
        let lkey = ListenerKey::new(parent.clone(), tcp.name.clone());
        // Discard any prior placement; we'll re-place at the end.
        let _ = self.take_listener_raw(&lkey);

        self.listeners_by_parent
            .entry(parent.clone())
            .or_default()
            .insert(lkey.clone());

        // Strip embedded routes — TCP listeners carry no other
        // protocol-specific data, so the "raw" form is essentially
        // (key, empty routes).
        let mut tcp_shell = tcp;
        let routes_to_insert = std::mem::take(&mut tcp_shell.routes);
        for r in routes_to_insert {
            self.upsert_tcp_route_raw(&lkey, r);
        }
        self.place_listener(tcp_shell, &lkey);
    }

    /// Remove a listener entirely. Routes under it lose "parent listener
    /// known" and demote to pending. Their source data stays, so they
    /// reactivate if a listener with the same key is re-added.
    fn remove_listener(&mut self, key: &ListenerKey) -> Vec<BindEvent> {
        if self.take_listener_raw(key).is_none() {
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

    /// Add or replace a TCP route under `parent`. The parent listener
    /// is re-evaluated afterwards because the TCP rule is "exactly one
    /// active route per listener" — adding/replacing a route may promote
    /// or demote the listener.
    fn upsert_tcp_route(&mut self, parent: &ListenerKey, route: TcpRoute) -> Vec<BindEvent> {
        self.upsert_tcp_route_raw(parent, route);
        self.re_resolve_listener(parent);
        if self.bind_meta.contains_key(&parent.bind) {
            self.rebuild_bind(&parent.bind);
            return vec![BindEvent::Updated(parent.bind.clone())];
        }
        Vec::new()
    }

    /// Lower-level route insertion: drops the old placement and any
    /// stale backend-index entries, updates fresh indexes, then places
    /// the route into either `active_routes` or `pending_routes` via
    /// `place_route`. Callers handle listener re-evaluation and bind
    /// rebuilding so we don't repeat them N times when processing N routes.
    fn upsert_tcp_route_raw(&mut self, parent: &ListenerKey, route: TcpRoute) {
        let rkey = RouteKey::new(parent.clone(), route.name.clone());

        // If the route was already known, drop its old placement and
        // the index entries from its previous backend_refs (which may
        // differ from the new ones).
        if let Some(old) = self.take_route_raw(&rkey) {
            for br in &old.backend_refs {
                let bkey = BackendKey::new(br.name.clone());
                if let Some(set) = self.routes_by_backend.get_mut(&bkey) {
                    set.remove(&rkey);
                }
            }
        }

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

    fn remove_tcp_route(&mut self, key: &RouteKey) -> Vec<BindEvent> {
        let Some(raw) = self.take_route_raw(key) else {
            return Vec::new();
        };
        if let Some(set) = self.routes_by_parent.get_mut(&key.listener) {
            set.remove(key);
        }
        for br in &raw.backend_refs {
            let bkey = BackendKey::new(br.name.clone());
            if let Some(set) = self.routes_by_backend.get_mut(&bkey) {
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

    /// Remove a backend. Routes that referenced it lose a ref and demote
    /// to pending; their parent listeners may demote in turn.
    fn remove_backend(&mut self, key: &BackendKey) -> Vec<BindEvent> {
        if self.backends.remove(key).is_none() {
            return Vec::new();
        }
        self.cascade_routes_by_backend(key)
    }

    /// Shared cascade for `upsert_backend` / `remove_backend`:
    /// re-evaluate every route that references the backend, then their
    /// parent listeners, then rebuild affected binds.
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

    /// Replace the entire store with the contents of `cfg`.
    /// TODO: optimize by diffing against the current state and only applying changes.
    /// this naive clear-and-rebuild is just easier to reason about for now.
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
                "secrets[{}]: not supported in TCP slice",
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

    /// Remove a route from whichever map currently holds it (if any)
    /// and reconstruct the raw `TcpRoute`. Used by upsert (to start fresh
    /// with new content), remove (to discard the data), and re-resolve
    /// (to re-evaluate placement under the current state).
    fn take_route_raw(&mut self, key: &RouteKey) -> Option<TcpRoute> {
        if let Some(raw) = self.pending_routes.remove(key) {
            return Some(raw);
        }
        self.active_routes.remove(key).map(|active| TcpRoute {
            name: key.name.clone(),
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

    /// Remove a listener from whichever map currently holds it (if any)
    /// and reconstruct the raw `TcpListener`.
    fn take_listener_raw(&mut self, key: &ListenerKey) -> Option<TcpListener> {
        if let Some(raw) = self.pending_listeners.remove(key) {
            return Some(raw);
        }
        self.active_listeners.remove(key).map(|_| TcpListener {
            name: key.name.clone(),
            routes: vec![],
        })
    }

    /// Decide the new placement of `route` under `key` and put it into
    /// exactly one of `pending_routes` or `active_routes`. Preconditions
    /// for active: parent bind known, parent listener known (active or
    /// pending), and every `backend_refs[i].name` resolves.
    fn place_route(&mut self, route: TcpRoute, key: &RouteKey) {
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
        let active = Arc::new(ActiveTcpRoute {
            key: key.clone(),
            filters: route.filters,
            backends: resolved,
        });
        self.active_routes.insert(key.clone(), active);
    }

    /// Decide the new placement of `listener` and put it into exactly
    /// one of `pending_listeners` or `active_listeners`. Done in two
    /// phases: speculatively park in pending so child routes can read
    /// "listener known"; re-resolve every child route; then promote to
    /// active iff parent bind exists and exactly one child route is
    /// active.
    fn place_listener(&mut self, listener: TcpListener, key: &ListenerKey) {
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
        let active_count = self.routes_by_parent.get(key).map_or(0, |set| {
            set.iter()
                .filter(|rk| self.active_routes.contains_key(rk))
                .count()
        });
        if active_count != 1 {
            return;
        }
        let route_key = self
            .routes_by_parent
            .get(key)
            .and_then(|set| {
                set.iter()
                    .find(|rk| self.active_routes.contains_key(rk))
                    .cloned()
            })
            .expect("exactly one active route confirmed above");
        let route = Arc::clone(&self.active_routes[&route_key]);
        let _ = self.pending_listeners.remove(key);
        let active = Arc::new(ActiveListener {
            key: key.clone(),
            kind: ActiveListenerKind::Tcp(ActiveTcpListener { route }),
        });
        self.active_listeners.insert(key.clone(), active);
    }

    /// Take a route's raw form and re-place it under the current state.
    /// No-op if the route is unknown.
    fn re_resolve_route(&mut self, key: &RouteKey) {
        if let Some(raw) = self.take_route_raw(key) {
            self.place_route(raw, key);
        }
    }

    /// Take a listener's raw form and re-place it under the current state.
    fn re_resolve_listener(&mut self, key: &ListenerKey) {
        if let Some(raw) = self.take_listener_raw(key) {
            self.place_listener(raw, key);
        }
    }

    /// Compose a fresh `Arc<ActiveBind>` for `key` from the currently
    /// active listeners under it. Listeners are sorted by name so the
    /// composed value is deterministic regardless of insertion order.
    /// Replaces the existing `Arc` in `binds` — readers holding the old
    /// Arc continue to see the previous snapshot until they re-read.
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
        let listeners: Vec<Arc<ActiveListener>> = lkeys
            .into_iter()
            .map(|lk| Arc::clone(&self.active_listeners[&lk]))
            .collect();
        let active = Arc::new(ActiveBind {
            key: key.clone(),
            address: meta.address,
            port: meta.port,
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
    use gateway_config::listener::{
        HttpListener, HttpsListener, Listener, TcpListener, TlsConfig, TlsMode,
    };
    use gateway_config::route::TcpRoute;

    // --- fixture builders ---

    fn tcp_bind(name: &str, port: u16) -> Bind {
        Bind {
            name: name.into(),
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port,
            bind_protocol: BindProtocol::Tcp,
            listeners: vec![],
        }
    }

    fn http_bind(name: &str, port: u16) -> Bind {
        Bind {
            name: name.into(),
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port,
            bind_protocol: BindProtocol::Http,
            listeners: vec![],
        }
    }

    fn tcp_listener(name: &str) -> Listener {
        Listener::Tcp(TcpListener {
            name: name.into(),
            routes: vec![],
        })
    }

    fn http_listener(name: &str) -> Listener {
        Listener::Http(HttpListener {
            name: name.into(),
            hostname: None,
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

    fn tcp_route(name: &str, backends: &[&str]) -> TcpRoute {
        TcpRoute {
            name: name.into(),
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
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r", &["be"]));
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));

        let read = store.read();
        let bind = read.bind(&bkey("b")).expect("bind active");
        assert_eq!(bind.listeners.len(), 1);
        let ActiveListenerKind::Tcp(tcp) = &bind.listeners[0].kind;
        assert_eq!(tcp.route.backends.len(), 1);
        assert_eq!(tcp.route.backends[0].backend.endpoints[0].port, 8080);
    }

    #[test]
    fn reverse_order_backend_route_listener_bind() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r", &["be"]));
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();

        let read = store.read();
        let bind = read
            .bind(&bkey("b"))
            .expect("bind active after reverse order");
        assert_eq!(bind.listeners.len(), 1);
    }

    #[test]
    fn listener_stashed_without_bind() {
        let store = Store::new();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        let read = store.read();
        assert!(read.bind(&bkey("b")).is_none());
        assert!(!read.is_listener_active(&lkey("b", "l")));
    }

    #[test]
    fn route_stashed_without_listener() {
        let store = Store::new();
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r", &["be"]));
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        let read = store.read();
        // Route requires its parent listener to be observed; it stays pending.
        assert!(!read.is_route_active(&rkey("b", "l", "r")));
        assert!(!read.is_listener_active(&lkey("b", "l")));
    }

    #[test]
    fn route_stashed_without_backend_then_promoted() {
        let store = Store::new();
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r", &["be"]));

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
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r", &["be"]));

        store.remove_bind(&bkey("b"));
        {
            let read = store.read();
            assert!(read.bind(&bkey("b")).is_none());
            assert!(!read.is_listener_active(&lkey("b", "l")));
        }

        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        let bind = store.read().bind(&bkey("b")).unwrap();
        assert_eq!(bind.listeners.len(), 1);
    }

    #[test]
    fn cascade_on_listener_remove() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r", &["be"]));

        store.remove_listener(&lkey("b", "l"));
        let bind = store.read().bind(&bkey("b")).unwrap();
        assert!(bind.listeners.is_empty());
    }

    #[test]
    fn cascade_on_backend_remove() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r", &["be"]));

        store.remove_backend(&backendkey("be"));
        assert!(!store.read().is_route_active(&rkey("b", "l", "r")));
        assert!(store.read().bind(&bkey("b")).unwrap().listeners.is_empty());

        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.99", 9999)]));
        let bind = store.read().bind(&bkey("b")).unwrap();
        let ActiveListenerKind::Tcp(tcp) = &bind.listeners[0].kind;
        assert_eq!(tcp.route.backends[0].backend.endpoints[0].port, 9999);
    }

    #[test]
    fn backend_update_propagates_new_endpoints() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r", &["be"]));

        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.2", 9090)]));
        let bind = store.read().bind(&bkey("b")).unwrap();
        let ActiveListenerKind::Tcp(tcp) = &bind.listeners[0].kind;
        assert_eq!(tcp.route.backends[0].backend.endpoints[0].port, 9090);
    }

    #[test]
    fn embedded_listeners_and_routes_via_upsert_bind() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        let mut b = tcp_bind("b", 5432);
        b.listeners.push(Listener::Tcp(TcpListener {
            name: "l".into(),
            routes: vec![tcp_route("r", &["be"])],
        }));
        store.upsert_bind(b).unwrap();
        let bind = store.read().bind(&bkey("b")).unwrap();
        assert_eq!(bind.listeners.len(), 1);
        let ActiveListenerKind::Tcp(tcp) = &bind.listeners[0].kind;
        assert_eq!(tcp.route.backends.len(), 1);
    }

    #[test]
    fn non_tcp_bind_rejected() {
        let store = Store::new();
        let err = store.upsert_bind(http_bind("b", 80)).unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedProtocol { .. }));
    }

    #[test]
    fn non_tcp_listener_rejected() {
        let store = Store::new();
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        let err = store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedProtocol { .. }));
        let err = store
            .upsert_listener(&bkey("b"), https_listener("l2"))
            .unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedProtocol { .. }));
    }

    #[test]
    fn tcp_bind_with_non_tcp_embedded_listener_rejected() {
        let store = Store::new();
        let mut b = tcp_bind("b", 5432);
        b.listeners.push(http_listener("l"));
        let err = store.upsert_bind(b).unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedProtocol { .. }));
    }

    #[test]
    fn listener_with_zero_routes_not_active() {
        let store = Store::new();
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        assert!(!store.read().is_listener_active(&lkey("b", "l")));
        assert!(store.read().bind(&bkey("b")).unwrap().listeners.is_empty());
    }

    #[test]
    fn listener_with_two_routes_not_active() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r0", &["be"]));
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r1", &["be"]));
        // Two active routes under one listener — schema says exactly one, store demotes the listener.
        assert!(!store.read().is_listener_active(&lkey("b", "l")));
    }

    #[test]
    fn route_with_multiple_backends_all_resolve() {
        let store = Store::new();
        store.upsert_backend(static_backend("be0", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_backend(static_backend("be1", &[("e0", "10.0.0.2", 8080)]));
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r", &["be0", "be1"]));

        let bind = store.read().bind(&bkey("b")).unwrap();
        let ActiveListenerKind::Tcp(tcp) = &bind.listeners[0].kind;
        assert_eq!(tcp.route.backends.len(), 2);
    }

    #[test]
    fn route_with_one_missing_backend_stays_pending() {
        let store = Store::new();
        store.upsert_backend(static_backend("be0", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        store.upsert_tcp_route(&lkey("b", "l"), tcp_route("r", &["be0", "be1"]));
        assert!(!store.read().is_route_active(&rkey("b", "l", "r")));

        store.upsert_backend(static_backend("be1", &[("e0", "10.0.0.2", 8080)]));
        assert!(store.read().is_route_active(&rkey("b", "l", "r")));
    }

    #[test]
    fn apply_bootstrap_from_config() {
        let cfg = gateway_config::parse_yaml(
            r"
gatewayConfig:
  name: g
  binds:
    - name: b
      port: 5432
      bindProtocol: TCP
      listeners:
        - name: l
          listenerProtocol: TCP
          routes:
            - name: r
              backendRefs: [{ name: be }]
  backends:
    - name: be
      type: Static
      endpoints:
        - { name: e0, address: 10.0.0.1, port: 8080 }
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
    fn apply_skips_non_tcp() {
        let cfg = gateway_config::parse_yaml(
            r"
gatewayConfig:
  name: g
  binds:
    - name: tcp-bind
      port: 5432
      bindProtocol: TCP
      listeners:
        - name: l
          listenerProtocol: TCP
          routes:
            - { name: r, backendRefs: [{ name: be }] }
    - name: http-bind
      port: 80
      bindProtocol: HTTP
  backends:
    - name: be
      type: Static
      endpoints: [{ name: e0, address: 10.0.0.1, port: 8080 }]
",
        )
        .unwrap();
        let store = Store::new();
        let report = store.apply(&cfg);
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped[0].contains("http-bind"));
        assert!(store.read().bind(&bkey("tcp-bind")).is_some());
        assert!(store.read().bind(&bkey("http-bind")).is_none());
    }

    #[test]
    fn subscribe_emits_added_on_new_bind() {
        let store = Store::new();
        let mut rx = store.subscribe();
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        let evt = rx.try_recv().expect("event");
        assert_eq!(evt, BindEvent::Added(bkey("b")));
    }

    #[test]
    fn subscribe_emits_updated_on_listener_change() {
        let store = Store::new();
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        let mut rx = store.subscribe();
        store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
            .unwrap();
        let evt = rx.try_recv().expect("event");
        assert_eq!(evt, BindEvent::Updated(bkey("b")));
    }

    #[test]
    fn subscribe_emits_removed() {
        let store = Store::new();
        store.upsert_bind(tcp_bind("b", 5432)).unwrap();
        let mut rx = store.subscribe();
        store.remove_bind(&bkey("b"));
        let evt = rx.try_recv().expect("event");
        assert_eq!(evt, BindEvent::Removed(bkey("b")));
    }

    #[test]
    fn store_clone_shares_state() {
        let s1 = Store::new();
        let s2 = s1.clone();
        s1.upsert_bind(tcp_bind("b", 5432)).unwrap();
        assert!(s2.read().bind(&bkey("b")).is_some());
    }
}
