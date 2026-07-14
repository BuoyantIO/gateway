use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::{RwLock, RwLockReadGuard};
use tokio::sync::broadcast;

use gateway_config::GatewayConfig;
use gateway_config::backend::{Backend, BackendRef};
use gateway_config::bind::{Bind, BindProtocol};
use gateway_config::listener::{Listener, TlsMode};
use gateway_config::route::HttpRoute;
use gateway_config::secret::TlsSecret;

use crate::active::{
    ActiveBackend, ActiveBackendRef, ActiveBind, ActiveHttpRoute, ActiveListener, ActiveTls,
};
use crate::error::{ApplyReport, StoreError};
use crate::event::BindEvent;
use crate::key::{BackendKey, BindKey, ListenerKey, RegisteredKeys, RouteKey, SecretKey};

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
//   * Route:    parent bind registered AND parent listener registered.
//               Backend refs resolve per-ref: a ref naming an
//               unregistered backend rides along unresolved, and the
//               runtime answers 500 for traffic destined to it.
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
    /// Registered TLS secrets. Like backends, these have no
    /// preconditions — always active when registered.
    secrets: HashMap<SecretKey, Arc<TlsSecret>>,

    /// Listeners whose preconditions are NOT currently met.
    pending_listeners: HashMap<ListenerKey, PendingListener>,
    /// HTTP routes whose preconditions are NOT currently met.
    /// The route's matches are already typed and pre-compiled — the
    /// values inside `HttpRoute` are parsed at YAML/proto
    /// deserialization time, no per-apply or per-request compile.
    pending_routes: HashMap<RouteKey, HttpRoute>,

    /// Resolved bind graph that readers walk.
    binds: HashMap<BindKey, Arc<ActiveBind>>,
    /// Listeners that satisfy every precondition right now.
    active_listeners: HashMap<ListenerKey, Arc<ActiveListener>>,
    /// Routes that satisfy every precondition right now.
    active_routes: HashMap<RouteKey, Arc<ActiveHttpRoute>>,

    /// Index: listeners under a bind, active OR pending.
    listeners_by_parent: HashMap<BindKey, HashSet<ListenerKey>>,
    /// Index: routes under a listener, active OR pending.
    routes_by_parent: HashMap<ListenerKey, HashSet<RouteKey>>,
    /// Index: routes naming a given backend in their `backend_refs`.
    routes_by_backend: HashMap<BackendKey, HashSet<RouteKey>>,
    /// Index: listeners naming a given secret in their `cert_refs`.
    listeners_by_secret: HashMap<SecretKey, HashSet<ListenerKey>>,
}

/// A listener as held by the store, before resolution. Routes are
/// tracked separately via `routes_by_parent`, not here. An `Https`
/// listener names the TLS secrets it needs; those must all be present
/// before it can be promoted (`cert_refs`). `Http` has no such
/// dependency.
#[derive(Debug, Clone)]
enum PendingListener {
    Http {
        hostname: Option<String>,
    },
    Https {
        hostname: Option<String>,
        cert_refs: Vec<SecretKey>,
    },
}

impl PendingListener {
    fn hostname(&self) -> Option<String> {
        match self {
            Self::Http { hostname } | Self::Https { hostname, .. } => hostname.clone(),
        }
    }

    /// Secrets this listener depends on — empty for `Http`, so the
    /// promotion gate is uniform across both variants.
    fn cert_refs(&self) -> &[SecretKey] {
        match self {
            Self::Http { .. } => &[],
            Self::Https { cert_refs, .. } => cert_refs,
        }
    }
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

    pub fn upsert_secret(&self, secret: TlsSecret) {
        let events = self.inner.write().upsert_secret(secret);
        self.dispatch(events);
    }

    pub fn remove_secret(&self, key: &SecretKey) {
        let events = self.inner.write().remove_secret(key);
        self.dispatch(events);
    }

    pub fn apply(&self, cfg: &GatewayConfig) -> ApplyReport {
        let (report, events) = self.inner.write().apply(cfg);
        self.dispatch(events);
        report
    }

    /// Drop every registered key not in `keep`.
    pub fn retain(&self, keep: &RegisteredKeys) {
        let (stale_routes, stale_backends, stale_listeners, stale_binds, stale_secrets) = {
            let read = self.read();
            (
                read.registered_route_keys()
                    .filter(|k| !keep.routes.contains(k))
                    .collect::<Vec<_>>(),
                read.registered_backend_keys()
                    .filter(|k| !keep.backends.contains(k))
                    .collect::<Vec<_>>(),
                read.registered_listener_keys()
                    .filter(|k| !keep.listeners.contains(k))
                    .collect::<Vec<_>>(),
                read.registered_bind_keys()
                    .filter(|k| !keep.binds.contains(k))
                    .collect::<Vec<_>>(),
                read.registered_secret_keys()
                    .filter(|k| !keep.secrets.contains(k))
                    .collect::<Vec<_>>(),
            )
        };
        for k in &stale_routes {
            self.remove_http_route(k);
        }
        for k in &stale_backends {
            self.remove_backend(k);
        }
        for k in &stale_listeners {
            self.remove_listener(k);
        }
        for k in &stale_binds {
            self.remove_bind(k);
        }
        for k in &stale_secrets {
            self.remove_secret(k);
        }
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

    pub fn secret(&self, key: &SecretKey) -> Option<Arc<TlsSecret>> {
        self.guard.secrets.get(key).cloned()
    }

    pub fn is_listener_active(&self, key: &ListenerKey) -> bool {
        self.guard.active_listeners.contains_key(key)
    }

    pub fn is_route_active(&self, key: &RouteKey) -> bool {
        self.guard.active_routes.contains_key(key)
    }

    /// Every bind currently upserted into the store. Binds have no
    /// preconditions, so "registered" and "active" coincide.
    pub fn registered_bind_keys(&self) -> impl Iterator<Item = BindKey> + '_ {
        self.guard.bind_meta.keys().cloned()
    }

    /// Every listener currently upserted, active or pending. Pending
    /// listeners are stashed when their parent bind is missing or
    /// they have no active routes; both states are valid Store
    /// residency and need to appear here so a consumer computing a
    /// snapshot diff can find them.
    pub fn registered_listener_keys(&self) -> impl Iterator<Item = ListenerKey> + '_ {
        self.guard
            .pending_listeners
            .keys()
            .chain(self.guard.active_listeners.keys())
            .cloned()
    }

    /// Every route currently upserted, active or pending.
    pub fn registered_route_keys(&self) -> impl Iterator<Item = RouteKey> + '_ {
        self.guard
            .pending_routes
            .keys()
            .chain(self.guard.active_routes.keys())
            .cloned()
    }

    /// Every backend currently upserted.
    pub fn registered_backend_keys(&self) -> impl Iterator<Item = BackendKey> + '_ {
        self.guard.backends.keys().cloned()
    }

    /// Every secret currently upserted.
    pub fn registered_secret_keys(&self) -> impl Iterator<Item = SecretKey> + '_ {
        self.guard.secrets.keys().cloned()
    }
}

// ==================== Inner mutation methods ====================

impl Inner {
    fn upsert_bind(&mut self, bind: Bind) -> Result<Vec<BindEvent>, StoreError> {
        // HTTP (plaintext) and TLS (termination) binds are served; TCP
        // is not. Embedded listeners are validated by the shared
        // `decompose_listener` below.
        if !matches!(bind.bind_protocol, BindProtocol::Http | BindProtocol::Tls) {
            return Err(StoreError::UnsupportedProtocol {
                kind: "bind",
                name: bind.name,
            });
        }
        // Validate all embedded listeners before mutating any state:
        // each must decompose, and its protocol must match the bind's.
        let decomposed = bind
            .listeners
            .into_iter()
            .map(decompose_listener)
            .collect::<Result<Vec<_>, _>>()?;
        for (name, data, _) in &decomposed {
            if !protocol_matches(bind.bind_protocol, data) {
                return Err(StoreError::ListenerBindMismatch {
                    listener: name.clone(),
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

        for (name, data, routes) in decomposed {
            self.upsert_listener_raw(&key, name, data, routes);
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
        let (name, data, routes) = decompose_listener(listener)?;
        // Reject a listener whose protocol contradicts its bind — but
        // only once the bind is known; an orphan listener is validated
        // when its bind lands.
        if let Some(meta) = self.bind_meta.get(parent)
            && !protocol_matches(meta.bind_protocol, &data)
        {
            return Err(StoreError::ListenerBindMismatch { listener: name });
        }
        self.upsert_listener_raw(parent, name, data, routes);
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
    fn upsert_listener_raw(
        &mut self,
        parent: &BindKey,
        name: String,
        data: PendingListener,
        routes: Vec<HttpRoute>,
    ) {
        let lkey = ListenerKey::new(parent.clone(), name);
        self.clear_listener_secret_index(&lkey);
        let _ = self.pending_listeners.remove(&lkey);
        let _ = self.active_listeners.remove(&lkey);

        self.listeners_by_parent
            .entry(parent.clone())
            .or_default()
            .insert(lkey.clone());
        for sref in data.cert_refs() {
            self.listeners_by_secret
                .entry(sref.clone())
                .or_default()
                .insert(lkey.clone());
        }

        for r in routes {
            self.upsert_route_raw(&lkey, r);
        }
        self.place_listener(data, &lkey);
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
        self.clear_listener_secret_index(key);
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
        let rkey = RouteKey::new(parent.clone(), route.name.clone());
        self.upsert_route_raw(parent, route);
        self.patch_listener_route(parent, &rkey);
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
        self.patch_listener_route(&key.listener, key);
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
            protocol: s.protocol,
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

    // A `TlsSecret` is valid by construction (parsed on the way in),
    // so this is infallible. Listeners may depend on the secret via
    // their `cert_refs`, so re-resolve those.
    fn upsert_secret(&mut self, secret: TlsSecret) -> Vec<BindEvent> {
        let key = SecretKey::new(secret.namespace.clone(), secret.name.clone());
        self.secrets.insert(key.clone(), Arc::new(secret));
        self.cascade_listeners_by_secret(&key)
    }

    fn remove_secret(&mut self, key: &SecretKey) -> Vec<BindEvent> {
        if self.secrets.remove(key).is_none() {
            return Vec::new();
        }
        self.cascade_listeners_by_secret(key)
    }

    fn cascade_listeners_by_secret(&mut self, key: &SecretKey) -> Vec<BindEvent> {
        let lkeys: Vec<ListenerKey> = self
            .listeners_by_secret
            .get(key)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut affected_binds: HashSet<BindKey> = HashSet::new();
        for lk in &lkeys {
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
            let mut e = self.upsert_secret(secret.clone());
            report.applied += 1;
            events.append(&mut e);
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
        self.secrets.clear();
        self.pending_listeners.clear();
        self.pending_routes.clear();
        self.binds.clear();
        self.active_listeners.clear();
        self.active_routes.clear();
        self.listeners_by_parent.clear();
        self.routes_by_parent.clear();
        self.routes_by_backend.clear();
        self.listeners_by_secret.clear();
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
                    name: abr.key.0.clone(),
                    weight: abr.weight,
                })
                .collect(),
            filters: active.filters.clone(),
        })
    }

    /// Strip secret-index entries for a listener key (used before
    /// re-indexing with the new `cert_refs` on update, and on remove).
    fn clear_listener_secret_index(&mut self, key: &ListenerKey) {
        let secret_keys: Vec<SecretKey> = self
            .listeners_by_secret
            .iter()
            .filter(|(_, set)| set.contains(key))
            .map(|(sk, _)| sk.clone())
            .collect();
        for sk in secret_keys {
            let empty = match self.listeners_by_secret.get_mut(&sk) {
                Some(set) => {
                    set.remove(key);
                    set.is_empty()
                }
                None => false,
            };
            if empty {
                self.listeners_by_secret.remove(&sk);
            }
        }
    }

    /// Take a listener's raw form. For an active listener the cert refs
    /// come back from the secret index so a re-resolve preserves the
    /// TLS dependency. (A listener with no cert refs round-trips as
    /// `Http`; the store treats that identically to a hypothetical
    /// zero-cert HTTPS listener, which the wire never produces.)
    fn take_listener_raw(&mut self, key: &ListenerKey) -> Option<PendingListener> {
        if let Some(raw) = self.pending_listeners.remove(key) {
            return Some(raw);
        }
        let active = self.active_listeners.remove(key)?;
        let hostname = active.hostname.clone();
        let cert_refs = self.cert_refs_for(key);
        Some(if cert_refs.is_empty() {
            PendingListener::Http { hostname }
        } else {
            PendingListener::Https {
                hostname,
                cert_refs,
            }
        })
    }

    /// Cert refs currently indexed for a listener (its TLS dependency).
    fn cert_refs_for(&self, key: &ListenerKey) -> Vec<SecretKey> {
        self.listeners_by_secret
            .iter()
            .filter(|(_, set)| set.contains(key))
            .map(|(sk, _)| sk.clone())
            .collect()
    }

    /// Decide the new placement of `route` under `key`. Active iff
    /// parent bind known and parent listener known (active or
    /// pending). Backend refs resolve individually: a ref naming an
    /// unregistered backend stays on the active route unresolved.
    fn place_route(&mut self, route: HttpRoute, key: &RouteKey) {
        if !self.bind_meta.contains_key(&key.listener.bind) || !self.listener_known(&key.listener) {
            self.pending_routes.insert(key.clone(), route);
            return;
        }
        let resolved = route
            .backend_refs
            .iter()
            .map(|br| {
                let bkey = BackendKey::new(br.name.clone());
                let backend = self.backends.get(&bkey).map(Arc::clone);
                ActiveBackendRef {
                    key: bkey,
                    backend,
                    weight: br.weight,
                }
            })
            .collect();
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
    /// to active iff parent bind exists, every referenced TLS secret
    /// is present, and **at least one** child route is active.
    fn place_listener(&mut self, listener: PendingListener, key: &ListenerKey) {
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

        let Some(meta) = self.bind_meta.get(&key.bind) else {
            return;
        };
        // Protocol gate: a listener never activates under a bind of the
        // wrong protocol. The upsert paths reject this when the bind is
        // already known; this also catches an orphan listener whose bind
        // lands later.
        if !protocol_matches(meta.bind_protocol, &self.pending_listeners[key]) {
            return;
        }
        // TLS dependency: every referenced secret must be present
        let secrets_ready = self.pending_listeners[key]
            .cert_refs()
            .iter()
            .all(|s| self.secrets.contains_key(s));
        if !secrets_ready {
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
        // Resolve the listener's cert refs to the secrets it terminates
        // with. All are present (checked above); empty == plaintext HTTP.
        let tls = match raw.cert_refs() {
            [] => None,
            refs => Some(ActiveTls {
                secrets: refs.iter().map(|s| Arc::clone(&self.secrets[s])).collect(),
            }),
        };
        let active = Arc::new(ActiveListener {
            key: key.clone(),
            hostname: raw.hostname(),
            routes,
            tls,
        });
        self.active_listeners.insert(key.clone(), active);
    }

    /// Update one route in its listener without touching the
    /// siblings.
    ///
    /// If the listener is active and stays active, copy its route
    /// list, patch the one entry at its sorted position, and swap the
    /// listener. The copy is a list of `Arc`s — cheap at any size.
    ///
    /// If the listener flips between pending and active (first route
    /// arrives, or the last one leaves), fall back to the full
    /// `place_listener` re-evaluation. That's rare.
    fn patch_listener_route(&mut self, lkey: &ListenerKey, rkey: &RouteKey) {
        let route = self.active_routes.get(rkey).cloned();
        let Some(current) = self.active_listeners.get(lkey) else {
            // The listener isn't active. A newly active route may
            // promote it; anything else changes nothing.
            if route.is_some() {
                self.re_resolve_listener(lkey);
            }
            return;
        };
        let mut routes = current.routes.clone();
        let idx = routes.binary_search_by(|r| r.key.name.cmp(&rkey.name));
        match (route, idx) {
            (Some(new), Ok(i)) => routes[i] = new,
            (Some(new), Err(i)) => routes.insert(i, new),
            (None, Ok(i)) => {
                routes.remove(i);
            }
            // Route wasn't in the list and still isn't.
            (None, Err(_)) => return,
        }
        if routes.is_empty() {
            // No active routes left: the listener goes pending.
            self.re_resolve_listener(lkey);
            return;
        }
        let updated = Arc::new(ActiveListener {
            key: current.key.clone(),
            hostname: current.hostname.clone(),
            routes,
            tls: current.tls.clone(),
        });
        self.active_listeners.insert(lkey.clone(), updated);
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
        let listeners: Vec<Arc<ActiveListener>> = lkeys
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

/// Whether a listener's kind is valid under a bind's protocol. The
/// runtime dispatches the accept path on the bind protocol, so an HTTP
/// listener belongs only under an HTTP bind and an HTTPS (terminating)
/// listener only under a TLS bind. TCP binds never reach here.
fn protocol_matches(bind: BindProtocol, listener: &PendingListener) -> bool {
    matches!(
        (bind, listener),
        (BindProtocol::Http, PendingListener::Http { .. })
            | (BindProtocol::Tls, PendingListener::Https { .. })
    )
}

/// Normalize a config `Listener` into the store's pending shape, with
/// its routes split out. Accepts HTTP (no cert refs) and terminating
/// HTTPS (cert refs from its TLS config); rejects passthrough TLS, TCP,
/// and HTTPS configs the store can't serve (non-`Terminate` mode or
/// non-`Secret` certificate refs). Shared by the embedded
/// (`upsert_bind`) and incremental (`upsert_listener`) paths.
fn decompose_listener(
    listener: Listener,
) -> Result<(String, PendingListener, Vec<HttpRoute>), StoreError> {
    match listener {
        Listener::Http(h) => Ok((
            h.name,
            PendingListener::Http {
                hostname: h.hostname,
            },
            h.routes,
        )),
        Listener::Https(h) => {
            if h.tls.mode != TlsMode::Terminate {
                return Err(StoreError::UnsupportedTls {
                    name: h.name,
                    reason: "only Terminate mode is supported",
                });
            }
            if h.tls.certificates.iter().any(|c| c.kind != "Secret") {
                return Err(StoreError::UnsupportedTls {
                    name: h.name,
                    reason: "certificate refs must be of kind Secret",
                });
            }
            let cert_refs = h
                .tls
                .certificates
                .iter()
                .map(|c| SecretKey::new(c.namespace.clone(), c.name.clone()))
                .collect();
            Ok((
                h.name,
                PendingListener::Https {
                    hostname: h.hostname,
                    cert_refs,
                },
                h.routes,
            ))
        }
        other => Err(StoreError::UnsupportedProtocol {
            kind: "listener",
            name: other.name().to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};

    use gateway_config::backend::{Backend, BackendProtocol, BackendRef, Endpoint, StaticBackend};
    use gateway_config::bind::{Bind, BindProtocol};
    use gateway_config::filter::{HeaderOps, HeaderPair, HttpFilter};
    use gateway_config::listener::{
        CertRef, HttpListener, HttpsListener, Listener, TcpListener, TlsConfig, TlsMode,
    };
    use gateway_config::route::{HttpMatch, HttpRoute, PathMatch};

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
        https_listener_with_certs(name, &[])
    }

    fn https_listener_with_certs(name: &str, certs: &[&str]) -> Listener {
        Listener::Https(HttpsListener {
            name: name.into(),
            hostname: None,
            tls: TlsConfig {
                mode: TlsMode::Terminate,
                certificates: certs
                    .iter()
                    .map(|c| CertRef {
                        namespace: String::new(),
                        name: (*c).into(),
                        kind: "Secret".into(),
                    })
                    .collect(),
            },
            routes: vec![],
        })
    }

    fn http_route(name: &str, path_prefix: &str, backends: &[&str]) -> HttpRoute {
        HttpRoute {
            name: name.into(),
            matches: vec![HttpMatch {
                host: None,
                path: PathMatch::PathPrefix {
                    value: path_prefix.into(),
                },
                method: None,
                headers: vec![],
                query_params: vec![],
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
            protocol: BackendProtocol::default(),
        })
    }

    fn static_backend_h2(name: &str, endpoints: &[(&str, &str, u16)]) -> Backend {
        let Backend::Static(mut s) = static_backend(name, endpoints);
        s.protocol = BackendProtocol::Http2;
        Backend::Static(s)
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
    fn resolved_backend(abr: &ActiveBackendRef) -> &ActiveBackend {
        abr.backend.as_ref().expect("backend ref resolves")
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
        assert_eq!(resolved_backend(&route.backends[0]).endpoints[0].port, 8080);
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
    fn route_with_missing_backend_activates_unresolved() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));

        // The missing backend does not hold the route (or its
        // listener) back — the ref rides along unresolved.
        assert!(store.read().is_route_active(&rkey("b", "l", "r")));
        {
            let read = store.read();
            let bind = read.bind(&bkey("b")).unwrap();
            assert_eq!(bind.listeners.len(), 1);
            let route = &bind.listeners[0].routes[0];
            assert!(route.backends[0].backend.is_none());
            assert_eq!(route.backends[0].key, backendkey("be"));
        }

        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));

        let read = store.read();
        let bind = read.bind(&bkey("b")).unwrap();
        let route = &bind.listeners[0].routes[0];
        assert_eq!(resolved_backend(&route.backends[0]).endpoints[0].port, 8080);
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

        // Removing the backend leaves the route (and listener) active;
        // the ref goes unresolved.
        store.remove_backend(&backendkey("be"));
        {
            let read = store.read();
            assert!(read.is_route_active(&rkey("b", "l", "r")));
            let bind = read.bind(&bkey("b")).unwrap();
            assert_eq!(bind.listeners.len(), 1);
            assert!(bind.listeners[0].routes[0].backends[0].backend.is_none());
        }

        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.99", 9999)]));
        let bind = store.read().bind(&bkey("b")).unwrap();
        let route = &bind.listeners[0].routes[0];
        assert_eq!(resolved_backend(&route.backends[0]).endpoints[0].port, 9999);
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
        assert_eq!(resolved_backend(&route.backends[0]).endpoints[0].port, 9090);
    }

    #[test]
    fn embedded_listeners_and_routes_via_upsert_bind() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        let mut b = http_bind("b", 80);
        b.listeners.push(Listener::Http(HttpListener {
            name: "l".into(),
            hostname: Some("svc.local".into()),
            // Same shape as the public API now — config and store
            // share `HttpRoute`.
            routes: vec![http_route("r", "/", &["be"])],
        }));
        store.upsert_bind(b).unwrap();
        let bind = store.read().bind(&bkey("b")).unwrap();
        let listener = &bind.listeners[0];
        assert_eq!(listener.hostname.as_deref(), Some("svc.local"));
        assert_eq!(listener.routes.len(), 1);
        assert_eq!(
            resolved_backend(&listener.routes[0].backends[0]).endpoints[0].port,
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
    fn tls_bind_accepted() {
        // TLS binds are served now (termination); the bind registers
        // even with no listener yet.
        let store = Store::new();
        store.upsert_bind(tls_bind("b", 443)).unwrap();
        assert!(store.read().bind(&bkey("b")).is_some());
    }

    #[test]
    fn https_listener_accepted() {
        // HTTPS listeners are accepted under a TLS bind (their cert
        // refs gate promotion); only TCP / passthrough TLS are rejected.
        let store = Store::new();
        store.upsert_bind(tls_bind("b", 443)).unwrap();
        assert!(
            store
                .upsert_listener(&bkey("b"), https_listener("l"))
                .is_ok()
        );
    }

    #[test]
    fn tcp_listener_rejected() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        let err = store
            .upsert_listener(&bkey("b"), tcp_listener("l"))
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

    // The runtime dispatches the accept path by bind protocol, so a
    // listener whose protocol doesn't match its bind must be rejected:
    // an HTTP listener under a TLS bind would get no certs, and an
    // HTTPS listener under an HTTP bind would be served as plaintext.

    #[test]
    fn http_listener_under_tls_bind_rejected() {
        let store = Store::new();
        store.upsert_bind(tls_bind("b", 443)).unwrap();
        let err = store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap_err();
        assert!(matches!(err, StoreError::ListenerBindMismatch { .. }));
    }

    #[test]
    fn https_listener_under_http_bind_rejected() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        let err = store
            .upsert_listener(&bkey("b"), https_listener("l"))
            .unwrap_err();
        assert!(matches!(err, StoreError::ListenerBindMismatch { .. }));
    }

    #[test]
    fn embedded_https_listener_under_http_bind_rejected() {
        let store = Store::new();
        let mut b = http_bind("b", 80);
        b.listeners.push(https_listener("l"));
        let err = store.upsert_bind(b).unwrap_err();
        assert!(matches!(err, StoreError::ListenerBindMismatch { .. }));
    }

    #[test]
    fn embedded_http_listener_under_tls_bind_rejected() {
        let store = Store::new();
        let mut b = tls_bind("b", 443);
        b.listeners.push(http_listener("l"));
        let err = store.upsert_bind(b).unwrap_err();
        assert!(matches!(err, StoreError::ListenerBindMismatch { .. }));
    }

    // A listener stashed before its bind is validated at upsert time
    // (bind unknown), so the protocol gate must also hold at promotion:
    // an orphan HTTPS listener whose bind later lands as HTTP must never
    // be promoted (which would serve it as plaintext).
    #[test]
    fn orphan_listener_not_promoted_under_mismatched_bind() {
        let store = Store::new();
        store
            .upsert_listener(&bkey("b"), https_listener_with_certs("l", &["app-tls"]))
            .unwrap();
        store.upsert_secret(tls_secret("app-tls"));
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));

        // The bind lands as HTTP — a mismatch for the HTTPS listener.
        store.upsert_bind(http_bind("b", 80)).unwrap();

        assert!(!store.read().is_listener_active(&lkey("b", "l")));
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
    fn backend_protocol_round_trips() {
        let store = Store::new();
        store.upsert_backend(static_backend("h1be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_backend(static_backend_h2("h2be", &[("e0", "10.0.0.2", 8080)]));

        let read = store.read();
        assert_eq!(
            read.backend(&backendkey("h1be")).unwrap().protocol,
            BackendProtocol::Http1
        );
        assert_eq!(
            read.backend(&backendkey("h2be")).unwrap().protocol,
            BackendProtocol::Http2
        );
    }

    #[test]
    fn route_with_one_missing_backend_activates_partially_resolved() {
        let store = Store::new();
        store.upsert_backend(static_backend("be0", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be0", "be1"]));
        assert!(store.read().is_route_active(&rkey("b", "l", "r")));
        {
            let read = store.read();
            let route = &read.bind(&bkey("b")).unwrap().listeners[0].routes[0];
            assert!(route.backends[0].backend.is_some());
            assert!(route.backends[1].backend.is_none());
        }

        store.upsert_backend(static_backend("be1", &[("e0", "10.0.0.2", 8080)]));
        let read = store.read();
        let route = &read.bind(&bkey("b")).unwrap().listeners[0].routes[0];
        assert!(route.backends.iter().all(|abr| abr.backend.is_some()));
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
                path: PathMatch::PathPrefix { value: "/".into() },
                method: None,
                headers: vec![],
                query_params: vec![],
            }],
            backend_refs: vec![BackendRef {
                name: "be".into(),
                weight: 1,
            }],
            filters: vec![HttpFilter::RequestHeaderModifier {
                name: "add-hdr".into(),
                request_headers: HeaderOps {
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
    fn apply_skips_tcp_keeps_http_and_tls() {
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
        assert_eq!(report.skipped.len(), 1);
        assert!(report.skipped.iter().any(|s| s.contains("tcp-bind")));
        assert!(store.read().bind(&bkey("http-bind")).is_some());
        assert!(store.read().bind(&bkey("tcp-bind")).is_none());
        // TLS binds are served now, so this one is kept.
        assert!(store.read().bind(&bkey("tls-bind")).is_some());
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

    // --- registered_*_keys ---

    #[test]
    fn registered_bind_keys_lists_upserted_binds() {
        let store = Store::new();
        store.upsert_bind(http_bind("a", 80)).unwrap();
        store.upsert_bind(http_bind("b", 81)).unwrap();
        let read = store.read();
        let keys: HashSet<BindKey> = read.registered_bind_keys().collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&bkey("a")));
        assert!(keys.contains(&bkey("b")));
    }

    #[test]
    fn registered_listener_keys_includes_pending_and_active() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        // Active: parent bind exists, has an active route.
        store
            .upsert_listener(&bkey("b"), http_listener("active"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "active"), http_route("r", "/", &["be"]));
        // Pending: no parent bind.
        store
            .upsert_listener(&bkey("no-bind"), http_listener("pending"))
            .unwrap();

        let read = store.read();
        let keys: HashSet<ListenerKey> = read.registered_listener_keys().collect();
        assert!(keys.contains(&lkey("b", "active")));
        assert!(keys.contains(&lkey("no-bind", "pending")));
    }

    #[test]
    fn registered_route_keys_includes_pending_and_active() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("active", "/", &["be"]));
        // Pending: backend doesn't exist.
        store.upsert_http_route(
            &lkey("b", "l"),
            http_route("pending", "/", &["nonexistent"]),
        );

        let read = store.read();
        let keys: HashSet<RouteKey> = read.registered_route_keys().collect();
        assert!(keys.contains(&rkey("b", "l", "active")));
        assert!(keys.contains(&rkey("b", "l", "pending")));
    }

    #[test]
    fn registered_backend_keys_lists_upserted_backends() {
        let store = Store::new();
        store.upsert_backend(static_backend("a", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_backend(static_backend("b", &[("e0", "10.0.0.2", 8080)]));
        let read = store.read();
        let keys: HashSet<BackendKey> = read.registered_backend_keys().collect();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&backendkey("a")));
        assert!(keys.contains(&backendkey("b")));
    }

    #[test]
    fn registered_keys_reflect_removes() {
        let store = Store::new();
        store.upsert_bind(http_bind("a", 80)).unwrap();
        store.upsert_bind(http_bind("b", 81)).unwrap();
        store.remove_bind(&bkey("a"));
        let read = store.read();
        let keys: HashSet<BindKey> = read.registered_bind_keys().collect();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&bkey("b")));
    }

    // --- retain ---

    #[test]
    fn retain_empty_keep_drops_everything() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));

        store.retain(&RegisteredKeys::default());

        let read = store.read();
        assert_eq!(read.registered_bind_keys().count(), 0);
        assert_eq!(read.registered_listener_keys().count(), 0);
        assert_eq!(read.registered_route_keys().count(), 0);
        assert_eq!(read.registered_backend_keys().count(), 0);
    }

    #[test]
    fn retain_keeps_named_entities_drops_others() {
        let store = Store::new();
        store.upsert_backend(static_backend("be0", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_backend(static_backend("be1", &[("e0", "10.0.0.2", 8080)]));
        store.upsert_bind(http_bind("b0", 80)).unwrap();
        store.upsert_bind(http_bind("b1", 81)).unwrap();
        store
            .upsert_listener(&bkey("b0"), http_listener("l0"))
            .unwrap();
        store
            .upsert_listener(&bkey("b1"), http_listener("l1"))
            .unwrap();
        store.upsert_http_route(&lkey("b0", "l0"), http_route("r0", "/", &["be0"]));
        store.upsert_http_route(&lkey("b1", "l1"), http_route("r1", "/", &["be1"]));

        let mut keep = RegisteredKeys::default();
        keep.binds.insert(bkey("b0"));
        keep.listeners.insert(lkey("b0", "l0"));
        keep.routes.insert(rkey("b0", "l0", "r0"));
        keep.backends.insert(backendkey("be0"));

        store.retain(&keep);

        let read = store.read();
        let binds: HashSet<BindKey> = read.registered_bind_keys().collect();
        assert_eq!(binds, [bkey("b0")].into_iter().collect());
        let listeners: HashSet<ListenerKey> = read.registered_listener_keys().collect();
        assert_eq!(listeners, [lkey("b0", "l0")].into_iter().collect());
        let routes: HashSet<RouteKey> = read.registered_route_keys().collect();
        assert_eq!(routes, [rkey("b0", "l0", "r0")].into_iter().collect());
        let backends: HashSet<BackendKey> = read.registered_backend_keys().collect();
        assert_eq!(backends, [backendkey("be0")].into_iter().collect());
    }

    #[test]
    fn retain_with_everything_kept_is_noop() {
        let store = Store::new();
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));

        let keep = RegisteredKeys {
            binds: [bkey("b")].into_iter().collect(),
            listeners: [lkey("b", "l")].into_iter().collect(),
            routes: [rkey("b", "l", "r")].into_iter().collect(),
            backends: [backendkey("be")].into_iter().collect(),
            secrets: HashSet::default(),
        };
        store.retain(&keep);

        let read = store.read();
        assert!(read.is_route_active(&rkey("b", "l", "r")));
        assert!(read.bind(&bkey("b")).is_some());
        assert!(read.backend(&backendkey("be")).is_some());
    }

    #[test]
    fn retain_handles_pending_entities() {
        // Pending route (parent listener not registered) survives if
        // it's in keep.
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));
        assert!(!store.read().is_route_active(&rkey("b", "l", "r")));

        let keep = RegisteredKeys {
            binds: [bkey("b")].into_iter().collect(),
            listeners: HashSet::default(),
            routes: [rkey("b", "l", "r")].into_iter().collect(),
            backends: HashSet::default(),
            secrets: HashSet::default(),
        };
        store.retain(&keep);

        let read = store.read();
        let routes: HashSet<RouteKey> = read.registered_route_keys().collect();
        assert!(routes.contains(&rkey("b", "l", "r")));
    }

    // --- secrets ---

    // Throwaway self-signed EC cert + PKCS#8 key (same pair as the
    // gateway-config fixtures).
    const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
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

    const KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcB/ubr8b5gfbp97H\n\
/hzgYBDdRqvQrz6jRyF1kz8TrcChRANCAARmgXqAedHQ4l0guGq9PvlkTmhf82QK\n\
huMI9EpCZAC8QV43yS5/4Ljj171TYarpLsLvYMlaNyyvyBrGOIxGJ7Qf\n\
-----END PRIVATE KEY-----\n";

    fn secretkey(name: &str) -> SecretKey {
        SecretKey::local(name)
    }

    fn tls_secret(name: &str) -> TlsSecret {
        TlsSecret::new("", name, CERT_PEM, KEY_PEM).expect("valid test secret")
    }

    #[test]
    fn upsert_secret_is_readable() {
        let store = Store::new();
        store.upsert_secret(tls_secret("app-tls"));
        let s = store.read().secret(&secretkey("app-tls")).expect("present");
        assert_eq!(s.name, "app-tls");
        assert_eq!(s.certs.len(), 1);
    }

    #[test]
    fn remove_secret_evicts() {
        let store = Store::new();
        store.upsert_secret(tls_secret("app-tls"));
        store.remove_secret(&secretkey("app-tls"));
        assert!(store.read().secret(&secretkey("app-tls")).is_none());
    }

    #[test]
    fn retain_keeps_listed_secret_drops_unlisted() {
        let store = Store::new();
        store.upsert_secret(tls_secret("keep"));
        store.upsert_secret(tls_secret("drop"));

        let keep = RegisteredKeys {
            secrets: [secretkey("keep")].into_iter().collect(),
            ..Default::default()
        };
        store.retain(&keep);

        assert!(store.read().secret(&secretkey("keep")).is_some());
        assert!(store.read().secret(&secretkey("drop")).is_none());
    }

    #[test]
    fn apply_reports_secret_applied() {
        let store = Store::new();
        let cfg = GatewayConfig {
            name: "t".into(),
            binds: vec![],
            backends: vec![],
            secrets: vec![tls_secret("app-tls")],
        };
        let report = store.apply(&cfg);
        assert_eq!(report.applied, 1);
        assert!(report.skipped.is_empty());
        assert!(store.read().secret(&secretkey("app-tls")).is_some());
    }

    // --- listener → secret stashing ---

    // An HTTPS listener with an active route + backend, but its secret
    // absent: gated pending until the secret lands, demoted when it goes.
    #[test]
    fn https_listener_stashed_until_secret_present() {
        let store = Store::new();
        store.upsert_bind(tls_bind("b", 443)).unwrap();
        store
            .upsert_listener(&bkey("b"), https_listener_with_certs("l", &["app-tls"]))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));

        // Route + backend are present, but the secret is missing.
        assert!(store.read().is_route_active(&rkey("b", "l", "r")));
        assert!(!store.read().is_listener_active(&lkey("b", "l")));

        store.upsert_secret(tls_secret("app-tls"));
        assert!(store.read().is_listener_active(&lkey("b", "l")));

        store.remove_secret(&secretkey("app-tls"));
        assert!(!store.read().is_listener_active(&lkey("b", "l")));
    }

    // All referenced secrets must be present.
    #[test]
    fn https_listener_needs_all_certs() {
        let store = Store::new();
        store.upsert_bind(tls_bind("b", 443)).unwrap();
        store
            .upsert_listener(&bkey("b"), https_listener_with_certs("l", &["a", "b"]))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));

        store.upsert_secret(tls_secret("a"));
        assert!(
            !store.read().is_listener_active(&lkey("b", "l")),
            "b missing"
        );
        store.upsert_secret(tls_secret("b"));
        assert!(store.read().is_listener_active(&lkey("b", "l")));

        store.remove_secret(&secretkey("a"));
        assert!(!store.read().is_listener_active(&lkey("b", "l")));
    }

    // A plain HTTP listener has no cert refs and is
    // unaffected by the secret gate.
    #[test]
    fn http_listener_unaffected_by_secret_gate() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        store
            .upsert_listener(&bkey("b"), http_listener("l"))
            .unwrap();
        store.upsert_http_route(&lkey("b", "l"), http_route("r", "/", &["be"]));
        store.upsert_backend(static_backend("be", &[("e0", "10.0.0.1", 8080)]));
        assert!(store.read().is_listener_active(&lkey("b", "l")));
    }

    fn https_listener_full(name: &str, mode: TlsMode, certs: &[(&str, &str)]) -> Listener {
        Listener::Https(HttpsListener {
            name: name.into(),
            hostname: None,
            tls: TlsConfig {
                mode,
                certificates: certs
                    .iter()
                    .map(|(n, k)| CertRef {
                        namespace: String::new(),
                        name: (*n).into(),
                        kind: (*k).into(),
                    })
                    .collect(),
            },
            routes: vec![],
        })
    }

    // v0 terminates only — a passthrough HTTPS listener is rejected,
    // not accepted and then mis-gated on secrets.
    #[test]
    fn https_listener_passthrough_mode_rejected() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        let l = https_listener_full("l", TlsMode::Passthrough, &[("app-tls", "Secret")]);
        let err = store.upsert_listener(&bkey("b"), l).unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedTls { .. }));
    }

    // Certificate refs must be Kubernetes Secrets; other kinds are
    // rejected rather than gated against the secret set forever.
    #[test]
    fn https_listener_non_secret_cert_kind_rejected() {
        let store = Store::new();
        store.upsert_bind(http_bind("b", 80)).unwrap();
        let l = https_listener_full("l", TlsMode::Terminate, &[("cm", "ConfigMap")]);
        let err = store.upsert_listener(&bkey("b"), l).unwrap_err();
        assert!(matches!(err, StoreError::UnsupportedTls { .. }));
    }

    // Removing a listener must not leave an empty set behind in the
    // secret index (white-box: the index is internal).
    #[test]
    fn removing_listener_cleans_secret_index() {
        let store = Store::new();
        store.upsert_bind(tls_bind("b", 443)).unwrap();
        store
            .upsert_listener(&bkey("b"), https_listener_with_certs("l", &["app-tls"]))
            .unwrap();
        assert!(
            store
                .inner
                .read()
                .listeners_by_secret
                .contains_key(&secretkey("app-tls"))
        );

        store.remove_listener(&lkey("b", "l"));
        assert!(
            !store
                .inner
                .read()
                .listeners_by_secret
                .contains_key(&secretkey("app-tls")),
            "empty secret set should be removed, not left behind"
        );
    }
}
