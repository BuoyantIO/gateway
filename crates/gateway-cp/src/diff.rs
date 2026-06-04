//! Snapshot diff -> batched `ConfigUpdate`.
//!
//! One pass per entity kind walks `keys(prev) ∪ keys(next)` and
//! classifies: same value → skip, added or changed → `Upsert`,
//! `prev`-only → `Remove`. The four passes share one `upserts` /
//! `removes` pair, ordered Bind → Backend → Listener → Route for
//! readable traces. The DP's Store handles ordering across kinds via
//! its stashing model; the order here is convention, not correctness.

use std::collections::HashSet;

use gateway_cp_proto::v1 as pb;
use gateway_state::{BackendKey, BindKey, ListenerKey, RouteKey};

use crate::snapshot::Snapshot;

/// Build a single `ConfigUpdate` carrying the per-entity changes
/// needed to move the Store from `prev` to `next`. Returns `None`
/// if the snapshots are equal.
pub fn diff(prev: &Snapshot, next: &Snapshot) -> Option<pb::ConfigUpdate> {
    let mut upserts: Vec<pb::Upsert> = Vec::new();
    let mut removes: Vec<pb::Remove> = Vec::new();

    diff_binds(prev, next, &mut upserts, &mut removes);
    diff_backends(prev, next, &mut upserts, &mut removes);
    diff_listeners(prev, next, &mut upserts, &mut removes);
    diff_routes(prev, next, &mut upserts, &mut removes);

    if upserts.is_empty() && removes.is_empty() {
        return None;
    }
    Some(pb::ConfigUpdate {
        upserts,
        removes,
        // Live deltas after bootstrap never set this; the server-side
        // bootstrap path overrides it when sending the initial batch.
        sync_complete: false,
    })
}

fn diff_binds(
    prev: &Snapshot,
    next: &Snapshot,
    upserts: &mut Vec<pb::Upsert>,
    removes: &mut Vec<pb::Remove>,
) {
    let keys: HashSet<&BindKey> = prev.binds.keys().chain(next.binds.keys()).collect();
    for k in keys {
        match (prev.binds.get(k), next.binds.get(k)) {
            (Some(p), Some(n)) if p == n => {}
            (_, Some(n)) => upserts.push(pb::Upsert {
                body: Some(pb::upsert::Body::Bind(n.clone())),
            }),
            (Some(_), None) => removes.push(pb::Remove {
                key: Some(pb::remove::Key::Bind(pb::BindKey { name: k.0.clone() })),
            }),
            (None, None) => unreachable!(),
        }
    }
}

fn diff_backends(
    prev: &Snapshot,
    next: &Snapshot,
    upserts: &mut Vec<pb::Upsert>,
    removes: &mut Vec<pb::Remove>,
) {
    let keys: HashSet<&BackendKey> = prev.backends.keys().chain(next.backends.keys()).collect();
    for k in keys {
        match (prev.backends.get(k), next.backends.get(k)) {
            (Some(p), Some(n)) if p == n => {}
            (_, Some(n)) => upserts.push(pb::Upsert {
                body: Some(pb::upsert::Body::Backend(n.clone())),
            }),
            (Some(_), None) => removes.push(pb::Remove {
                key: Some(pb::remove::Key::Backend(pb::BackendKey {
                    name: k.0.clone(),
                })),
            }),
            (None, None) => unreachable!(),
        }
    }
}

fn diff_listeners(
    prev: &Snapshot,
    next: &Snapshot,
    upserts: &mut Vec<pb::Upsert>,
    removes: &mut Vec<pb::Remove>,
) {
    let keys: HashSet<&ListenerKey> = prev.listeners.keys().chain(next.listeners.keys()).collect();
    for k in keys {
        match (prev.listeners.get(k), next.listeners.get(k)) {
            (Some(p), Some(n)) if p == n => {}
            (_, Some(n)) => upserts.push(pb::Upsert {
                body: Some(pb::upsert::Body::Listener(n.clone())),
            }),
            (Some(_), None) => removes.push(pb::Remove {
                key: Some(pb::remove::Key::Listener(pb::ListenerKey {
                    bind: k.bind.0.clone(),
                    name: k.name.clone(),
                })),
            }),
            (None, None) => unreachable!(),
        }
    }
}

fn diff_routes(
    prev: &Snapshot,
    next: &Snapshot,
    upserts: &mut Vec<pb::Upsert>,
    removes: &mut Vec<pb::Remove>,
) {
    let keys: HashSet<&RouteKey> = prev.routes.keys().chain(next.routes.keys()).collect();
    for k in keys {
        match (prev.routes.get(k), next.routes.get(k)) {
            (Some(p), Some(n)) if p == n => {}
            (_, Some(n)) => upserts.push(pb::Upsert {
                body: Some(pb::upsert::Body::HttpRoute(n.clone())),
            }),
            (Some(_), None) => removes.push(pb::Remove {
                key: Some(pb::remove::Key::HttpRoute(pb::RouteKey {
                    bind: k.listener.bind.0.clone(),
                    listener: k.listener.name.clone(),
                    name: k.name.clone(),
                })),
            }),
            (None, None) => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upsert_bind(name: &str, port: u32) -> pb::BindUpsert {
        pb::BindUpsert {
            name: name.into(),
            address: "0.0.0.0".into(),
            port,
            bind_protocol: pb::BindProtocol::Http as i32,
        }
    }

    #[test]
    fn identical_snapshots_return_none() {
        let mut s = Snapshot::default();
        s.binds.insert(BindKey::new("a"), upsert_bind("a", 80));
        assert!(diff(&s, &s).is_none());
    }

    #[test]
    fn add_yields_upsert_only() {
        let prev = Snapshot::default();
        let mut next = Snapshot::default();
        next.binds.insert(BindKey::new("a"), upsert_bind("a", 80));
        let batch = diff(&prev, &next).expect("diff");
        assert_eq!(batch.upserts.len(), 1);
        assert!(batch.removes.is_empty());
        assert!(!batch.sync_complete);
    }

    #[test]
    fn delete_yields_remove_only() {
        let mut prev = Snapshot::default();
        prev.binds.insert(BindKey::new("a"), upsert_bind("a", 80));
        let next = Snapshot::default();
        let batch = diff(&prev, &next).expect("diff");
        assert!(batch.upserts.is_empty());
        assert_eq!(batch.removes.len(), 1);
    }

    #[test]
    fn value_change_yields_upsert() {
        let mut prev = Snapshot::default();
        prev.binds.insert(BindKey::new("a"), upsert_bind("a", 80));
        let mut next = Snapshot::default();
        next.binds.insert(BindKey::new("a"), upsert_bind("a", 81));
        let batch = diff(&prev, &next).expect("diff");
        assert_eq!(batch.upserts.len(), 1);
        assert!(batch.removes.is_empty());
    }

    #[test]
    fn mixed_diff_has_both_upserts_and_removes() {
        let mut prev = Snapshot::default();
        prev.binds.insert(BindKey::new("a"), upsert_bind("a", 80));
        prev.binds.insert(BindKey::new("b"), upsert_bind("b", 81));
        let mut next = Snapshot::default();
        next.binds.insert(BindKey::new("a"), upsert_bind("a", 80));
        next.binds.insert(BindKey::new("c"), upsert_bind("c", 82));
        let batch = diff(&prev, &next).expect("diff");
        // b removed, c added.
        assert_eq!(batch.upserts.len(), 1);
        assert_eq!(batch.removes.len(), 1);
    }
}
