//! Per-Gateway snapshot: one collection of proto upsert messages
//! grouped by entity kind. The translator emits one per Gateway; the
//! diff turns two of them into a `ConfigUpdate`.

use std::collections::HashMap;

use gateway_cp_proto::v1 as pb;
use gateway_state::{BackendKey, BindKey, ListenerKey, RouteKey, SecretKey};

/// `(namespace, name)` of a Gateway resource.
pub type GatewayId = (String, String);

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Snapshot {
    pub binds: HashMap<BindKey, pb::BindUpsert>,
    pub listeners: HashMap<ListenerKey, pb::ListenerUpsert>,
    pub routes: HashMap<RouteKey, pb::HttpRouteUpsert>,
    pub backends: HashMap<BackendKey, pb::BackendUpsert>,
    pub secrets: HashMap<SecretKey, pb::SecretUpsert>,
}
