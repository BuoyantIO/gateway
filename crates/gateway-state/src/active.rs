use std::net::IpAddr;
use std::sync::Arc;

use gateway_config::backend::Endpoint;
use gateway_config::filter::TcpFilter;

use crate::key::{BackendKey, BindKey, ListenerKey, RouteKey};

#[derive(Debug, Clone)]
pub struct ActiveBind {
    pub key: BindKey,
    pub address: IpAddr,
    pub port: u16,
    pub listeners: Vec<Arc<ActiveListener>>,
}

#[derive(Debug, Clone)]
pub struct ActiveListener {
    pub key: ListenerKey,
    pub kind: ActiveListenerKind,
}

#[derive(Debug, Clone)]
pub enum ActiveListenerKind {
    Tcp(ActiveTcpListener),
}

#[derive(Debug, Clone)]
pub struct ActiveTcpListener {
    pub route: Arc<ActiveTcpRoute>,
}

#[derive(Debug, Clone)]
pub struct ActiveTcpRoute {
    pub key: RouteKey,
    pub filters: Vec<TcpFilter>,
    pub backends: Vec<ActiveBackendRef>,
}

#[derive(Debug, Clone)]
pub struct ActiveBackendRef {
    pub backend: Arc<ActiveBackend>,
    pub weight: u32,
}

#[derive(Debug, Clone)]
pub struct ActiveBackend {
    pub key: BackendKey,
    pub endpoints: Vec<Endpoint>,
}
