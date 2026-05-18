use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::listener::Listener;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bind {
    pub name: String,
    #[serde(default = "default_bind_address")]
    pub address: IpAddr,
    pub port: u16,
    pub bind_protocol: BindProtocol,
    #[serde(default)]
    pub listeners: Vec<Listener>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum BindProtocol {
    Tls,
    Http,
    Tcp,
}

fn default_bind_address() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}
