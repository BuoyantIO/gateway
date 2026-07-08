//! End-to-end test harness for the gateway. Drives a real kind
//! cluster: each test creates its own namespace, `Gateway`,
//! `HTTPRoute`, and backend; the CP provisions the data plane from
//! the Gateway, and tests reach it at the `LoadBalancer` address read
//! from `Gateway.status.addresses` — the same way an external
//! client would.

pub mod cluster;
pub mod drive;
pub mod fixtures;

pub use cluster::{Scope, kube_client};
pub use drive::{Driver, wait_until_redirected, wait_until_routed, wait_until_routed_tls};
pub use fixtures::{
    HttpRouteBuilder, deploy_echo, deploy_tls_secret, gateway, gateway_address, gateway_https,
    http_route,
};
