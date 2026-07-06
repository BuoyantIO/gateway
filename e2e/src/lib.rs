//! End-to-end test harness for the gateway. Drives a real kind
//! cluster: each test creates its own namespace, `Gateway`, DP
//! `Deployment`, `HTTPRoute`, and backend, then sends real HTTP
//! through the data plane and asserts the response.

pub mod cluster;
pub mod drive;
pub mod fixtures;

pub use cluster::{Scope, kube_client};
pub use drive::{Driver, wait_until_redirected, wait_until_routed, wait_until_routed_tls};
pub use fixtures::{
    HttpRouteBuilder, deploy_dp, deploy_echo, deploy_tls_secret, gateway, gateway_https, http_route,
};

/// Fixed `NodePort` exposed by every test's DP `Service`. Tests run
/// `--test-threads=1` so only one `Service` binds it at a time.
pub const NODE_PORT: u16 = 30080;

/// Host loopback that `kind` maps to the cluster's `NodePort` range.
/// See `e2e/kind.yaml`.
pub const NODE_HOST: &str = "127.0.0.1";
