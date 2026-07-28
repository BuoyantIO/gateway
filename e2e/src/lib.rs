//! End-to-end test harness for the gateway. Drives a real kind
//! cluster: each test creates its own namespace, `Gateway`,
//! `HTTPRoute`, and backend; the CP provisions the data plane from
//! the Gateway, and tests reach it at the `LoadBalancer` address read
//! from `Gateway.status.addresses` — the same way an external
//! client would.

pub mod cluster;
pub mod drive;
pub mod fixtures;

/// Generated types for the e2e gRPC echo service (`proto/echo.proto`).
pub mod grpc {
    #![allow(clippy::pedantic, clippy::nursery, clippy::all, missing_docs)]
    tonic::include_proto!("echo.v1");
}

pub use cluster::{Scope, kube_client};
pub use drive::{Driver, wait_until_redirected, wait_until_routed, wait_until_routed_tls};
pub use fixtures::{
    HttpRouteBuilder, annotate_gateway, delete_http_route, deploy_echo, deploy_grpc_echo,
    deploy_tls_secret, dp_admin_get, gateway, gateway_address, gateway_https,
    gateway_https_with_cert_ns, http_route, scale_deployment,
};
