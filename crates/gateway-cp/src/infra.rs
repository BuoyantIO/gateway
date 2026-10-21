//! Per-Gateway data-plane infrastructure.
//!
//! The CP provisions a gatewayd `Deployment`, a fronting `Service`,
//! and a `ServiceAccount` in each owned Gateway's namespace.
//! [`desired`] is the pure half — Gateway in, objects out;
//! [`writer`] owns the apiserver writes. The watch loop connects
//! them through an [`InfraPublisher`].

pub(crate) mod annotations;
pub mod desired;
pub mod writer;

pub use desired::{GatewayInfra, InfraConfig, desired, desired_set};
pub use writer::FIELD_MANAGER;

use tokio::sync::watch;

/// Watch-loop side of the provisioner: carries the config used to
/// compute the desired set per translate pass and the channel the
/// writer task listens on.
pub struct InfraPublisher {
    pub config: InfraConfig,
    pub tx: watch::Sender<Vec<GatewayInfra>>,
}

/// Standard Gateway API label naming the owning Gateway. Selector
/// for the DP pods and the filter for the CP's child watches.
pub const GATEWAY_NAME_LABEL: &str = "gateway.networking.k8s.io/gateway-name";

/// Label marking objects this controller manages; the adoption
/// guard refuses to apply over objects that lack it.
pub const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";

/// Value of [`MANAGED_BY_LABEL`] on everything we create.
pub const MANAGED_BY_VALUE: &str = "gateway.buoyant.io";

/// Per-Gateway opt-out annotation: a value of
/// [`PROVISIONING_DISABLED`] makes the Gateway self-managed and the
/// provisioner skips it entirely.
pub const PROVISIONING_ANNOTATION: &str = "gateway.buoyant.io/provisioning";

/// The only recognized [`PROVISIONING_ANNOTATION`] value.
pub const PROVISIONING_DISABLED: &str = "disabled";

/// Per-Gateway override for the provisioned `Service`'s type:
/// `ClusterIP`, `NodePort`, or `LoadBalancer` (the default). Any
/// other value falls back to the default with a warning.
pub const SERVICE_TYPE_ANNOTATION: &str = "gateway.buoyant.io/service-type";

/// Per-Gateway replica count for the provisioned data-plane
/// `Deployment`: a positive integer, default 1. Anything else falls
/// back to the default with a warning.
pub const DP_REPLICAS_ANNOTATION: &str = "gateway.buoyant.io/dp-replicas";

/// Per-Gateway resource requests and limits for the provisioned
/// data-plane container, each a Kubernetes quantity. Unset means no
/// entry; an invalid quantity is skipped with a warning without
/// discarding the others.
pub const DP_CPU_REQUEST_ANNOTATION: &str = "gateway.buoyant.io/dp-cpu-request";
pub const DP_MEMORY_REQUEST_ANNOTATION: &str = "gateway.buoyant.io/dp-memory-request";
pub const DP_CPU_LIMIT_ANNOTATION: &str = "gateway.buoyant.io/dp-cpu-limit";
pub const DP_MEMORY_LIMIT_ANNOTATION: &str = "gateway.buoyant.io/dp-memory-limit";

/// Per-Gateway `RUST_LOG` for the provisioned data-plane container,
/// default `info`.
pub const DP_LOG_FILTER_ANNOTATION: &str = "gateway.buoyant.io/dp-log-filter";

/// Per-Gateway reference to an operator-owned `Service` in the
/// Gateway's own namespace. When set, the provisioner skips its own
/// `Service` (deleting a previously provisioned one) and never
/// mutates the referenced object; address writeback reads the
/// referenced `Service` instead. The operator points its selector at
/// the DP pods via [`GATEWAY_NAME_LABEL`].
pub const SERVICE_NAME_ANNOTATION: &str = "gateway.buoyant.io/service-name";
