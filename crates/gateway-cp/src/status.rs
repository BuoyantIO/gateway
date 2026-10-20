//! Status writeback: desired values and the apiserver writer.
//!
//! [`build`] is the pure half — resolution outcomes in, Gateway API
//! status types out; [`writer`] owns every status write. The kube
//! watch loop connects them through a `tokio::sync::watch` channel
//! carrying a [`StatusWork`] per translate pass, so status writes
//! can never block config publication to data planes.

pub mod build;
pub mod writer;

pub use build::{
    StatusSet, StatusWork, build, build_work, reconcile_backend_binding_status,
    reconcile_gateway_backend_status, reconcile_gateway_class_status, reconcile_gateway_status,
};
