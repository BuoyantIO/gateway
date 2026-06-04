//! Kubernetes control plane: watches Gateway API resources and pushes
//! incremental `ConfigUpdate` batches to data planes over a streaming
//! gRPC channel.
//!
//! This task wires only the pure translation + diff layer. Watch
//! plumbing and the gRPC server land in later steps.

pub mod diff;
pub mod server;
pub mod snapshot;
pub mod translator;

pub use diff::diff;
pub use server::{ConfigStreamService, ServerState};
pub use snapshot::{GatewayId, Snapshot};
pub use translator::{K8sState, translate};
