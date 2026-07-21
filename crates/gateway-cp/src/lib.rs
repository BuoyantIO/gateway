//! Kubernetes control plane: watches Gateway API resources and pushes
//! incremental `ConfigUpdate` batches to data planes over a streaming
//! gRPC channel.

pub mod admin;
pub mod diff;
pub mod infra;
pub mod lease;
pub mod resolve;
pub mod server;
pub mod snapshot;
pub mod status;
pub mod translator;
pub mod watch;

pub use diff::diff;
pub use server::{ConfigStreamService, ServerState};
pub use snapshot::{GatewayId, Snapshot};
pub use translator::{K8sState, translate};
pub use watch::{WatchError, run as run_watch};
