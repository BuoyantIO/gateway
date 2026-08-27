//! The gateway's data-plane runtime. Subscribes to `BindEvent`s from a
//! `gateway_state::Store`, manages one accept task per active bind, and
//! dispatches accepted connections to the appropriate protocol handler.

mod accept;
mod error;
mod gateway;
pub mod lb;
pub mod metrics;
mod proxy;

pub use error::RuntimeError;
pub use gateway::Gateway;
pub use gateway_drain as drain;
pub use gateway_extension as extension;
pub use metrics::Metrics;
pub use proxy::http::HttpClient;
