//! The gateway's data-plane runtime. Subscribes to `BindEvent`s from a
//! `gateway_state::Store`, manages one accept task per active bind, and
//! dispatches accepted connections to the appropriate protocol handler.

mod accept;
mod error;
mod gateway;
mod proxy;

pub use error::RuntimeError;
pub use gateway::Gateway;
