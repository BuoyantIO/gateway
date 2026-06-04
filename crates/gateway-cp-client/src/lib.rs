//! Data-plane side of the control-plane stream: consume
//! `ConfigUpdate` batches and apply them to a `gateway_state::Store`
//! via its existing incremental API.

pub mod apply;
pub mod client;
pub mod convert;
pub mod error;

pub use apply::{Affected, ApplyOutcome, apply_update};
pub use client::run;
pub use error::Error;
