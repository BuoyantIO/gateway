//! Data-plane side of the gateway control-plane protocol.
//!
//! Consumes `ConfigUpdate` batches from the control plane and applies
//! them to a `gateway_state::Store` via its existing incremental API.
//! No new public surface on the Store.
//!
//! This crate is split into:
//! - `convert` — pure proto-to-`gateway-config` translation
//! - `apply`   — calls `Store::upsert_*` / `remove_*` for each batch item
//! - `error`   — shared error type
//!
//! The gRPC stream loop (`client::run`) lands in a follow-up step;
//! today the crate is library-only and testable in isolation against
//! a fresh `Store`.

pub mod apply;
pub mod convert;
pub mod error;

pub use apply::apply_update;
pub use error::Error;
