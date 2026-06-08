//! Typed gateway configuration: data model, YAML parsing, and
//! per-object validation.

pub mod backend;
pub mod bind;
pub mod config;
pub mod error;
pub mod filter;
pub mod listener;
pub mod parse;
pub mod route;
pub mod secret;
pub(crate) mod serde_http;
pub mod validate;

pub use config::GatewayConfig;
pub use error::ParseError;
pub use parse::parse_yaml;
pub use validate::{Rejection, RejectionReason, validate};
