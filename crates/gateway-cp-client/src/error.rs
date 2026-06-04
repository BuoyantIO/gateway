//! Error type shared by `convert` and `apply`.

use thiserror::Error;

/// Failure modes for translating a proto `ConfigUpdate` into Store
/// mutations. Conversion failures (`MissingField`, `InvalidValue`,
/// `UnsupportedEnum`) surface translator-side bugs — the CP should
/// never emit a message that the DP can't construct. The `Store`
/// variant wraps the data-plane-side rejection (only
/// `UnsupportedProtocol` today).
#[derive(Debug, Error)]
pub enum Error {
    #[error("missing required field `{0}`")]
    MissingField(&'static str),

    #[error("invalid {field}: {value}")]
    InvalidValue { field: &'static str, value: String },

    #[error("unsupported {kind} enum value: {value}")]
    UnsupportedEnum { kind: &'static str, value: i32 },

    #[error(transparent)]
    Store(#[from] gateway_state::StoreError),
}
