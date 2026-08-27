//! Error type shared by `convert` and `apply`.

use thiserror::Error;

/// Conversion / Store / gRPC errors surfaced by this crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("missing required field `{0}`")]
    MissingField(&'static str),

    #[error("invalid {field}: {value}")]
    InvalidValue { field: &'static str, value: String },

    #[error("unsupported {kind} enum value: {value}")]
    UnsupportedEnum { kind: &'static str, value: i32 },

    #[error("invalid extension `{name}` config: {source}")]
    InvalidExtension {
        name: String,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("invalid header name `{name}`: {source}")]
    InvalidHeaderName {
        name: String,
        #[source]
        source: http::header::InvalidHeaderName,
    },

    #[error("invalid header value `{value}`: {source}")]
    InvalidHeaderValue {
        value: String,
        #[source]
        source: http::header::InvalidHeaderValue,
    },

    #[error("invalid regex `{pattern}`: {source}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },

    #[error("invalid secret `{name}`: {source}")]
    InvalidSecret {
        name: String,
        #[source]
        source: gateway_config::secret::TlsSecretError,
    },

    #[error(transparent)]
    Store(#[from] gateway_state::StoreError),

    #[error("control-plane transport error: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("control-plane stream error: {0}")]
    Stream(#[from] tonic::Status),
}
