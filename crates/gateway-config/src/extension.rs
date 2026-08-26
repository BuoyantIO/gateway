//! Extension objects: named instantiations of extension classes.

use serde::Deserialize;

/// The opaque config type handed to an extension class.
pub type ConfigValue = serde_yaml::Value;

/// A named instantiation of an extension class: which class, the
/// operator's policy, and an opaque config only the class reads.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Extension {
    /// Identity routes reference.
    pub name: String,
    /// The registered class that interprets `config` — e.g. the
    /// built-in `request_header_modifier`, or `bllmp_selector`.
    /// Several objects may name one class, each with its own config.
    pub class: String,
    #[serde(default)]
    pub failure_mode: FailureMode,
    #[serde(default)]
    pub limits: Limits,
    /// Handed to the class verbatim; the gateway never reads a key
    /// inside it. The schema is the class's contract, and the class
    /// rejects what it does not understand.
    #[serde(default)]
    pub config: serde_yaml::Value,
}

/// What a hook error does to the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
pub enum FailureMode {
    /// A hook error fails the request.
    #[default]
    Closed,
    /// A hook error is logged and the request continues.
    Open,
}

/// Operator ceilings clamping what the class's builder may declare.
/// An absent field is no ceiling.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    /// Ceiling on the declared request-body mode. `None` (the
    /// variant) is a valid ceiling: the class may not read the body.
    pub request_body: Option<RequestBodyLimit>,
    /// Max buffer size in bytes; only meaningful with
    /// `requestBody: Buffer`.
    pub max_buffer_bytes: Option<u64>,
}

/// The request-body modes an operator may grant, ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub enum RequestBodyLimit {
    None,
    Stream,
    Buffer,
}
