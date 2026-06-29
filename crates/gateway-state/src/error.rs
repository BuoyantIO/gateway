use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("unsupported protocol for {kind} `{name}`")]
    UnsupportedProtocol { kind: &'static str, name: String },

    #[error("unsupported TLS config for listener `{name}`: {reason}")]
    UnsupportedTls { name: String, reason: &'static str },
}

#[derive(Debug, Default)]
pub struct ApplyReport {
    pub applied: usize,
    pub skipped: Vec<String>,
}
