use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("unsupported protocol for {kind} `{name}`: only HTTP is supported")]
    UnsupportedProtocol { kind: &'static str, name: String },
}

#[derive(Debug, Default)]
pub struct ApplyReport {
    pub applied: usize,
    pub skipped: Vec<String>,
}
