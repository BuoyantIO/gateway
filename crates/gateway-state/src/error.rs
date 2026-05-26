use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error(
        "unsupported protocol for {kind} `{name}`: only TCP and HTTP are supported in this slice"
    )]
    UnsupportedProtocol { kind: &'static str, name: String },

    #[error("listener `{listener}` does not match bind `{bind}`'s protocol family")]
    ListenerKindMismatch { bind: String, listener: String },
}

#[derive(Debug, Default)]
pub struct ApplyReport {
    pub applied: usize,
    pub skipped: Vec<String>,
}
