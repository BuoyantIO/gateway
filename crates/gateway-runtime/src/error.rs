use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub(crate) enum ProxyError {
    #[error("bind not in store")]
    BindGone,
    #[error("bind has no active listener")]
    NoListener,
    #[error("route has no backend refs")]
    NoBackend,
    #[error("backend has no endpoints")]
    NoEndpoint,
    #[error("no viable endpoint (all evicted)")]
    NoViableEndpoint,
}
