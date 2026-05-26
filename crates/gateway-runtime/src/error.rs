use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
