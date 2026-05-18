use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}
