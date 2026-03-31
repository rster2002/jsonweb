use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub enum JwkError {
    SerdeJson(#[from] serde_json::Error)
}