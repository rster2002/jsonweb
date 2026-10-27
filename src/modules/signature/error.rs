use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub enum JwsError {
    SerdeJson(#[from] serde_json::Error),
}