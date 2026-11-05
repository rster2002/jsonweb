use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub enum JwkError {
    SerdeJson(#[from] serde_json::Error),

    #[error("Missing algorithm")]
    MissingAlgorithm,

    #[error("Mismatched algorithm")]
    MismatchedAlgorithm,
    
    // TODO remove
    #[error("Failed")]
    Failed,
}