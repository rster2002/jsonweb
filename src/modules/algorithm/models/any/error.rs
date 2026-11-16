use thiserror::Error;

#[derive(Debug, Error)]
pub enum AnyError {
    #[error("Failed to verify signature: {0}")]
    FailedToVerify(String),
}