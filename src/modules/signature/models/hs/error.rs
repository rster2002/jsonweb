use thiserror::Error;

#[derive(Debug, Error)]
pub enum HSError {
    #[error("Key length is invalid")]
    InvalidLength,

    #[error("Failed to base64 decode `k` parameter: {0}")]
    FailedToBase64DecodeK(#[source] base64::DecodeError),
}