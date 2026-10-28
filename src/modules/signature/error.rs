use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub enum JwsError {
    SerdeJson(#[from] serde_json::Error),
    AlgError(Box<dyn std::error::Error>),

    #[error("No header found when verifying compact JWS")]
    NoHeader,

    #[error("Failed to decode JWS header: {0}")]
    DecodeBase64Header(#[source] base64::DecodeError),

    #[error("Failed to decode JWS header: {0}")]
    DecodeJsonHeader(#[source] serde_json::Error),

    #[error("JWS header does not contain an `alg` field")]
    NoAlg,
    
    #[error("Algorithm in JWS header does not match algorithm used to verify")]
    UnmatchedAlgorithm,

    #[error("JWS payload did not match signature")]
    InvalidSignature,

    #[error("No payload found when verifying compact JWS")]
    NoPayload,

    #[error("Failed to decode JWS payload: {0}")]
    DecodeBase64Payload(#[source] base64::DecodeError),
    
    #[error("No signature found when verifying compact JWS")]
    NoSignature,

    #[error("Failed to decode JWS signature: {0}")]
    DecodeBase64Signature(#[source] base64::DecodeError),
}