use thiserror::Error;

#[derive(Debug, Error)]
pub enum RSError {
    #[error("Failed to sign: {0}")]
    FailedToSign(#[source] rsa::Error),

    #[error("Failed to verify: {0}")]
    FailedToVerify(#[source] rsa::Error),

    #[error("Failed to base64 decode `n` parameter: {0}")]
    FailedToBase64DecodeN(#[source] base64::DecodeError),

    #[error("Failed to base64 decode `p` parameter: {0}")]
    FailedToBase64DecodeP(#[source] base64::DecodeError),

    #[error("Failed to base64 decode `q` parameter: {0}")]
    FailedToBase64DecodeQ(#[source] base64::DecodeError),

    #[error("Failed to base64 decode `e` parameter: {0}")]
    FailedToBase64DecodeE(#[source] base64::DecodeError),

    #[error("Failed to base64 decode `dp` parameter: {0}")]
    FailedToBase64DecodeDP(#[source] base64::DecodeError),

    #[error("Failed to base64 decode `dq` parameter: {0}")]
    FailedToBase64DecodeDQ(#[source] base64::DecodeError),

    #[error("Failed to base64 decode `qi` parameter: {0}")]
    FailedToBase64DecodeQI(#[source] base64::DecodeError),
    
    #[error("Failed to represent `n`")]
    FailedToRepresentN(#[source] rsa::Error),

    #[error("Failed to represent `p`")]
    FailedToRepresentP(#[source] rsa::Error),

    #[error("Failed to represent `q`")]
    FailedToRepresentQ(#[source] rsa::Error),

    #[error("Failed to represent `e`")]
    FailedToRepresentE(#[source] rsa::Error),

    #[error("Failed to represent `dp`")]
    FailedToRepresentDP(#[source] rsa::Error),

    #[error("Failed to represent `dq`")]
    FailedToRepresentDQ(#[source] rsa::Error),

    #[error("Failed to represent `qi`")]
    FailedToRepresentQI(#[source] rsa::Error),

    #[error("Failed to create private key from parameters: {0}")]
    FailedToCreatePrivateKeyFromParameters(#[source] rsa::Error),

    #[error("Failed to create public key from parameters: {0}")]
    FailedToCreatePublicKeyFromParameters(#[source] rsa::Error),
    
    #[error("Failed to precompute: {0}")]
    FailedToPrecompute(#[source] rsa::Error),

    #[error("Missing precompute")]
    MissingPrecompute,
    
    #[error("Mismatched `n`")]
    MismatchedN,
    
    #[error("Mismatched `dp`")]
    MismatchedDP,
    
    #[error("Mismatched `dq`")]
    MismatchedDQ,
    
    #[error("Mismatched `qi`")]
    MismatchedQI,
}