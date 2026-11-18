use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrivateEnumError {
    #[error("Failed to sign using set")]
    FailedToSign,
    
    #[error("Failed to verify using set")]
    FailedToVerify,

    #[error("Failed to parse")]
    FailedToParse(String),
}