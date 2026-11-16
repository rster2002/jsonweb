#[derive(Debug, thiserror::Error)]
pub enum PublicSetError {
    #[error("Failed to verify")]
    FailedToVerify,

    #[error("Failed to parse")]
    FailedToParse(String),
}