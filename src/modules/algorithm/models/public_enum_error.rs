#[derive(Debug, thiserror::Error)]
pub enum PublicEnumError {
    #[error("Failed to verify")]
    FailedToVerify,

    #[error("Failed to parse")]
    FailedToParse(String),
}