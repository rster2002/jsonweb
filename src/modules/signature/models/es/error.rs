use thiserror::Error;
use crate::modules::params::ec::ECParamsError;

#[derive(Debug, Error)]
pub enum ESError {
    #[error(transparent)]
    ECParamsError(#[from] ECParamsError),
    
    #[error("Malformed signature")]
    MalformedSignature,

    #[error("Failed to convert `x` to array")]
    FailedToConvertXToArray,

    #[error("Failed to convert `y` to array")]
    FailedToConvertYToArray,

    #[error("Failed to create verifying key")]
    FailedToCreateVerifyingKey,

    #[error("Mismatched curve: got {0}, expected {1}")]
    MismatchedCurve(String, String),
}