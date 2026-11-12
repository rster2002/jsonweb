use thiserror::Error;

#[derive(Debug, Error)]
pub enum ESError {
    #[error("Missing Sec1 `x`")]
    MissingSec1X,

    #[error("Missing Sec1 `y`")]
    MissingSec1Y,
    
    #[error("Failed to represent `d`")]
    FailedToRepresentD,

    #[error("Failed to decode base64 `d`: {0}")]
    FailedToDecodeBase64D(#[source] base64::DecodeError),

    #[error("Failed to decode base64 `x`: {0}")]
    FailedToDecodeBase64X(#[source] base64::DecodeError),

    #[error("Failed to decode base64 `y`: {0}")]
    FailedToDecodeBase64Y(#[source] base64::DecodeError),

    #[error("Expected size of `d` to be {0} bytes")]
    InvalidDSize(usize),

    #[error("Expected size of `x` to be {0} bytes")]
    InvalidXSize(usize),

    #[error("Expected size of `y` to be {0} bytes")]
    InvalidYSize(usize),
    
    #[error("Mismatched curve: got {0}, expected {1}")]
    MismatchedCurve(String, &'static str),

    #[error("Mismatched `x`")]
    MismatchedX,

    #[error("Mismatched `y`")]
    MismatchedY,

    #[error("Malformed signature")]
    MalformedSignature,

    #[error("Failed to convert `x` to array")]
    FailedToConvertXToArray,

    #[error("Failed to convert `y` to array")]
    FailedToConvertYToArray,

    #[error("Failed to create verifying key")]
    FailedToCreateVerifyingKey,
}