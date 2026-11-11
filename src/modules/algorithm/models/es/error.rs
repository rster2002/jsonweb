use thiserror::Error;

#[derive(Debug, Error)]
pub enum ESError {
    #[error("Missing Sec1 `x`")]
    MissingSec1X,

    #[error("Missing Sec1 `y`")]
    MissingSec1Y,
    
    #[error("Failed to represent `d`")]
    FailedToRepresentD,
    
    #[error("Mismatched curve: got {0}, expected {1}")]
    MismatchedCurve(String, &'static str),
}