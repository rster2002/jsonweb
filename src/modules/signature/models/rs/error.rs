use thiserror::Error;
use crate::modules::params::rsa::RSAParamsError;

#[derive(Debug, Error)]
pub enum RSError {
    #[error(transparent)]
    RSAParamsError(#[from] RSAParamsError),

    #[error("Failed to sign: {0}")]
    FailedToSign(#[source] rsa::Error),

    #[error("Failed to verify: {0}")]
    FailedToVerify(#[source] rsa::Error),
}