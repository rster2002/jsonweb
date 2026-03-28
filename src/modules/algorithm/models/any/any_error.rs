use thiserror::Error;

#[derive(Debug, Error)]
#[error(transparent)]
pub enum AnyError {
    #[cfg(any(feature = "es256", feature = "es384"))]
    Ecdsa(#[from] ecdsa::Error),
}