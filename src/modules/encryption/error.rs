use thiserror::Error;

#[derive(Debug, Error)]
pub enum JweError {
    #[error("Invalid CEK length")]
    InvalidCekLength,
}