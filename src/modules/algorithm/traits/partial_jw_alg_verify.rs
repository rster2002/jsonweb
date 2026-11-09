use crate::algorithm::{JwAlg, JwAlgVerify};

/// Trait for algorithms that can potentially verify a signature of the given `alg`.
pub trait PartialJwAlgVerify {
    type Error: std::error::Error;

    /// Returns `Some` result if the algorithm was handled by this algorithm, or `None` if it could
    /// not be processed.
    fn partial_verify(&self, alg: &str, payload: &[u8], signature: &[u8]) -> Option<Result<bool, Self::Error>>;
}

impl<T, E> PartialJwAlgVerify for T
where T : JwAlg + JwAlgVerify<Error = E>,
    E : std::error::Error,
{
    type Error = E;

    fn partial_verify(&self, alg: &str, payload: &[u8], signature: &[u8]) -> Option<Result<bool, Self::Error>> {
        if alg != T::alg().as_ref() {
            return None;
        }
        
        Some(self.verify(payload, signature))
    }
}