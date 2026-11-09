/// Verify a given signature against a payload using this algorithm.
pub trait JwAlgVerify {
    type Error: std::error::Error;

    /// Verify the given `payload` against the given `signature` using this algorithm.
    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Self::Error>;
}
