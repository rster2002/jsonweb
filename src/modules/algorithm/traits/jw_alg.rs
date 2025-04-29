pub trait JwAlg {
    type Error: std::error::Error;

    fn alg() -> impl AsRef<str>;
    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error>;
}
