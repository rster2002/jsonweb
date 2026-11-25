pub trait JweEncryption {
    type Error: std::error::Error;

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}