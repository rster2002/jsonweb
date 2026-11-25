pub trait JweDecryption {
    type Error: std::error::Error;

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}