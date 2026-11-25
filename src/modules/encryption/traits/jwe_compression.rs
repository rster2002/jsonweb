pub trait JweCompression {
    type Error: std::error::Error;

    const ZIP: &'static str;

    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}