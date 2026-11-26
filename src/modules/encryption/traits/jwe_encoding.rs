pub trait JweEncoding {
    type Error: std::error::Error;

    const ENC: &'static str;
    const CEK_LENGTH: usize;

    fn encrypt(&self, cek: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}