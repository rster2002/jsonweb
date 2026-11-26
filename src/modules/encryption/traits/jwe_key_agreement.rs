use crate::modules::encryption::random_cek;

pub trait JweKeyAgreement {
    type Error: std::error::Error;

    const JWE_ALG: &'static str;

    /// CEK to use for the encryption of the content. By default, returns a random CEK of the
    /// specified length, but can be overridden to use for key agreement strategies like Direct Key
    /// Agreement or Key Agreement with Key Wrapping.
    fn cek(&self, length: usize) -> Result<Vec<u8>, Self::Error> {
        Ok(random_cek(length))
    }
}