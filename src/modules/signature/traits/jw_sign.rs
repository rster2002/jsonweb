use crate::modules::signature::JwVerify;

pub trait JwSign: JwVerify {
    type Error: std::error::Error;

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, <Self as JwSign>::Error>;
}