use crate::algorithm::JwAlgVerify;

pub trait JwAlgSign: JwAlgVerify {
    type Error: std::error::Error;

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, <Self as JwAlgSign>::Error>;
}