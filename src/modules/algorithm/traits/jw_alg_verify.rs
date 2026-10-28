use crate::algorithm::JwAlg;

pub trait JwAlgVerify {
    type Error: std::error::Error;

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Self::Error>;
}
