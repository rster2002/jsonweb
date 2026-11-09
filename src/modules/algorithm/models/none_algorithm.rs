use std::convert::Infallible;
use crate::algorithm::{JwAlgVerify, JwAlgSign};

#[derive(Clone, Debug)]
pub struct NoneAlgorithm;

impl JwAlgVerify for NoneAlgorithm {
    type Error = Infallible;

    fn verify(&self, _: &[u8], _: &[u8]) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

impl JwAlgSign for NoneAlgorithm {
    type Error = Infallible;

    fn sign(&self, _: &[u8]) -> Result<Vec<u8>, Infallible> {
        Ok(vec![])
    }
}
