use std::convert::Infallible;
use crate::algorithm::{JwAlgVerify, JwAlgSign};

#[derive(Clone, Debug)]
pub struct NoneAlgorithm;

impl JwAlgVerify for NoneAlgorithm {
    type Error = Infallible;

    fn verify(&self, _: &str, _: &[u8]) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

impl JwAlgSign for NoneAlgorithm {
    fn sign(&self, _: &str) -> Vec<u8> {
        vec![]
    }
}
