use crate::algorithm::JwAlg;

pub trait JwAlgSign: JwAlg {
    fn sign(&self, payload: &str) -> Vec<u8>;
}