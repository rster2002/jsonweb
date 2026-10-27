use crate::algorithm::JwAlgVerify;
use crate::algorithm::traits::jw_alg::JwAlg;

pub trait JwAlgSign: JwAlgVerify {
    fn sign(&self, payload: &[u8]) -> Vec<u8>;
}