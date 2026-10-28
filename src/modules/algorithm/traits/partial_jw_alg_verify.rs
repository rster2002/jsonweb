use crate::algorithm::{JwAlg, JwAlgVerify};

pub trait PartialJwAlgVerify {
    type Error: std::error::Error;

    fn partial_verify(&self, alg: &str, payload: &[u8], signature: &[u8]) -> Option<Result<bool, Self::Error>>;
}

impl<T, E> PartialJwAlgVerify for T
where T : JwAlg + JwAlgVerify<Error = E>,
    E : std::error::Error,
{
    type Error = E;

    fn partial_verify(&self, alg: &str, payload: &[u8], signature: &[u8]) -> Option<Result<bool, Self::Error>> {
        if alg != T::alg().as_ref() {
            return None;
        }
        
        Some(self.verify(payload, signature))
    }
}