use std::convert::Infallible;
use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
use crate::algorithm::JwAlgVerify;

#[derive(Clone)]
pub struct ES256Public {
    inner: VerifyingKey,
}

impl JwAlgVerify for ES256Public {
    type Error = Infallible;

    fn alg() -> impl AsRef<str> {
        "ES256"
    }

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let signature = Signature::try_from(signature).unwrap();

        Ok(self.inner.verify(payload.as_bytes(), &signature).is_ok())
    }
}
