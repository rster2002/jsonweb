use p384::ecdsa::signature::digest::Digest;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use crate::algorithm::{JwAlgVerify};

#[derive(Clone)]
pub struct RSPublic<D>(VerifyingKey<D>)
where D : Digest;

impl<D> JwAlgVerify for RSPublic<D>
where D : Digest
{
    type Error = rsa::signature::Error;

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let signature = Signature::try_from(signature)?;
        Ok(self.0.verify(payload.as_bytes(), &signature).is_ok())
    }
}
