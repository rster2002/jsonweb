use p384::ecdsa::signature::digest::Digest;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use crate::algorithm::{JwAlg, JwAlgVerify};

pub struct RSPublic<D>(VerifyingKey<D>)
where D : Digest;

#[cfg(feature = "rs256")]
impl JwAlg for RSPublic<sha2::Sha256> {
    fn alg() -> impl AsRef<str> {
        "RS256"
    }
}

#[cfg(feature = "rs384")]
impl JwAlg for RSPublic<sha2::Sha384> {
    fn alg() -> impl AsRef<str> {
        "RS384"
    }
}

#[cfg(feature = "rs512")]
impl JwAlg for RSPublic<sha2::Sha512> {
    fn alg() -> impl AsRef<str> {
        "RS512"
    }
}

impl<D> JwAlgVerify for RSPublic<D>
where D : Digest
{
    type Error = rsa::signature::Error;

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let signature = Signature::try_from(signature)?;
        Ok(self.0.verify(payload.as_bytes(), &signature).is_ok())
    }
}
