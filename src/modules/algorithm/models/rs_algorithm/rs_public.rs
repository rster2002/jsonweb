use p384::ecdsa::signature::digest::Digest;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use crate::algorithm::{JwAlg, JwAlgVerify};
use crate::algorithm::traits::partial_jw_alg::PartialJwAlg;

#[derive(Clone)]
pub struct RSPublic<D>(VerifyingKey<D>)
where D : Digest;

#[cfg(feature = "rs256")]
impl JwAlg for RSPublic<sha2::Sha256> {
    fn alg() -> impl AsRef<str> {
        "RS256"
    }
}

impl PartialJwAlg for RSPublic<sha2::Sha256> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}

#[cfg(feature = "rs384")]
impl JwAlg for RSPublic<sha2::Sha384> {
    fn alg() -> impl AsRef<str> {
        "RS384"
    }
}

#[cfg(feature = "rs384")]
impl PartialJwAlg for RSPublic<sha2::Sha384> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}

#[cfg(feature = "rs512")]
impl JwAlg for RSPublic<sha2::Sha512> {
    fn alg() -> impl AsRef<str> {
        "RS512"
    }
}

#[cfg(feature = "rs512")]
impl PartialJwAlg for RSPublic<sha2::Sha512> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
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
