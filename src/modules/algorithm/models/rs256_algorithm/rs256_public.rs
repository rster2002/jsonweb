use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha2::Sha256;
use crate::algorithm::JwAlgVerify;

#[derive(Clone)]
pub struct RS256Public {
    inner: RsaPublicKey,
    verifying_key: VerifyingKey<Sha256>,
}

impl JwAlgVerify for RS256Public {
    type Error = rsa::signature::Error;

    fn alg() -> impl AsRef<str> {
        "RS256"
    }

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let signature = Signature::try_from(signature)?;
        Ok(self.verifying_key.verify(payload.as_bytes(), &signature).is_ok())
    }
}
