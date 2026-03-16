use std::convert::Infallible;
use ecdsa::elliptic_curve::{Curve, SecretKey};
use ecdsa::SigningKey;
use hmac::Mac;
use crate::algorithm::{JwAlgSign, JwAlgVerify};
use p256::NistP256;
use crate::algorithm::traits::jw_alg::JwAlg;

#[derive(Clone)]
pub struct ESPrivate<C>
where C : Curve,
{
    inner: SecretKey<C>,
    signing_key: SigningKey<C>,
}

impl JwAlg for ESPrivate<NistP256> {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

impl<C> JwAlgVerify for ESPrivate<C>
where C : Curve,
{
    type Error = Infallible;

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let verifying_key = self.signing_key.verifying_key();
        let signature = Signature::try_from(signature).unwrap();

        Ok(verifying_key.verify(payload.as_bytes(), &signature).is_ok())
    }
}

impl<C> JwAlgSign for ESPrivate<C>
where C : Curve,
{
    fn sign(&self, payload: &str) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(payload.as_bytes());
        signature.to_vec()
    }
}
