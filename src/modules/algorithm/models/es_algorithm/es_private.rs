use std::convert::Infallible;
use ecdsa::elliptic_curve::{AffinePoint, CurveArithmetic, PrimeCurve, Scalar};
use ecdsa::elliptic_curve::ops::Invert;
use ecdsa::elliptic_curve::subtle::CtOption;
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
use ecdsa::{Signature, SignatureSize, SigningKey};
use ecdsa::elliptic_curve::generic_array::ArrayLength;
use ecdsa::signature::{Signer, Verifier};
use crate::algorithm::{JwAlgSign, JwAlgVerify};
use crate::algorithm::traits::jw_alg::JwAlg;

pub struct ESPrivate<C>(SigningKey<C>)
where C: PrimeCurve + CurveArithmetic + DigestPrimitive,
      Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
      AffinePoint<C>: VerifyPrimitive<C>,
      SignatureSize<C>: ArrayLength<u8>;

#[cfg(feature = "es256")]
impl JwAlg for ESPrivate<p256::NistP256> {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

#[cfg(feature = "es384")]
impl JwAlg for ESPrivate<p384::NistP384> {
    fn alg() -> impl AsRef<str> {
        "ES384"
    }
}

impl<C> JwAlgVerify for SigningKey<C>
where C: PrimeCurve + CurveArithmetic + DigestPrimitive,
      Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
      AffinePoint<C>: VerifyPrimitive<C>,
      SignatureSize<C>: ArrayLength<u8>,
{
    type Error = Infallible;

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let verifying_key = self.verifying_key();
        let signature = Signature::<C>::try_from(signature).unwrap(); // TODO return false

        Ok(verifying_key.verify(payload.as_bytes(), &signature).is_ok())
    }
}

impl<C> JwAlgSign for SigningKey<C>
where C: PrimeCurve + CurveArithmetic + DigestPrimitive,
      Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
      AffinePoint<C>: VerifyPrimitive<C>,
      SignatureSize<C>: ArrayLength<u8>,
{
    fn sign(&self, payload: &str) -> Vec<u8> {
        let signature: Signature<C> = Signer::sign(self, payload.as_bytes());
        signature.to_vec()
    }
}