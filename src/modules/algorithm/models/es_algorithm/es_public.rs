use ecdsa::{PrimeCurve, Signature, SignatureSize, VerifyingKey};
use ecdsa::elliptic_curve::{AffinePoint, CurveArithmetic};
use crate::algorithm::{JwAlg, JwAlgVerify};
use ecdsa::elliptic_curve::generic_array::ArrayLength;
use ecdsa::hazmat::{DigestPrimitive, VerifyPrimitive};
use ecdsa::signature::Verifier;

pub struct ESPublic<C>(VerifyingKey<C>)
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    AffinePoint<C>: VerifyPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>;

#[cfg(feature = "es256")]
impl JwAlg for ESPublic<p256::NistP256> {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

#[cfg(feature = "es384")]
impl JwAlg for ESPublic<p384::NistP384> {
    fn alg() -> impl AsRef<str> {
        "ES384"
    }
}

impl<C> JwAlgVerify for ESPublic<C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    AffinePoint<C>: VerifyPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Error = ecdsa::Error;

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let signature = Signature::<C>::try_from(signature).unwrap(); // TODO return false

        Ok(self.0.verify(payload.as_bytes(), &signature).is_ok())
    }
}
