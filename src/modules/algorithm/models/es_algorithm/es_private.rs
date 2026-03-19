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
use ecdsa::elliptic_curve::FieldBytes;
use crate::algorithm::traits::partial_jw_alg::PartialJwAlg;
use crate::modules::key::{JwkPrivateParams, JwkType};

#[derive(Clone)]
pub struct ESPrivate<C>(pub SigningKey<C>)
where C: PrimeCurve + CurveArithmetic + DigestPrimitive,
      Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
      AffinePoint<C>: VerifyPrimitive<C>,
      SignatureSize<C>: ArrayLength<u8>;

impl<C> ESPrivate<C>
where C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    AffinePoint<C>: VerifyPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    #[cfg(feature = "rand")]
    pub fn rand() -> Self {
        let mut rng = rand::thread_rng();
        ESPrivate::from(SigningKey::random(&mut rng))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ecdsa::Error> {
        let field_bytes = FieldBytes::<C>::from_slice(bytes);
        Ok(ESPrivate::from(SigningKey::from_bytes(field_bytes)?))
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

impl<C> JwkType for ESPrivate<C>
where C: PrimeCurve + CurveArithmetic + DigestPrimitive,
      Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
      AffinePoint<C>: VerifyPrimitive<C>,
      SignatureSize<C>: ArrayLength<u8>,
{
    fn kty() -> impl AsRef<str> {
        "EC"
    }
}

impl<C> From<SigningKey<C>> for ESPrivate<C>
where C: PrimeCurve + CurveArithmetic + DigestPrimitive,
      Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
      AffinePoint<C>: VerifyPrimitive<C>,
      SignatureSize<C>: ArrayLength<u8>
{
    fn from(key: SigningKey<C>) -> Self {
        ESPrivate(key)
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::ES256Private;

    #[test]
    fn es256_can_be_generated_randomly() {
        ES256Private::rand();
    }

    #[test]
    fn es256_to_and_from_bytes() {
        let alg = ES256Private::rand();
        let bytes = alg.to_bytes();

        let alg2 = ES256Private::from_bytes(&bytes).unwrap();
        assert_eq!(alg.0, alg2.0);
    }
}
