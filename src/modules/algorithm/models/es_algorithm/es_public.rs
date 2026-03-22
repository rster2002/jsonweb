use ecdsa::{PrimeCurve, Signature, SignatureSize, VerifyingKey};
use ecdsa::elliptic_curve::{AffinePoint, CurveArithmetic};
use crate::algorithm::{JwAlg, JwAlgVerify};
use ecdsa::elliptic_curve::generic_array::ArrayLength;
use ecdsa::hazmat::{DigestPrimitive, VerifyPrimitive};
use ecdsa::signature::Verifier;
use crate::algorithm::traits::partial_jw_alg::PartialJwAlg;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ESPublic<C>(pub(crate) VerifyingKey<C>)
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    AffinePoint<C>: VerifyPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>;

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
