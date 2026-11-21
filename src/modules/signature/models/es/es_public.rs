use crate::algorithm::JwAlgVerify;
use crate::modules::key::JwkType;
use ecdsa::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use ecdsa::elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, sec1};
use ecdsa::signature::Verifier;
use ecdsa::{EcdsaCurve, Signature, VerifyingKey};
use elliptic_curve::PublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ESPublic<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    pub(crate) verifying_key: VerifyingKey<C>,
}

impl<C> From<PublicKey<C>> for ESPublic<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn from(value: PublicKey<C>) -> Self {
        let verifying_key = VerifyingKey::<C>::from(value);

        ESPublic::from(verifying_key)
    }
}

impl<C> From<VerifyingKey<C>> for ESPublic<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn from(value: VerifyingKey<C>) -> Self {
        ESPublic {
            verifying_key: value,
        }
    }
}

impl<C> JwkType for ESPublic<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn kty() -> impl AsRef<str> {
        "EC"
    }
}

impl<C> JwAlgVerify for ESPublic<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Error = ecdsa::Error;

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let signature = match Signature::<C>::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return Ok(false),
        };

        Ok(self.verifying_key.verify(payload, &signature).is_ok())
    }
}
