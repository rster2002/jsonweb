use std::convert::Infallible;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ecdsa::elliptic_curve::{sec1, AffinePoint, CurveArithmetic, FieldBytesSize, PrimeCurve, Scalar};
use ecdsa::elliptic_curve::ops::Invert;
use ecdsa::elliptic_curve::subtle::CtOption;
use ecdsa::{EcdsaCurve, Signature, SignatureSize, SigningKey};
use ecdsa::signature::{Signer, Verifier};
use crate::algorithm::{JwAlgSign, JwAlgVerify};
use crate::algorithm::traits::jw_alg::JwAlg;
use ecdsa::elliptic_curve::FieldBytes;
use ecdsa::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use crate::algorithm::es::{ESError, ESPrivateParams};
use crate::algorithm::traits::partial_jw_alg::PartialJwAlg;
use crate::modules::key::{JwkPrivateParams, JwkType};

#[derive(Debug, Clone)]
pub struct ESPrivate<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    pub(crate) signing_key: SigningKey<C>,
}

impl<C> ESPrivate<C>
where C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
      AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
      FieldBytesSize<C>: sec1::ModulusSize,
{
    /// Returns an incomplete ESPrivateParams struct where the `crv` field is empty.
    pub(crate) fn private_parameters(&self, crv: impl Into<String>) -> Result<ESPrivateParams, ESError> {
        let verifying_key = self.signing_key.verifying_key();
        let sec1_point = verifying_key.to_sec1_point(false);
        let x = sec1_point.x()
            .ok_or(ESError::MissingSec1X)?;

        let y = sec1_point.y()
            .ok_or(ESError::MissingSec1Y)?;

        // TODO check: Missing "The length of this octet string
        //    MUST be ceiling(log-base-2(n)/8) octets (where n is the order of the
        //    curve)."

        let d = self.signing_key.to_bytes();

        Ok(ESPrivateParams {
            crv: crv.into(),
            x: BASE64_URL_SAFE_NO_PAD.encode(x),
            y: BASE64_URL_SAFE_NO_PAD.encode(y),
            d: BASE64_URL_SAFE_NO_PAD.encode(d),
        })
    }
}

impl<C> JwAlgVerify for ESPrivate<C>
where
    C: CurveArithmetic + EcdsaCurve + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Error = ESError;

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        todo!()
    }
}

impl<C> JwAlgSign for ESPrivate<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Error = Infallible;

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, <Self as JwAlgSign>::Error> {
        let signature: Signature<C> = Signer::sign(&self.signing_key, payload);
        Ok(signature.to_vec())
    }
}

// impl<C> ESPrivate<C>
// where
//     C: EcdsaCurve + CurveArithmetic,
// {
//     // #[cfg(feature = "rand")]
//     // pub fn rand() -> Self {
//     //     let mut rng = rand::thread_rng();
//     //     ESPrivate::from(SigningKey::random(&mut rng))
//     // }
//
//     // pub fn to_bytes(&self) -> Vec<u8> {
//     //     self.0.to_bytes().to_vec()
//     // }
//     //
//     // pub fn from_bytes(bytes: &[u8]) -> Result<Self, ecdsa::Error> {
//     //     let field_bytes = FieldBytes::<C>::from_slice(bytes);
//     //     Ok(ESPrivate::from(SigningKey::from_bytes(field_bytes)?))
//     // }
// }

// impl<C> JwAlgVerify for SigningKey<C>
// where
//     C: EcdsaCurve + CurveArithmetic,
// {
//     type Error = Infallible;
//
//     fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
//         let verifying_key = self.verifying_key();
//         let signature = match Signature::<C>::try_from(signature) {
//             Ok(sig) => sig,
//             Err(_) => return Ok(false),
//         };
//
//         Ok(verifying_key.verify(payload, &signature).is_ok())
//     }
// }

// impl<C> JwAlgSign for SigningKey<C>
// where
//     C: EcdsaCurve + CurveArithmetic,
// {
//     type Error = Infallible;
//
//     fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Infallible> {
//         let signature: Signature<C> = Signer::sign(self, payload);
//         Ok(signature.to_vec())
//     }
// }

impl<C> JwkType for ESPrivate<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn kty() -> impl AsRef<str> {
        "EC"
    }
}

impl<C> From<SigningKey<C>> for ESPrivate<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    fn from(key: SigningKey<C>) -> Self {
        ESPrivate {
            signing_key: key,
        }
    }
}

#[cfg(test)]
mod tests {


    // #[test]
    // #[cfg(feature = "rand")]
    // fn es256_can_be_generated_randomly() {
    //     ES256Private::rand();
    // }
    //
    // #[test]
    // #[cfg(feature = "rand")]
    // fn es256_to_and_from_bytes() {
    //     let alg = ES256Private::rand();
    //     let bytes = alg.to_bytes();
    //
    //     let alg2 = ES256Private::from_bytes(&bytes).unwrap();
    //     assert_eq!(alg.0, alg2.0);
    // }
}
