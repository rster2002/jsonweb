use crate::algorithm::JwAlgVerify;
use crate::algorithm::es::{ESError, ESPublicParams};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use digest::typenum::Unsigned;
use ecdsa::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use ecdsa::elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, sec1};
use ecdsa::signature::Verifier;
use ecdsa::{EcdsaCurve, Sec1Point, Signature, VerifyingKey};
use ecdsa::elliptic_curve::array::Array;
use crate::modules::key::{JwkPublicParams, JwkType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ESPublic<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    pub(crate) verifying_key: VerifyingKey<C>,
}

impl<C> ESPublic<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    pub(crate) fn from_public_parameters(
        parameters: ESPublicParams,
        crv: &'static str,
    ) -> Result<Self, ESError> {
        if crv != parameters.crv {
            return Err(ESError::MismatchedCurve(parameters.crv, crv));
        }

        let expected_size = <C::FieldBytesSize as Unsigned>::USIZE;

        let x = BASE64_URL_SAFE_NO_PAD
            .decode(parameters.x)
            .map_err(|e| ESError::FailedToDecodeBase64X(e))?;

        if x.len() != expected_size {
            return Err(ESError::InvalidXSize(expected_size));
        }

        let y = BASE64_URL_SAFE_NO_PAD
            .decode(parameters.y)
            .map_err(|e| ESError::FailedToDecodeBase64Y(e))?;

        if y.len() != expected_size {
            return Err(ESError::InvalidYSize(expected_size));
        }

        let x_array = Array::try_from(x).map_err(|_| ESError::FailedToConvertXToArray)?;
        let y_array = Array::try_from(y).map_err(|_| ESError::FailedToConvertXToArray)?;

        let sec1_point = Sec1Point::<C>::from_affine_coordinates(
            &x_array,
            &y_array,
            false,
        );

        let verifying_key = VerifyingKey::from_sec1_point(&sec1_point)
            .map_err(|_| ESError::FailedToCreateVerifyingKey)?;

        Ok(ESPublic {
            verifying_key,
        })
    }

    pub(crate) fn into_public_parameters(
        verifying_key: &VerifyingKey<C>,
        crv: impl Into<String>,
    ) -> Result<ESPublicParams, ESError> {
        let sec1_point = verifying_key.to_sec1_point(false);
        let x = sec1_point.x().ok_or(ESError::MissingSec1X)?;
        let y = sec1_point.y().ok_or(ESError::MissingSec1Y)?;

        Ok(ESPublicParams {
            crv: crv.into(),
            x: BASE64_URL_SAFE_NO_PAD.encode(x),
            y: BASE64_URL_SAFE_NO_PAD.encode(y),
        })
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
