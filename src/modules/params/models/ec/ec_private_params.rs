use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use digest::typenum::Unsigned;
use ecdsa::{EcdsaCurve, SigningKey};
use ecdsa::elliptic_curve::{sec1, AffinePoint, CurveArithmetic, FieldBytesSize, FieldBytes};
use ecdsa::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use serde::{Deserialize, Serialize};
use crate::modules::params::ec::error::ECParamsError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECPrivateParams {
    pub crv: String,
    pub x: String,
    pub y: String,
    pub d: String,
}

impl ECPrivateParams {
    // TODO not happy with this actually...
    /// Attempt to turn the parameters into a signing key and ensure that the curve matches the
    /// expected curve. Prefer using this function over using `TryFrom` directly or ensure that
    /// you handle mismatched `crv` values yourself.
    pub fn try_into_key_crv<C>(params: ECPrivateParams, expected_crv: &str) -> Result<SigningKey<C>, ECParamsError>
    where
        C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
        AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
        FieldBytesSize<C>: sec1::ModulusSize,
    {
        if expected_crv != params.crv {
            return Err(ECParamsError::MismatchedCurve(params.crv, expected_crv.to_string()));
        }

        Ok(params.try_into()?)
    }
}

impl<C> TryFrom<ECPrivateParams> for SigningKey<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    type Error = ECParamsError;

    fn try_from(params: ECPrivateParams) -> Result<Self, Self::Error> {
        let expected_size = <C::FieldBytesSize as Unsigned>::USIZE;

        let d = BASE64_URL_SAFE_NO_PAD
            .decode(params.d)
            .map_err(|e| ECParamsError::FailedToDecodeBase64D(e))?;

        if d.len() != expected_size {
            return Err(ECParamsError::InvalidDSize(expected_size));
        }

        let x = BASE64_URL_SAFE_NO_PAD
            .decode(params.x)
            .map_err(|e| ECParamsError::FailedToDecodeBase64X(e))?;

        if x.len() != expected_size {
            return Err(ECParamsError::InvalidXSize(expected_size));
        }

        let y = BASE64_URL_SAFE_NO_PAD
            .decode(params.y)
            .map_err(|e| ECParamsError::FailedToDecodeBase64Y(e))?;

        if y.len() != expected_size {
            return Err(ECParamsError::InvalidYSize(expected_size));
        }

        let field_bytes = FieldBytes::<C>::try_from(d)
            .map_err(|_| ECParamsError::FailedToRepresentD)?;

        let signing_key = SigningKey::from_bytes(&field_bytes)
            .map_err(|_| ECParamsError::FailedToRepresentD)?;

        let verifying_key = signing_key.verifying_key();

        let sec1_point = verifying_key.to_sec1_point(false);
        let p_x = sec1_point.x().ok_or(ECParamsError::MissingSec1X)?;
        let p_y = sec1_point.y().ok_or(ECParamsError::MissingSec1Y)?;

        if p_x.as_ref() != x {
            return Err(ECParamsError::MismatchedX);
        }

        if p_y.as_ref() != y {
            return Err(ECParamsError::MismatchedY);
        }

        Ok(signing_key)
    }
}