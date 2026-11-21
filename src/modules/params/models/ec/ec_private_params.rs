use crate::modules::params::ec::error::ECParamsError;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use digest::typenum::Unsigned;
use elliptic_curve::array::Array;
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, Sec1Point, ToSec1Point};
use elliptic_curve::{AffinePoint, Curve, CurveArithmetic, FieldBytesSize, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};

#[derive(Clone, Serialize, Deserialize)]
pub struct ECPrivateParams {
    pub crv: String,
    pub x: String,
    pub y: String,
    pub d: String,
}

impl ECPrivateParams {
    /// Return the public Sec1 Point for these params.
    pub fn sec1_point<C>(&self) -> Result<Sec1Point<C>, ECParamsError>
    where C : Curve + CurveArithmetic,
          AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
          FieldBytesSize<C>: ModulusSize,
    {
        let expected_size = <C::FieldBytesSize as Unsigned>::USIZE;

        let x = BASE64_URL_SAFE_NO_PAD
            .decode(&self.x)
            .map_err(|e| ECParamsError::FailedToDecodeBase64X(e))?;

        if x.len() != expected_size {
            return Err(ECParamsError::InvalidXSize(expected_size));
        }

        let y = BASE64_URL_SAFE_NO_PAD
            .decode(&self.y)
            .map_err(|e| ECParamsError::FailedToDecodeBase64Y(e))?;

        if y.len() != expected_size {
            return Err(ECParamsError::InvalidYSize(expected_size));
        }

        let x_a = Array::try_from(x)
            .map_err(|_| ECParamsError::InvalidXSize(expected_size))?;

        let y_a = Array::try_from(y)
            .map_err(|_| ECParamsError::InvalidXSize(expected_size))?;

        let sec1_point = Sec1Point::<C>::from_affine_coordinates(
            &x_a,
            &y_a,
            false,
        );

        Ok(sec1_point)
    }

    /// Return the public key for these params.
    pub fn public_key<C>(&self) -> Result<PublicKey<C>, ECParamsError>
    where C : Curve + CurveArithmetic,
          AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
          FieldBytesSize<C>: ModulusSize,
    {
        let sec1_point = self.sec1_point::<C>()?;
        let public_key = PublicKey::<C>::from_sec1_point(&sec1_point);

        if public_key.is_none().into() {
            return Err(ECParamsError::Todo);
        }

        Ok(public_key.unwrap())
    }

    /// Returns the private key for these params and ensure it matches with the public components.
    pub fn secret_key<C>(&self) -> Result<SecretKey<C>, ECParamsError>
    where C : Curve + CurveArithmetic,
          AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
          FieldBytesSize<C>: ModulusSize,
    {
        let expected_size = <C::FieldBytesSize as Unsigned>::USIZE;

        let d = BASE64_URL_SAFE_NO_PAD
            .decode(&self.d)
            .map_err(|e| ECParamsError::FailedToDecodeBase64D(e))?;

        if d.len() != expected_size {
            return Err(ECParamsError::InvalidDSize(expected_size));
        }

        let secret_key = SecretKey::<C>::from_slice(d.as_ref())
            .map_err(|_| ECParamsError::FailedToRepresentD)?;

        let sec1_point = secret_key.public_key().to_sec1_point(false);
        let expected_point = self.sec1_point::<C>()?;

        if sec1_point != expected_point {
            return Err(ECParamsError::Todo);
        }

        Ok(secret_key)
    }
}

impl Debug for ECPrivateParams {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ECPrivateParams {{ crv: {}, x: {:?}, y: {:?}, d: .. }}", self.crv, self.x, self.y)
    }
}

// impl ECPrivateParams {
//     // TODO not happy with this actually...
//     /// Attempt to turn the parameters into a signing key and ensure that the curve matches the
//     /// expected curve. Prefer using this function over using `TryFrom` directly or ensure that
//     /// you handle mismatched `crv` values yourself.
//     pub fn try_into_key_crv<C>(params: ECPrivateParams, expected_crv: &str) -> Result<SigningKey<C>, ECParamsError>
//     where
//         C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
//         AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
//         FieldBytesSize<C>: sec1::ModulusSize,
//     {
//         if expected_crv != params.crv {
//             return Err(ECParamsError::MismatchedCurve(params.crv, expected_crv.to_string()));
//         }
//
//         Ok(params.try_into()?)
//     },
// }

// impl<C> TryFrom<ECPrivateParams> for (Sec1Point<C>, FieldBytes<C>)
// where
//     C: Curve
// {
//     type Error = ECParamsError;
//
//     fn try_from(params: ECPrivateParams) -> Result<Self, Self::Error> {
//         let expected_size = <C::FieldBytesSize as Unsigned>::USIZE;
//
//         let d = BASE64_URL_SAFE_NO_PAD
//             .decode(params.d)
//             .map_err(|e| ECParamsError::FailedToDecodeBase64D(e))?;
//
//         if d.len() != expected_size {
//             return Err(ECParamsError::InvalidDSize(expected_size));
//         }
//
//         let x = BASE64_URL_SAFE_NO_PAD
//             .decode(params.x)
//             .map_err(|e| ECParamsError::FailedToDecodeBase64X(e))?;
//
//         if x.len() != expected_size {
//             return Err(ECParamsError::InvalidXSize(expected_size));
//         }
//
//         let y = BASE64_URL_SAFE_NO_PAD
//             .decode(params.y)
//             .map_err(|e| ECParamsError::FailedToDecodeBase64Y(e))?;
//
//         if y.len() != expected_size {
//             return Err(ECParamsError::InvalidYSize(expected_size));
//         }
//
//         let field_bytes = FieldBytes::<C>::try_from(d)
//             .map_err(|_| ECParamsError::FailedToRepresentD)?;
//
//         let signing_key = SigningKey::from_bytes(&field_bytes)
//             .map_err(|_| ECParamsError::FailedToRepresentD)?;
//
//         let verifying_key = signing_key.verifying_key();
//
//         let sec1_point = verifying_key.to_sec1_point(false);
//         let p_x = sec1_point.x().ok_or(ECParamsError::MissingSec1X)?;
//         let p_y = sec1_point.y().ok_or(ECParamsError::MissingSec1Y)?;
//
//         if p_x.as_ref() != x {
//             return Err(ECParamsError::MismatchedX);
//         }
//
//         if p_y.as_ref() != y {
//             return Err(ECParamsError::MismatchedY);
//         }
//
//         Ok(signing_key)
//     }
// }