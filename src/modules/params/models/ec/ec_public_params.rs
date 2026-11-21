use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use digest::array::Array;
use digest::typenum::Unsigned;
use elliptic_curve::{AffinePoint, Curve, CurveArithmetic, FieldBytesSize, PublicKey};
use elliptic_curve::sec1::{FromSec1Point, ModulusSize, Sec1Point, ToSec1Point};
use serde::{Deserialize, Serialize};
use crate::modules::params::ec::{ECParamsError, ECPrivateParams};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECPublicParams {
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl ECPublicParams {
    /// Create a new ECPublicParams from a public key.
    pub fn from_public_key<C>(public_key: &PublicKey<C>, crv: impl Into<String>) -> Result<Self, ECParamsError>
    where C : Curve + CurveArithmetic,
          AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
          FieldBytesSize<C>: ModulusSize,
    {
        Self::from_sec1_point::<C>(&public_key.to_sec1_point(false), crv)
    }

    /// Create a new ECPublicParams from a Sec1 Point.
    pub fn from_sec1_point<C>(sec1_point: &Sec1Point<C>, crv: impl Into<String>) -> Result<Self, ECParamsError>
    where C : Curve + CurveArithmetic,
          FieldBytesSize<C>: ModulusSize,
    {
        let x = sec1_point.x().ok_or(ECParamsError::MissingSec1X)?;
        let y = sec1_point.y().ok_or(ECParamsError::MissingSec1Y)?;

        Ok(ECPublicParams {
            crv: crv.into(),
            x: BASE64_URL_SAFE_NO_PAD.encode(x),
            y: BASE64_URL_SAFE_NO_PAD.encode(y),
        })
    }

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
}

// impl<C, S> TryFrom<(&PublicKey<C>, S)> for ECPublicParams
// where C : Curve + CurveArithmetic,
//       AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
//       FieldBytesSize<C>: ModulusSize,
//     S: Into<String>
// {
//     type Error = ECParamsError;
//
//     fn try_from((key, crv): (&PublicKey<C>, S)) -> Result<Self, Self::Error> {
//         let sec1_point = key.to_sec1_point(false);
//         let x = sec1_point.x().ok_or(ECParamsError::MissingSec1X)?;
//         let y = sec1_point.y().ok_or(ECParamsError::MissingSec1Y)?;
//
//         Ok(ECPublicParams {
//             crv: crv.into(),
//             x: BASE64_URL_SAFE_NO_PAD.encode(x),
//             y: BASE64_URL_SAFE_NO_PAD.encode(y),
//         })
//     }
// }

impl From<ECPrivateParams> for ECPublicParams {
    fn from(value: ECPrivateParams) -> Self {
        ECPublicParams {
            crv: value.crv,
            x: value.x,
            y: value.y,
        }
    }
}