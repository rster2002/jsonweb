use crate::modules::params::ec::{ECParamsError, ECPublicParams};
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
    /// Create ECPrivateParams from a SecretKey.
    pub fn from_secret_key<C>(secret_key: &SecretKey<C>, crv: impl Into<String>) -> Result<Self, ECParamsError>
    where C : Curve + CurveArithmetic,
          AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
          FieldBytesSize<C>: ModulusSize,
    {
        let public_params = ECPublicParams::from_public_key::<C>(&secret_key.public_key(), crv)?;

        let d = secret_key.to_bytes();

        Ok(ECPrivateParams {
            crv: public_params.crv,
            x: public_params.x,
            y: public_params.y,
            d: BASE64_URL_SAFE_NO_PAD.encode(d),
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
