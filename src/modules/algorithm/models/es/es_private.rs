use crate::algorithm::es::{ESError, ESPrivateParams, ESPublic};
use crate::algorithm::{JwAlgSign, JwAlgVerify};
use crate::modules::key::JwkType;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use ecdsa::elliptic_curve::FieldBytes;
use ecdsa::elliptic_curve::common::typenum::Unsigned;
use ecdsa::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};
use ecdsa::elliptic_curve::{
    AffinePoint, CurveArithmetic, FieldBytesSize, sec1,
};
use ecdsa::signature::{Signer, Verifier};
use ecdsa::{EcdsaCurve, Signature, SigningKey};
use std::convert::Infallible;

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
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    pub(crate) fn from_private_parameters(
        parameters: ESPrivateParams,
        crv: &'static str,
    ) -> Result<Self, ESError> {
        if crv != parameters.crv {
            return Err(ESError::MismatchedCurve(parameters.crv, crv));
        }

        let expected_size = <C::FieldBytesSize as Unsigned>::USIZE;

        let d = BASE64_URL_SAFE_NO_PAD
            .decode(parameters.d)
            .map_err(|e| ESError::FailedToDecodeBase64D(e))?;

        if d.len() != expected_size {
            return Err(ESError::InvalidDSize(expected_size));
        }

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

        let field_bytes = FieldBytes::<C>::try_from(d)
            .map_err(|_| ESError::FailedToRepresentD)?;

        let signing_key = SigningKey::from_bytes(&field_bytes)
            .map_err(|_| ESError::FailedToRepresentD)?;

        let verifying_key = signing_key.verifying_key();

        let sec1_point = verifying_key.to_sec1_point(false);
        let p_x = sec1_point.x().ok_or(ESError::MissingSec1X)?;
        let p_y = sec1_point.y().ok_or(ESError::MissingSec1Y)?;

        if p_x.as_ref() != x {
            return Err(ESError::MismatchedX);
        }

        if p_y.as_ref() != y {
            return Err(ESError::MismatchedY);
        }

        Ok(Self { signing_key })
    }

    pub(crate) fn into_private_parameters(
        signing_key: &SigningKey<C>,
        crv: impl Into<String>,
    ) -> Result<ESPrivateParams, ESError> {
        let public_params = ESPublic::into_public_parameters(signing_key.verifying_key(), crv)?;

        // TODO check: Missing "The length of this octet string
        //    MUST be ceiling(log-base-2(n)/8) octets (where n is the order of the
        //    curve)."

        let d = signing_key.to_bytes();

        Ok(ESPrivateParams {
            crv: public_params.crv,
            x: public_params.x,
            y: public_params.y,
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
        let verifying_key = self.signing_key.verifying_key();
        let signature = Signature::try_from(signature).map_err(|_| ESError::MalformedSignature)?;
        let verification = verifying_key.verify(payload, &signature);

        Ok(verification.is_ok())
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
        ESPrivate { signing_key: key }
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::es::{ES256Private, ESPrivateParams};
    use crate::algorithm::{JwAlgSign, JwAlgVerify};

    #[test]
    fn inner_from_params_works() {
        let a = ES256Private::from_private_parameters(
            ESPrivateParams {
                crv: "P-256".to_string(),
                x: "Q5PISQVZ7LMwDNrjCNUcPLR45-zArUIqVazbscbLZ5Y".to_string(),
                y: "cum17-MtTGX2X7yrI0tvp0Xl9NVEmHUuotAwyJHOv7I".to_string(),
                d: "3XAy6ko-fegKfkV5uE5nKY4wTncjvFMYTJM0uh4rj8E".to_string(),
            },
            "P-256",
        )
            .expect("To have been generated");

        let signature = a.sign(b"Hello world")
            .expect("infallible");

        let correct = a.verify(b"Hello world", &signature)
            .expect("To have been verified");

        assert!(correct);
    }

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
