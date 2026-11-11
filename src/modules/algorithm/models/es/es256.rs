use crate::algorithm::es::{ESError, ESPrivateParams, ESPublic};
use crate::algorithm::models::es::es_private::ESPrivate;
use crate::algorithm::JwAlg;
use crate::modules::key::JwkPrivateParams;

// Private
pub type ES256Private = ESPrivate<p256::NistP256>;

impl JwAlg for ES256Private {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

impl TryFrom<ESPrivateParams> for ES256Private {
    type Error = ESError;

    fn try_from(value: ESPrivateParams) -> Result<Self, Self::Error> {
        

        todo!()
    }
}

impl TryInto<ESPrivateParams> for ES256Private {
    type Error = ESError;

    fn try_into(self) -> Result<ESPrivateParams, Self::Error> {
        self.private_parameters("P-256")
    }
}

impl JwkPrivateParams for ES256Private {
    type PrivateParams = ESPrivateParams;
}

// impl JwkPrivateParams<'_> for ES256Private {
//     type PrivateParams = ESPrivateParams;
//
//     fn get_private_params(&self) -> Option<Self::PrivateParams> {
//         let verifying_key = self.0.verifying_key();
//         let affine_point = verifying_key.as_affine();
//         let encoded_point: EncodedPoint<p256::NistP256> = affine_point.clone().into(); // TODO remove clone
//         let x = encoded_point.x()?;
//         let y = encoded_point.y()?;
//
//         let d_bytes = self.0.as_nonzero_scalar().to_bytes();
//
//         Some(ESPrivateParams {
//             crv: ESCurve::P256,
//             x: BASE64_URL_SAFE_NO_PAD.encode(&x),
//             y: BASE64_URL_SAFE_NO_PAD.encode(&y),
//             d: BASE64_URL_SAFE_NO_PAD.encode(&d_bytes),
//         })
//     }
// }

// Public
pub type ES256Public = ESPublic<p256::NistP256>;

impl JwAlg for ES256Public {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

// impl JwkPublicParams<'_> for ES256Public {
//     type PublicParams = ESPublicParams;
//
//     fn get_public_params(&self) -> Option<Self::PublicParams> {
//         let affine_point = self.0.as_affine();
//         let encoded_point: EncodedPoint<p256::NistP256> = affine_point.clone().into(); // TODO remove clone
//         let x = encoded_point.x()?;
//         let y = encoded_point.y()?;
//
//         Some(ESPublicParams {
//             crv: ESCurve::P256,
//             x: BASE64_URL_SAFE_NO_PAD.encode(&x),
//             y: BASE64_URL_SAFE_NO_PAD.encode(&y),
//         })
//     }
// }

// impl From<ES256Private> for ES256Public {
//     fn from(value: ES256Private) -> Self {
//         Self(value.0.into())
//     }
// }
