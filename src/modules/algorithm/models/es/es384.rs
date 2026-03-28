use base64::Engine;
use base64::prelude::{BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD};
use ecdsa::EncodedPoint;
use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::es::{ES256Private, ES256Public, ESCurve, ESPrivateParams, ESPublicParams};
use crate::algorithm::models::es::es_private::ESPrivate;
use crate::algorithm::models::es::es_public::ESPublic;
use crate::modules::key::{JwkPrivateParams, JwkPublicParams};

// Private
pub type ES384Private = ESPrivate<p384::NistP384>;

impl JwAlg for ES384Private {
    fn alg() -> impl AsRef<str> {
        "ES384"
    }
}

impl PartialJwAlg for ESPrivate<p384::NistP384> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}

impl JwkPrivateParams<'_> for ES384Private {
    type PrivateParams = ESPrivateParams;

    fn get_private_params(&self) -> Option<Self::PrivateParams> {
        let verifying_key = self.0.verifying_key();
        let affine_point = verifying_key.as_affine();
        let encoded_point: EncodedPoint<p384::NistP384> = affine_point.clone().into(); // TODO remove clone
        let x = encoded_point.x()?;
        let y = encoded_point.y()?;

        let d_bytes = self.0.as_nonzero_scalar().to_bytes();

        Some(ESPrivateParams {
            crv: ESCurve::P384,
            x: BASE64_URL_SAFE.encode(&x),
            y: BASE64_URL_SAFE.encode(&y),
            d: BASE64_URL_SAFE.encode(&d_bytes),
        })
    }
}

// Public
pub type ES384Public = ESPublic<p384::NistP384>;

impl JwAlg for ES384Public {
    fn alg() -> impl AsRef<str> {
        "ES384"
    }
}

impl PartialJwAlg for ES384Public {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}

impl JwkPublicParams<'_> for ES384Public {
    type PublicParams = ESPublicParams;

    fn get_public_params(&self) -> Option<Self::PublicParams> {
        let affine_point = self.0.as_affine();
        let encoded_point: EncodedPoint<p384::NistP384> = affine_point.clone().into(); // TODO remove clone
        let x = encoded_point.x()?;
        let y = encoded_point.y()?;

        Some(ESPublicParams {
            crv: ESCurve::P384,
            x: BASE64_URL_SAFE_NO_PAD.encode(&x),
            y: BASE64_URL_SAFE_NO_PAD.encode(&y),
        })
    }
}

impl From<ES384Private> for ES384Public {
    fn from(value: ES384Private) -> Self {
        Self(value.0.into())
    }
}
