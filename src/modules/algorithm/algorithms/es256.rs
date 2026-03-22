use base64::Engine;
use base64::prelude::BASE64_URL_SAFE;
use ecdsa::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use ecdsa::EncodedPoint;
use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::models::es_algorithm::es_curve::ESCurve;
use crate::algorithm::models::es_algorithm::es_private::ESPrivate;
use crate::algorithm::models::es_algorithm::es_private_params::EsPrivateParams;
use crate::algorithm::models::es_algorithm::es_public::ESPublic;
use crate::algorithm::models::es_algorithm::es_public_params::ESPublicParams;
use crate::modules::key::JwkPrivateParams;

// Private
impl JwAlg for ESPrivate<p256::NistP256> {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

impl PartialJwAlg for ESPrivate<p256::NistP256> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}

impl JwkPrivateParams<'_> for ESPrivate<p256::NistP256> {
    type PrivateParams = EsPrivateParams;

    fn get_private_params(&self) -> Option<Self::PrivateParams> {
        let verifying_key = self.0.verifying_key();
        let affine_point = verifying_key.as_affine();
        let encoded_point: EncodedPoint<p256::NistP256> = affine_point.clone().into(); // TODO remove clone
        let x = encoded_point.x()?;
        let y = encoded_point.y()?;

        let d_bytes = self.0.as_nonzero_scalar().to_bytes();

        Some(EsPrivateParams {
            crv: ESCurve::P256,
            x: BASE64_URL_SAFE.encode(&x),
            y: BASE64_URL_SAFE.encode(&y),
            d: BASE64_URL_SAFE.encode(&d_bytes),
        })
    }
}

// Public
impl JwAlg for ESPublic<p256::NistP256> {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

impl PartialJwAlg for ESPublic<p256::NistP256> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}

impl JwkPrivateParams<'_> for ESPublic<p256::NistP256> {
    type PrivateParams = ESPublicParams;

    fn get_private_params(&self) -> Option<Self::PrivateParams> {
        let affine_point = self.0.as_affine();
        let encoded_point: EncodedPoint<p256::NistP256> = affine_point.clone().into(); // TODO remove clone
        let x = encoded_point.x()?;
        let y = encoded_point.y()?;

        Some(ESPublicParams {
            crv: ESCurve::P256,
            x: BASE64_URL_SAFE.encode(&x),
            y: BASE64_URL_SAFE.encode(&y),
        })
    }
}