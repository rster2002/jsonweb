use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::models::es_algorithm::es_curve::EsCurve;
use crate::algorithm::models::es_algorithm::es_private::ESPrivate;
use crate::algorithm::models::es_algorithm::es_private_params::EsPrivateParams;
use crate::algorithm::models::es_algorithm::es_public::ESPublic;
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

    fn get_private_params(&self) -> Self::PrivateParams {

        EsPrivateParams {
            crv: EsCurve::P256,
            x: "".to_string(),
            y: "".to_string(),
            d: "".to_string(),
        }
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