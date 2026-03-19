use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::models::es_algorithm::es_private::ESPrivate;
use crate::algorithm::models::es_algorithm::es_public::ESPublic;

// Private
impl JwAlg for ESPrivate<p384::NistP384> {
    fn alg() -> impl AsRef<str> {
        "ES384"
    }
}

impl PartialJwAlg for ESPrivate<p384::NistP384> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}

// Public

impl JwAlg for ESPublic<p384::NistP384> {
    fn alg() -> impl AsRef<str> {
        "ES384"
    }
}

impl PartialJwAlg for ESPublic<p384::NistP384> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}