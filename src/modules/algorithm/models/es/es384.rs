use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::models::es::es_private::ESPrivate;
use crate::algorithm::models::es::es_public::ESPublic;

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