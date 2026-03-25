use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::models::rs::rs_private::RSPrivate;
use crate::algorithm::models::rs::rs_public::RSPublic;

// Private
pub type RS512Private = RSPrivate<sha2::Sha512>;

impl JwAlg for RS512Private {
    fn alg() -> impl AsRef<str> {
        "RS512"
    }
}

impl PartialJwAlg for RS512Private {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}

// Public
pub type RS512Public = RSPublic<sha2::Sha512>;

impl JwAlg for RS512Public {
    fn alg() -> impl AsRef<str> {
        "RS512"
    }
}

impl PartialJwAlg for RS512Public {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}