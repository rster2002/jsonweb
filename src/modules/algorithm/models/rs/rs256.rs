use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::models::rs::rs_private::RSPrivate;
use crate::algorithm::models::rs::rs_public::RSPublic;

// Private
pub type RS256Private = RSPrivate<sha2::Sha256>;

impl JwAlg for RS256Private {
    fn alg() -> impl AsRef<str> {
        "RS256"
    }
}

impl PartialJwAlg for RS256Private {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}

// Public
pub type RS256Public = RSPublic<sha2::Sha256>;

impl JwAlg for RS256Public {
    fn alg() -> impl AsRef<str> {
        "RS256"
    }
}

impl PartialJwAlg for RS256Public {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}