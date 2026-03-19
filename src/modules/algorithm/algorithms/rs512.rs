use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::models::rs_algorithm::rs_private::RSPrivate;
use crate::algorithm::models::rs_algorithm::rs_public::RSPublic;

// Private
impl JwAlg for RSPrivate<sha2::Sha512> {
    fn alg() -> impl AsRef<str> {
        "RS512"
    }
}

impl PartialJwAlg for RSPrivate<sha2::Sha512> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}

// Public
impl JwAlg for RSPublic<sha2::Sha512> {
    fn alg() -> impl AsRef<str> {
        "RS512"
    }
}

impl PartialJwAlg for RSPublic<sha2::Sha512> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}