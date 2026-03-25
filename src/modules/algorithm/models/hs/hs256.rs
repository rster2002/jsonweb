use sha2::Sha256;
use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::hs::HSPrivate;

pub type HS256Private = HSPrivate<Sha256>;

impl JwAlg for HS256Private {
    fn alg() -> impl AsRef<str> {
        "HS256"
    }
}

impl PartialJwAlg for HS256Private {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}