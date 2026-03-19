use sha2::Sha256;
use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::models::hs_algorithm::HSPrivate;

impl JwAlg for HSPrivate<Sha256> {
    fn alg() -> impl AsRef<str> {
        "HS256"
    }
}

impl PartialJwAlg for HSPrivate<Sha256> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}