use crate::algorithm::hs::HSPrivate;
use crate::algorithm::JwAlg;
use sha2::Sha256;

pub type HS256Private = HSPrivate<Sha256>;

impl JwAlg for HS256Private {
    fn alg() -> impl AsRef<str> {
        "HS256"
    }
}
