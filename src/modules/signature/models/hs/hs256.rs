use crate::algorithm::JwAlg;
use sha2::Sha256;
use crate::modules::signature::hs::HSPrivate;

pub type HS256Private = HSPrivate<Sha256>;

impl JwAlg for HS256Private {
    fn alg() -> impl AsRef<str> {
        "HS256"
    }
}
