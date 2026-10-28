use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::models::rs::rs_private::RSPrivate;
use crate::algorithm::models::rs::rs_public::RSPublic;

// Private
pub type RS384Private = RSPrivate<sha2::Sha384>;

impl JwAlg for RS384Private {
    fn alg() -> impl AsRef<str> {
        "RS384"
    }
}

// Public
pub type RS384Public = RSPublic<sha2::Sha384>;

impl JwAlg for RS384Public {
    fn alg() -> impl AsRef<str> {
        "RS384"
    }
}
