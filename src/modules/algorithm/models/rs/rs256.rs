use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use rsa::traits::PublicKeyParts;
use crate::algorithm::{JwAlg, PartialJwAlg};
use crate::algorithm::models::rs::rs_private::RSPrivate;
use crate::algorithm::models::rs::rs_public::RSPublic;
use crate::algorithm::rs::rs_public_params::RSPublicParams;
use crate::modules::key::JwkPublicParams;

// Private
pub type RS256Private = RSPrivate<sha2::Sha256>;

impl JwAlg for RS256Private {
    fn alg() -> impl AsRef<str> {
        "RS256"
    }
}

// Public
pub type RS256Public = RSPublic<sha2::Sha256>;

impl JwAlg for RS256Public {
    fn alg() -> impl AsRef<str> {
        "RS256"
    }
}
