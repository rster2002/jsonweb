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

impl JwkPublicParams<'_> for RS256Public {
    type PublicParams = RSPublicParams;

    fn get_public_params(&self) -> Option<Self::PublicParams> {
        let public_key = self.0.as_ref();
        let n = public_key.n().to_bytes_be();
        let e = public_key.e().to_bytes_be();

        Some(RSPublicParams {
            n: BASE64_URL_SAFE_NO_PAD.encode(&n),
            e: BASE64_URL_SAFE_NO_PAD.encode(&e),
        })
    }
}
