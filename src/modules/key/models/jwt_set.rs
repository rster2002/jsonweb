use serde::{Deserialize, Serialize};
use crate::algorithm::{JwAlgVerify, PartialJwAlg};
use crate::modules::key::error::JwkError;
use crate::modules::key::models::jwk::Jwk;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtSet {
    pub keys: Vec<Jwk>,
}

impl PartialJwAlg for JwtSet {
    fn partial_alg() -> Option<impl AsRef<str>> {
        None::<&'static str>
    }
}

impl JwAlgVerify for JwtSet {
    type Error = JwkError;

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        todo!()
    }
}