use serde::{Deserialize, Serialize};
use crate::algorithm::{JwAlgVerify, HandlesJwAlg};
use crate::modules::key::error::JwkError;
use crate::modules::key::models::jwk::Jwk;

#[derive(Debug, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}


