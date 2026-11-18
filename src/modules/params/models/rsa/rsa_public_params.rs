use crate::modules::params::models::rsa::rsa_private_params::RSAPrivateParams;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RSAPublicParams {
    pub n: String,
    pub e: String,
}

impl From<RSAPrivateParams> for RSAPublicParams {
    fn from(value: RSAPrivateParams) -> Self {
        RSAPublicParams {
            n: value.n,
            e: value.e,
        }
    }
}