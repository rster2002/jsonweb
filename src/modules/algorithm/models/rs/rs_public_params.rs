use serde::{Deserialize, Serialize};
use crate::algorithm::rs::rs_private_params::RSPrivateParams;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RSPublicParams {
    pub n: String,
    pub e: String,
}

impl From<RSPrivateParams> for RSPublicParams {
    fn from(value: RSPrivateParams) -> Self {
        RSPublicParams {
            n: value.n,
            e: value.e,
        }
    }
}