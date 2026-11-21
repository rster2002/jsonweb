use serde::{Deserialize, Serialize};
use crate::modules::params::ec::ECPrivateParams;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECPublicParams {
    pub crv: String,
    pub x: String,
    pub y: String,
}

impl From<ECPrivateParams> for ECPublicParams {
    fn from(value: ECPrivateParams) -> Self {
        ECPublicParams {
            crv: value.crv,
            x: value.x,
            y: value.y,
        }
    }
}