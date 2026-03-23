use serde::{Deserialize, Serialize};
use crate::algorithm::es::{ESPrivateParams, ESPublicParams};

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JwkParams {
    ESPrivateParams(ESPrivateParams),
    ESPublicParams(ESPublicParams),
}