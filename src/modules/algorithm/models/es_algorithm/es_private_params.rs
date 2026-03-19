use serde::{Deserialize, Serialize};
use crate::algorithm::models::es_algorithm::es_curve::EsCurve;

#[derive(Debug, Serialize, Deserialize)]
pub struct EsPrivateParams {
    pub crv: EsCurve,
    pub x: String,
    pub y: String,
    pub d: String,
}