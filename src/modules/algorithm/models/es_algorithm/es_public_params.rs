use serde::{Deserialize, Serialize};
use crate::algorithm::models::es_algorithm::es_curve::ESCurve;

#[derive(Debug, Serialize, Deserialize)]
pub struct ESPublicParams {
    pub crv: ESCurve,
    pub x: String,
    pub y: String,
}