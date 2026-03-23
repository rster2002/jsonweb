use serde::{Deserialize, Serialize};
use crate::algorithm::models::es::es_curve::ESCurve;

#[derive(Debug, Serialize, Deserialize)]
pub struct ESPublicParams {
    pub crv: ESCurve,
    pub x: String,
    pub y: String,
}