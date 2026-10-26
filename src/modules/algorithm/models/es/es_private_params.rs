use serde::{Deserialize, Serialize};
use crate::algorithm::es::ESCurve;

/// Private parameters for the 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESPrivateParams {
    pub crv: ESCurve,
    pub x: String,
    pub y: String,
    pub d: String,
}