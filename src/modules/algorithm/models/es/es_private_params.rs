use serde::{Deserialize, Serialize};

/// Private parameters for the 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESPrivateParams {
    pub crv: String,
    pub x: String,
    pub y: String,
    pub d: String,
}