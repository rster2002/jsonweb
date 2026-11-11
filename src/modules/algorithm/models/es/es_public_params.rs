use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ESPublicParams {
    pub crv: String,
    pub x: String,
    pub y: String,
}