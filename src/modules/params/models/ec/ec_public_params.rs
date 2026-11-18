use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECPublicParams {
    pub crv: String,
    pub x: String,
    pub y: String,
}