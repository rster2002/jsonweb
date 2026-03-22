use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum ESCurve {
    #[serde(rename = "P-256")]
    P256,

    #[serde(rename = "P-384")]
    P384,

    #[serde(rename = "P-521")]
    P521,
}