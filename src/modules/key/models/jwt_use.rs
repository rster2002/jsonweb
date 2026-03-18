use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum JwtUse {
    #[serde(rename = "sig")]
    Signature,

    #[serde(rename = "enc")]
    Encryption,

    #[serde(untagged)]
    Unknown(String),
}