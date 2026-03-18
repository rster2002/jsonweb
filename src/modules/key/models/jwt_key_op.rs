use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum JwtKeyOp {
    #[serde(rename = "sign")]
    Sign,

    #[serde(rename = "verify")]
    Verify,

    #[serde(rename = "encrypt")]
    Encrypt,

    #[serde(rename = "decrypt")]
    Decrypt,

    #[serde(rename = "wrapKey")]
    WrapKey,

    #[serde(rename = "unwrapKey")]
    UnwrapKey,

    #[serde(rename = "deriveKey")]
    DeriveKey,

    #[serde(rename = "deriveBits")]
    DeriveBits,
    
    #[serde(untagged)]
    Other(String),
}