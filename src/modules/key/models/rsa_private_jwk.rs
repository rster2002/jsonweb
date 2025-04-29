use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct RsaPublicJwk {
    pub n: String,
    pub e: String,
}
