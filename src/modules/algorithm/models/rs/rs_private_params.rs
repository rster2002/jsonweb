use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RSPrivateParams {
    pub n: String,
    pub e: String,
    pub d: String,
}