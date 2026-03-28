use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RSPublicParams {
    pub n: String,
    pub e: String,
}