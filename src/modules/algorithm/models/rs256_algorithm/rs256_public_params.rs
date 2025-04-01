use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct RS256PublicParams {
    pub n: String,
    pub e: String,
}
