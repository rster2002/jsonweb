use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ES256PrivateParams {
    pub crv: String,
    pub d: String,
    pub x: String,
    pub y: String,
}
