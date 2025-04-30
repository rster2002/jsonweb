use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ES256PrivateParams {
    pub crv: String,
    pub x: String,
    pub y: String,
    pub d: String,
}
