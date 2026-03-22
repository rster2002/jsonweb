use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::modules::key::models::jwt_key_op::JwtKeyOp;
use crate::modules::key::models::jwt_use::JwtUse;
use crate::token::JwtError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,

    #[serde(rename = "use")]
    pub usage: Option<JwtUse>,
    pub key_ops: Option<Vec<JwtKeyOp>>,
    pub alg: Option<String>,
    pub kid: Option<String>,
    pub x5u: Option<String>,
    pub x5c: Option<Vec<String>>,
    pub x5t: Option<String>,

    #[serde(rename = "x5t#S256")]
    pub x5t_s256: Option<String>,

    #[serde(flatten)]
    pub params: Option<Value>,
}

impl TryFrom<Value> for Jwk {
    type Error = JwtError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        todo!()
    }
}