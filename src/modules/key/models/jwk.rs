use crate::algorithm::JwAlgVerify;
use crate::modules::key::JwkError;
use crate::modules::key::models::jwk_key_op::JwkKeyOp;
use crate::modules::key::models::jwt_use::JwkUse;
use crate::token::JwtError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,

    #[serde(rename = "use")]
    pub usage: Option<JwkUse>,
    pub key_ops: Option<Vec<JwkKeyOp>>,
    pub alg: Option<String>,
    pub kid: Option<String>,
    pub x5u: Option<String>,
    pub x5c: Option<Vec<String>>,
    pub x5t: Option<String>,

    #[serde(rename = "x5t#S256")]
    pub x5t_s256: Option<String>,
}

impl TryFrom<Value> for Jwk {
    type Error = JwkError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(serde_json::from_value(value)?)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn scratch() {
        let public_key = json!({
            "alg": "RS256",
            "e": "AQAB",
            "kid": "VIQGk4NjKt8",
            "kty": "RSA",
            "n": "48Gy0BgJlyeqtOaFTF9eJhWo-51pryRma7hGuqz3zz8_IOxWMQU2aEiIaRlUozIu3thqowByO4bBD5M0Hc9PuPGJy75hxlCc7J4JMxBw5_SK3r2-cBm2s1Jex2jUqK6-Omau22eA0F97w3Op6ISXAMN3AhqJ4ZgNJQw9Kn3rDBTdr6on62eY3NXmcsh9HseS0YECqDyDr0O_HlUfz8NpLlLZUEAhnJxbcBU6napsyM2uoBq8x4Im98o5jyYfUM3xhlaVCaNVuxHKxc7TkFH8Cnv0-JRbjPZGeWHk78rQ-56h2CcYII5j63FEN6V0evcSIfg3ICxRqf0eaxbOiqAg1Q",
            "use": "sig"
        });
    }
}
