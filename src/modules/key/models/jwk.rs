use crate::algorithm::{JwAlg, JwAlgVerify};
use crate::modules::key::{JwkError, JwkPrivateParams};
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

    #[serde(flatten)]
    pub parameters: Value,
}

impl Jwk {
    /// Attempt to turn the JWK into a private algorithm to use.
    pub fn to_private<A>(self) -> Result<A, JwkError>
    where A : JwAlg + JwkPrivateParams,
    {
        if self.kty != A::kty().as_ref() {
            return Err(JwkError::MismatchedKeyType);
        }

        let Some(alg) = self.alg else {
            return Err(JwkError::MissingAlgorithm);
        };

        if alg != A::alg().as_ref() {
            return Err(JwkError::MismatchedAlgorithm);
        }

        let parameters = serde_json::from_value(self.parameters)?;
        Ok(A::try_from(parameters).map_err(|_| JwkError::Failed)?)
    }
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
    use crate::algorithm::rs::RS256Private;
    use crate::modules::header::JoseHeader;
    use crate::modules::key::Jwk;
    use crate::modules::signature::sign_compact;

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

        let jwk = Jwk::try_from(public_key).unwrap();
        dbg!(jwk);
    }

    #[test]
    fn correct_rs256_key_can_be_decoded() {
        let private_key = json!({
            "kty":"RSA",
            "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e":"AQAB",
            "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
            "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
            "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
            "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
            "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
            "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
            "alg":"RS256",
            "kid":"2011-04-29"
        });

        let payload = b"hello world";

        let jwk = Jwk::try_from(private_key).unwrap();
        let alg: RS256Private = jwk.to_private().unwrap();

        let signed = sign_compact(JoseHeader::default(), payload, &alg)
            .unwrap();
    }
}
