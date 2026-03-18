mod models;
mod traits;
pub mod error;

#[cfg(all(test, feature = "rs256"))]
mod tests {
    use pkcs1::DecodeRsaPrivateKey;
    use rsa::RsaPrivateKey;
    use serde_json::json;
    use crate::algorithm::{RS256Private};
    use crate::modules::key::models::jwk::Jwk;

    #[test]
    fn jwk_is_created_correctly() {
        let ec_key = Jwk::try_from(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "",
            "y": "",
        }));
    }
}
