mod models;
mod traits;
mod error;

pub use traits::jwk_private_params::JwkPrivateParams;
pub use traits::jwk_public_params::JwkPublicParams;
pub use traits::jwk_type::JwkType;
pub use models::jwk::Jwk;
pub use error::JwkError;

#[cfg(all(test, feature = "rs256"))]
mod tests {
    use pkcs1::DecodeRsaPrivateKey;
    use rsa::RsaPrivateKey;
    use serde_json::json;
    use crate::modules::key::models::jwk::Jwk;

    #[test]
    fn jwk_is_created_correctly() {
        // let ec_key = Jwk::try_from(json!({
        //     "kty": "EC",
        //     "crv": "P-256",
        //     "x": "",
        //     "y": "",
        // }));
    }
}
