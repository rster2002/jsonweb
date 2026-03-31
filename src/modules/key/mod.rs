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
    use std::fs::read_to_string;
    use pkcs1::DecodeRsaPrivateKey;
    use rsa::RsaPrivateKey;
    use serde_json::json;
    use crate::modules::key::models::jwk::Jwk;

    #[test]
    fn jwk_is_created_correctly() {
        let string = read_to_string("./test-files/es256-private.jwks.json")
            .unwrap();
    }
}
