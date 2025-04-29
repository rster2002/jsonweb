mod models;
mod traits;

pub use traits::jw_key_type::JwKeyType;
pub use models::rsa_private_jwk::RsaPublicJwk;

#[cfg(all(test, feature = "rs256"))]
mod tests {
    use pkcs1::DecodeRsaPrivateKey;
    use rsa::RsaPrivateKey;
    use crate::algorithm::{RS256Private};
    use crate::modules::key::models::jwk::Jwk;

    #[test]
    fn jwk_is_created_correctly() {
        let private_key = RsaPrivateKey::from_pkcs1_pem(include_str!("../../../test-files/rs256.key")).unwrap();
        let alg = RS256Private::new(private_key);
        // let jwk = Jwk::new(&alg);
    }
}
