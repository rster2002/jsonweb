mod models;
mod traits;

pub use traits::jw_key_type::JwKeyType;

#[cfg(all(test, feature = "rs256"))]
mod tests {
    use pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs1v15::SigningKey;
    use rsa::RsaPrivateKey;
    use crate::algorithm::{HS256Algorithm, RS256Algorithm};

    #[test]
    fn jwk_is_created_correctly() {
        let private_key = RsaPrivateKey::from_pkcs1_pem(include_str!("../../../test-files/rs256.key")).unwrap();

        let signing_key = SigningKey::new(private_key);
        let alg = RS256Algorithm::new(signing_key);


    }
}
