mod models;
mod traits;

#[cfg(all(test, feature = "rs256"))]
mod tests {
    use pkcs1::DecodeRsaPrivateKey;
    use rsa::RsaPrivateKey;
    use crate::algorithm::{RS256Private};

    #[test]
    fn jwk_is_created_correctly() {
        let private_key = RsaPrivateKey::from_pkcs1_pem(include_str!("../../../test-files/rs256.key")).unwrap();
        let alg = RS256Private::from(private_key);
        // let jwk = Jwk::new(&alg);
    }
}
