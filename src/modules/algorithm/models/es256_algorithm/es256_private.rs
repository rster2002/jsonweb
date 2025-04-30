use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use p256::ecdsa::{SigningKey, Signature, signature::Signer};
use p256::ecdsa::signature::Verifier;
use p256::elliptic_curve::SecretKey;
use p256::NistP256;
use crate::algorithm::{JwAlg, JwAlgSign};
use crate::algorithm::models::es256_algorithm::es256_private_params::ES256PrivateParams;
use crate::modules::key::JwKeyType;

/// ```shell
/// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out es256.pem
/// ```
#[derive(Clone)]
pub struct ES256Private {
    inner: SecretKey<NistP256>,
    signing_key: SigningKey,
}

impl From<SecretKey<NistP256>> for ES256Private {
    fn from(value: SecretKey<NistP256>) -> Self {
        ES256Private {
            signing_key: SigningKey::from(value.clone()),
            inner: value,
        }
    }
}

impl JwAlg for ES256Private {
    type Error = Infallible;

    fn alg() -> impl AsRef<str> {
        "ES256"
    }

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let verifying_key = self.signing_key.verifying_key();
        let signature = Signature::try_from(signature).unwrap();

        Ok(verifying_key.verify(payload.as_bytes(), &signature).is_ok())
    }
}

impl JwAlgSign for ES256Private {
    fn sign(&self, payload: &str) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(payload.as_bytes());
        signature.to_vec()
    }
}

impl JwKeyType<'_> for ES256Private {
    type Params = ES256PrivateParams;

    fn kty() -> impl AsRef<str> {
        "EC"
    }

    fn parms(&self) -> Self::Params {
        let base_value = serde_json::to_value(self.inner.clone().to_jwk())
            .expect("should always work");

        let key = base_value
            .as_object()
            .expect("should always be an object");

        ES256PrivateParams {
            crv: key.get("crv")
                .expect("should always have a value")
                .as_str()
                .expect("should always be a string")
                .to_string(),

            x: key.get("x")
                .expect("should always have a value")
                .as_str()
                .expect("should always be a string")
                .to_string(),

            y: key.get("y")
                .expect("should always have a value")
                .as_str()
                .expect("should always be a string")
                .to_string(),

            d: key.get("d")
                .expect("should always have a value")
                .as_str()
                .expect("should always be a string")
                .to_string(),
        }
    }
}

impl Debug for ES256Private {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ES256Algorithm {{ .. }}")
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use p256::ecdsa::SigningKey;
    use p256::SecretKey;
    use crate::algorithm::{ES256Private, JwAlg, JwAlgSign};

    #[test]
    fn es256_algorithm_works_as_expected() {
        let payload = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0";
        let secret_key = include_str!("../../../../../test-files/es256.key").parse::<SecretKey>().unwrap();

        let alg = ES256Private::from(secret_key);

        let signature_bytes = alg.sign(payload);
        let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature_bytes);

        assert_eq!(signature_string, "XX7zPdDrYpegeS7mBfBIUVXnqVT-XSemrGjgoZBlrN0--n94Lv03J9vzbDDJXPzxnSs_62ymIJr1zBMaoMAveA");

        let verify = alg.verify(payload, &signature_bytes).unwrap();

        assert!(verify);
    }
    
    #[test]
    fn jwk_is_generated_correctly() {
        
    }
}
