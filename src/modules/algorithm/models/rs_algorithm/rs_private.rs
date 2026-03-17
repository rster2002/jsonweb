use crate::algorithm::{JwAlg, JwAlgSign, JwAlgVerify};
use ecdsa::elliptic_curve::pkcs8::AssociatedOid;
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::signature::{Keypair, SignatureEncoding, Signer, Verifier};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[cfg(feature = "pkcs1")]
use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};

#[derive(Clone)]
pub struct RSPrivate<D>(SigningKey<D>)
where D: Digest + AssociatedOid;

impl<D> RSPrivate<D>
where D: Digest + AssociatedOid,
{
    #[cfg(feature = "rand")]
    pub fn rand() -> Result<Self, rsa::Error> {
        Self::rand_size(4096)
    }

    #[cfg(feature = "rand")]
    pub fn rand_size(size: usize) -> Result<Self, rsa::Error> {
        let mut rng = rand::thread_rng();
        Ok(RSPrivate::from(SigningKey::random(&mut rng, size)?))
    }

    #[cfg(feature = "pkcs1")]
    pub fn to_pkcs1_der_bytes(&self) -> Result<Vec<u8>, rsa::Error> {
        Ok(self.0.to_pkcs1_der()?
            .to_bytes()
            .to_vec())
    }

    #[cfg(feature = "pkcs1")]
    pub fn from_pkcs1_der_bytes(bytes: &[u8]) -> Result<Self, rsa::Error> {
        Ok(RSPrivate::from(SigningKey::from_pkcs1_der(bytes)?))
    }
}

#[cfg(feature = "rs256")]
impl JwAlg for RSPrivate<sha2::Sha256> {
    fn alg() -> impl AsRef<str> {
        "RS256"
    }
}

#[cfg(feature = "rs384")]
impl JwAlg for RSPrivate<sha2::Sha384> {
    fn alg() -> impl AsRef<str> {
        "RS384"
    }
}

#[cfg(feature = "rs512")]
impl JwAlg for RSPrivate<sha2::Sha512> {
    fn alg() -> impl AsRef<str> {
        "RS512"
    }
}

impl<D> JwAlgVerify for RSPrivate<D>
where D: Digest + AssociatedOid,
{
    type Error = rsa::signature::Error;

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let signature = Signature::try_from(signature)?;

        Ok(self.0.verifying_key().verify(payload.as_bytes(), &signature).is_ok())
    }
}

impl<D> JwAlgSign for RSPrivate<D>
where D: Digest + AssociatedOid,
{
    fn sign(&self, payload: &str) -> Vec<u8> {
        self.0.sign(payload.as_bytes()).to_vec()
    }
}

impl<D> From<SigningKey<D>> for RSPrivate<D>
where D: Digest + AssociatedOid,
{
    fn from(key: SigningKey<D>) -> Self {
        Self(key)
    }
}

impl<D> From<RsaPrivateKey> for RSPrivate<D>
where D: Digest + AssociatedOid,
{
    fn from(key: RsaPrivateKey) -> Self {
        Self::from(SigningKey::new(key))
    }
}

#[cfg(all(test, feature = "pkcs1"))]
mod tests {
    use crate::algorithm::{JwAlgSign, JwAlgVerify, RS256Private};
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use base64::Engine;
    use pkcs1::DecodeRsaPrivateKey;
    pub use rsa::RsaPrivateKey;

    #[test]
    fn rs256_algorithm_works_as_expected() {
        let payload = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJoaiI6dHJ1ZX0";

        let private_key = RsaPrivateKey::from_pkcs1_pem(include_str!("../../../../../test-files/rs256.key")).unwrap();
        let alg = RS256Private::from(private_key);

        let signature_bytes = alg.sign(payload);
        let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature_bytes);

        assert_eq!(signature_string, "ptH8Vc-nhm4gTl7HqaictKQyK3fxiJmSfyu-ouYlmIfyyRBIYw2tUdKxIsxgYMPXC7oV0-ShYtlUm73-q2buLoYGc52d-03RQghcVvZrag2nQCKsBBmTXFUADEaVopO65aND5h7Uif_1aQJXmX-40-V5te0fT3WSyU_1oKayxpi53_c7RXD7gDlWSXAZFDNhPopcRnq2_4FQylzFf4qbwtGWUNdJA4SGOikr1lsTrQRPGXLNXREG0PWv9GFoobQDTj9DWBG4B_cCAUVAjYUCx8BbgHSY9jeiYE_FbDykW0tRSA3XAYpf1QCPZmrCPButUixWY03FTTxsQxlJuY8r-w");

        let verify = alg.verify(payload, &signature_bytes).unwrap();

        assert!(verify);
    }
}
