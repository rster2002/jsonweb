use crate::algorithm::{JwAlgSign, JwAlgVerify};
use digest::block_api::EagerHash;
use hmac::digest::InvalidLength;
use hmac::{Hmac, Mac};
use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use digest::KeyInit;
#[cfg(feature = "rand")]
use rand::RngCore;

#[cfg(feature = "hs256")]
mod hs256;

#[cfg(feature = "hs256")]
pub use hs256::HS256Private;

#[derive(Clone)]
pub struct HSPrivate<D>(Hmac<D>)
where
    D: EagerHash;

impl<D> HSPrivate<D>
where
    D: EagerHash,
{
    pub fn new(key: &[u8]) -> Result<Self, InvalidLength> {
        Ok(HSPrivate(Hmac::<D>::new_from_slice(key)?))
    }

    #[cfg(feature = "rand")]
    pub fn rand() -> Result<Self, InvalidLength> {
        let mut rng = rand::thread_rng();
        let mut slice = [0u8; 32];
        rng.fill_bytes(&mut slice);

        HSPrivate::new(&slice)
    }
}

impl<D> JwAlgVerify for HSPrivate<D>
where D: EagerHash,
{
    type Error = Infallible;

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let mut inner = self.0.clone();
        inner.update(payload);

        let finalized = inner.finalize()
            .into_bytes()
            .to_vec();

        Ok(signature == finalized)
    }
}

impl<D> JwAlgSign for HSPrivate<D>
where D : EagerHash,
{
    type Error = Infallible;

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Infallible> {
        let mut inner = self.0.clone();
        inner.update(payload);

        Ok(inner.finalize().into_bytes().to_vec())
    }
}

impl<D> Debug for HSPrivate<D>
where D : EagerHash,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "HSPrivate(..)")
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::JwAlgSign;
    use crate::algorithm::hs::HS256Private;
    use crate::modules::algorithm::JwAlgVerify;
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;

    #[test]
    fn hs256_algorithm_works_as_expected() {
        let payload = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoaiI6dHJ1ZX0";
        let alg = HS256Private::new("qwed".as_ref()).unwrap();

        let signature_bytes = alg.sign(payload).unwrap();
        let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature_bytes);

        assert_eq!(signature_string, "AeQU9YyCnBlrJwtd1PVmGW3apn6kQ6yi_U4qT9o0vkQ");

        let verify = alg.verify(payload, &signature_bytes).unwrap();

        assert!(verify);
    }

    #[test]
    fn hs256_can_be_generated_randomly() {
        // HS256Private::rand().unwrap();
    }
}
