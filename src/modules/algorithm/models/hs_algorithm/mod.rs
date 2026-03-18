use std::convert::Infallible;
use std::fmt::{Debug};
use ecdsa::elliptic_curve::consts::U256;
use ecdsa::elliptic_curve::generic_array::typenum::{IsLess, Le, NonZero};
use ecdsa::signature::digest::block_buffer::Eager;
use ecdsa::signature::digest::core_api::{BlockSizeUser, BufferKindUser, CoreProxy, FixedOutputCore, UpdateCore};
use ecdsa::signature::digest::HashMarker;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::algorithm::{JwAlgVerify, JwAlgSign, JwAlg};
use hmac::digest::InvalidLength;

#[cfg(feature = "rand")]
use rand::RngCore;
use crate::algorithm::traits::partial_jw_alg::PartialJwAlg;

#[derive(Clone)]
pub struct HSPrivate<D>(Hmac<D>)
where D: CoreProxy,
      D::Core: HashMarker
      + UpdateCore
      + FixedOutputCore
      + BufferKindUser<BufferKind = Eager>
      + Default
      + Clone,
      <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
      Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero;

impl<D> HSPrivate<D>
where D: CoreProxy,
      D::Core: HashMarker
      + UpdateCore
      + FixedOutputCore
      + BufferKindUser<BufferKind = Eager>
      + Default
      + Clone,
      <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
      Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
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

#[cfg(feature = "hs256")]
impl JwAlg for HSPrivate<Sha256> {
    fn alg() -> impl AsRef<str> {
        "HS256"
    }
}

#[cfg(feature = "hs256")]
impl PartialJwAlg for HSPrivate<Sha256> {
    fn partial_alg() -> Option<impl AsRef<str>> {
        Some(Self::alg())
    }
}

impl<D> JwAlgVerify for HSPrivate<D>
where D: CoreProxy,
      D::Core: HashMarker
      + UpdateCore
      + FixedOutputCore
      + BufferKindUser<BufferKind = Eager>
      + Default
      + Clone,
      <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
      Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    type Error = Infallible;

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        let mut inner = self.0.clone();
        inner.update(payload.as_bytes());

        let finalized = inner.finalize()
            .into_bytes()
            .to_vec();

        Ok(signature == finalized)
    }
}

impl<D> JwAlgSign for HSPrivate<D>
where D: CoreProxy,
      D::Core: HashMarker
      + UpdateCore
      + FixedOutputCore
      + BufferKindUser<BufferKind = Eager>
      + Default
      + Clone,
      <D::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
      Le<<D::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    fn sign(&self, payload: &str) -> Vec<u8> {
        let mut inner = self.0.clone();
        inner.update(payload.as_bytes());

        inner.finalize().into_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use crate::algorithm::JwAlgSign;
    use crate::algorithm::models::hs_algorithm::HSPrivate;
    use crate::modules::algorithm::{HS256Private, JwAlgVerify};

    #[test]
    fn hs256_algorithm_works_as_expected() {
        let payload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoaiI6dHJ1ZX0";
        let alg = HS256Private::new("qwed".as_ref()).unwrap();

        let signature_bytes = alg.sign(payload);
        let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature_bytes);

        assert_eq!(signature_string, "AeQU9YyCnBlrJwtd1PVmGW3apn6kQ6yi_U4qT9o0vkQ");

        let verify = alg.verify(payload, &signature_bytes).unwrap();

        assert!(verify);
    }

    #[test]
    fn hs256_can_be_generated_randomly() {
        HS256Private::rand().unwrap();
    }
}
