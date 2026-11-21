
use crate::modules::key::{JwkPublicParams, JwkType};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use const_oid::AssociatedOid;
use digest::Digest;
use rsa::traits::PublicKeyParts;
use rsa::{BoxedUint, PublicKey};
use std::marker::PhantomData;
use crate::modules::params::rsa::{RSAPrivateParams, RSAPublicParams};
use crate::modules::signature::JwVerify;
use crate::modules::signature::rs::{RSError, RSPrivate};

#[derive(Debug, Clone)]
pub struct RSPublic<D>
where D : Digest + AssociatedOid,
{
    pub(crate) public_key: PublicKey,
    _p: PhantomData<D>,
}

impl<D> JwVerify for RSPublic<D>
where D : Digest + AssociatedOid,
{
    type Error = RSError;

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, RSError> {
        match self.public_key.pkcs1v15_verify::<D>(payload, signature) {
            Ok(()) => Ok(true),
            Err(rsa::Error::Verification) => Ok(false),
            Err(error) => Err(RSError::FailedToVerify(error)),
        }
    }
}

impl<D> From<&RSPrivate<D>> for RSPublic<D>
where D : Digest + AssociatedOid,
{
    fn from(value: &RSPrivate<D>) -> Self {
        RSPublic {
            public_key: value.private_key.as_public_key().clone(),
            _p: PhantomData,
        }
    }
}

impl<D> TryFrom<RSAPublicParams> for RSPublic<D>
where
    D: AssociatedOid + Digest,
{
    type Error = RSError;

    fn try_from(value: RSAPublicParams) -> Result<Self, Self::Error> {
        Ok(RSPublic::from(value.public_key()?))
    }
}

impl<D> TryFrom<RSAPrivateParams> for RSPublic<D>
where
    D: AssociatedOid + Digest,
{
    type Error = RSError;

    fn try_from(value: RSAPrivateParams) -> Result<Self, Self::Error> {
        Ok(RSPublic::from(value.public_key()?))
    }
}

impl<D> TryInto<RSAPublicParams> for RSPublic<D>
where
    D: AssociatedOid + Digest,
{
    type Error = RSError;

    fn try_into(self) -> Result<RSAPublicParams, Self::Error> {
        Ok(RSAPublicParams::from_public_key(self.public_key.clone())?)
    }
}

impl<D> JwkType for RSPublic<D>
where
    D: AssociatedOid + Digest,
{
    fn kty() -> impl AsRef<str> {
        "RSA"
    }
}

impl<D> JwkPublicParams for RSPublic<D>
where D : Digest + AssociatedOid,
{
    type PublicParams = RSAPublicParams;
}

impl<D> From<RSPrivate<D>> for RSPublic<D>
where
    D: AssociatedOid + Digest,
{
    fn from(value: RSPrivate<D>) -> Self {
        RSPublic::from(value.private_key.as_public_key().clone())
    }
}

impl<D> From<PublicKey> for RSPublic<D>
where
    D: AssociatedOid + Digest,
{
    fn from(value: PublicKey) -> Self {
        RSPublic {
            public_key: value,
            _p: PhantomData,
        }
    }
}
