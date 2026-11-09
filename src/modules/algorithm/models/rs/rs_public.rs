use std::convert::Infallible;
use std::marker::PhantomData;
use const_oid::AssociatedOid;
use digest::Digest;
use rsa::PublicKey;
use rsa::signature::Verifier;
use crate::algorithm::{JwAlgVerify};
use crate::algorithm::rs::error::RSError;
use crate::algorithm::rs::rs_private::RSPrivate;

#[derive(Debug, Clone)]
pub struct RSPublic<D>
where D : Digest + AssociatedOid,
{
    pub(crate) public_key: PublicKey,
    _p: PhantomData<D>,
}

impl<D> JwAlgVerify for RSPublic<D>
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
