use std::convert::Infallible;
use std::marker::PhantomData;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use const_oid::AssociatedOid;
use digest::Digest;
use rsa::{BoxedUint, PublicKey};
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use crate::algorithm::{JwAlgVerify};
use crate::algorithm::rs::error::RSError;
use crate::algorithm::rs::rs_private::RSPrivate;
use crate::algorithm::rs::rs_public_params::RSPublicParams;
use crate::modules::key::JwkPublicParams;

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

impl<D> TryFrom<RSPublicParams> for RSPublic<D>
where
    D: AssociatedOid + Digest,
{
    type Error = RSError;

    fn try_from(value: RSPublicParams) -> Result<Self, Self::Error> {
        let n = BASE64_URL_SAFE_NO_PAD
            .decode(value.n)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSError::FailedToBase64DecodeN(e))?
            .map_err(|e| RSError::FailedToRepresentN(rsa::Error::Decode(e)))?;

        let e = BASE64_URL_SAFE_NO_PAD
            .decode(value.e)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSError::FailedToBase64DecodeE(e))?
            .map_err(|e| RSError::FailedToRepresentE(rsa::Error::Decode(e)))?;

        let public_key = PublicKey::new(n, e)
            .map_err(|e| RSError::FailedToCreatePublicKeyFromParameters(e))?;

        Ok(RSPublic {
            public_key,
            _p: PhantomData,
        })
    }
}

impl<D> TryInto<RSPublicParams> for RSPublic<D>
where
    D: AssociatedOid + Digest,
{
    type Error = RSError;

    fn try_into(self) -> Result<RSPublicParams, Self::Error> {
        let n = BASE64_URL_SAFE_NO_PAD.encode(self.public_key.n().to_be_bytes());
        let e = BASE64_URL_SAFE_NO_PAD.encode(self.public_key.e_bytes());

        Ok(RSPublicParams {
            n,
            e,
        })
    }
}

impl<D> JwkPublicParams for RSPublic<D>
where D : Digest + AssociatedOid,
{
    type PublicParams = RSPublicParams;
}
