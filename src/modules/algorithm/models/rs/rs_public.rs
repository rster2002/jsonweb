use std::marker::PhantomData;
use const_oid::AssociatedOid;
use digest::Digest;
use rsa::PublicKey;
use rsa::signature::Verifier;
use crate::algorithm::{JwAlgVerify};

#[derive(Debug, Clone)]
pub struct RSPublic<D>
where D : Digest + AssociatedOid,
{
    public_key: PublicKey,
    _p: PhantomData<D>,
}

impl<D> JwAlgVerify for RSPublic<D>
where D : Digest + AssociatedOid,
{
    type Error = rsa::signature::Error;

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        Ok(self.public_key.pkcs1v15_verify::<D>(payload, signature).is_ok())
    }
}
