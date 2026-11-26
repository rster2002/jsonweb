use std::marker::PhantomData;
use aes::Aes256;
use aes_gcm::{AesGcm};
use digest::common::BlockSizeUser;
use digest::typenum::{Unsigned, U12, U16};
use crate::modules::encryption::JweEncoding;

pub type Aes256GmcEncoding = AesGcmEncoding<Aes256>;

#[derive(Debug)]
pub struct AesGcmEncoding<A>
where A : BlockSizeUser<BlockSize = U16>
{
    _p: PhantomData<A>,
}

impl Default for Aes256GmcEncoding {
    fn default() -> Self {
        Self { _p: PhantomData }
    }
}

impl<A> JweEncoding for AesGcmEncoding<A>
where A : BlockSizeUser<BlockSize = U16>
{
    type Error = !;
    const ENC: &'static str = "";
    const CEK_LENGTH: usize = A::BlockSize::USIZE;

    fn encrypt(&self, cek: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }
}