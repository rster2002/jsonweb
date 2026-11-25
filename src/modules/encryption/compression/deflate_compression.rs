use std::convert::Infallible;
use crate::modules::encryption::JweCompression;

pub struct DeflateCompression;

impl JweCompression for DeflateCompression {
    type Error = !;
    const ZIP: &'static str = "DEF";

    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }

    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }
}