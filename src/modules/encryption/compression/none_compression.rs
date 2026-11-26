use crate::modules::encryption::JweCompression;

pub struct NoneCompression;

impl JweCompression for NoneCompression {
    type Error = !;
    const ZIP: &'static str = "";

    fn compress(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(data.to_vec())
    }

    fn decompress(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(data.to_vec())
    }
}