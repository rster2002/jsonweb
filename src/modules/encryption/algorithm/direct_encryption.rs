use crate::modules::encryption::JweKeyAgreement;

/// Direct encryption using a shared key.
pub struct DirectEncryption {
    key: Vec<u8>,
}

impl DirectEncryption {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}

impl JweKeyAgreement for DirectEncryption {
    type Error = !;
    const JWE_ALG: &'static str = "";

    fn cek(&self, expected_size: usize) -> Result<Vec<u8>, Self::Error> {
        Ok(self.key.iter().take(expected_size).cloned().collect())
    }
}