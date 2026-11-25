use rand::{Rng, RngCore};
use crate::modules::encryption::error::JweError;
use crate::modules::encryption::JweEncoding;

pub fn encrypt_compact<A, E, C>(
    plaintext: &[u8],
    encoding: E,
) -> Result<String, JweError>
where E : JweEncoding,
{
    let mut rng = rand::thread_rng();
    let mut sec = vec![0u8; E::CEK_LENGTH];
    rng.fill_bytes(&mut sec);

    assert_eq!(sec.len(), E::CEK_LENGTH);

    

    todo!()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_encrypt_compact() {

    }
}