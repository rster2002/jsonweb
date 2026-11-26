use rand::{Rng, RngCore};
use crate::modules::encryption::error::JweError;
use crate::modules::encryption::{JweCompression, JweEncoding, JweKeyAgreement};
use crate::modules::header::JoseHeader;

pub fn encrypt_compact<A, E, C>(
    header: JoseHeader,
    plaintext: &[u8],
    algorithm: &A,
    encoding: &E,
    compression: &C,
) -> Result<String, JweError>
where
    A : JweKeyAgreement,
    E : JweEncoding,
    C : JweCompression,
{
    let header = header.or(JoseHeader {
        enc: Some(E::ENC.to_string()),
        ..Default::default()
    });

    let cek = algorithm.cek(E::CEK_LENGTH)
        .unwrap();

    if cek.len() != E::CEK_LENGTH {
        return Err(JweError::InvalidCekLength);
    }

    Ok("a".to_string())
}

#[cfg(test)]
mod tests {
    use crate::modules::encryption::algorithm::DirectEncryption;
    use crate::modules::encryption::encoding::aes_gcm::Aes256GmcEncoding;
    use crate::modules::encryption::functions::encrypt_compact::encrypt_compact;
    use crate::modules::encryption::{random_cek, NoneCompression};
    use crate::modules::header::JoseHeader;

    #[test]
    fn test_encrypt_compact() {
        encrypt_compact(
            JoseHeader::default(),
            b"Hello world",
            &DirectEncryption::new(random_cek(16)),
            &Aes256GmcEncoding::default(),
            &NoneCompression,
        ).unwrap();
    }
}