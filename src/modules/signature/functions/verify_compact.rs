use crate::algorithm::{JwAlg, JwAlgVerify, PartialJwAlg, PartialJwAlgVerify};
use crate::modules::header::JoseHeader;
use crate::modules::signature::error::JwsError;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;

pub fn verify_compact<A>(signature: &str, algorithm: &A) -> Result<Vec<u8>, JwsError>
where
    A: PartialJwAlg + PartialJwAlgVerify,
    <A as PartialJwAlgVerify>::Error: 'static,
{
    let mut parts = signature.splitn(3, '.');
    let header_string = parts.next().ok_or(JwsError::NoHeader)?;
    let header_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(header_string.as_bytes())
        .map_err(|e| JwsError::DecodeBase64Header(e))?;
    let header_json: JoseHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| JwsError::DecodeJsonHeader(e))?;
    let header_alg = header_json.alg.as_ref().ok_or(JwsError::NoAlg)?;

    let payload_string = parts.next().ok_or(JwsError::NoPayload)?;
    let payload_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(payload_string.as_bytes())
        .map_err(|e| JwsError::DecodeBase64Payload(e))?;

    let signature_string = parts.next().ok_or(JwsError::NoSignature)?;
    let signature_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(signature_string.as_bytes())
        .map_err(|e| JwsError::DecodeBase64Signature(e))?;

    let target = format!("{}.{}", header_string, payload_string);
    match algorithm.partial_verify(&header_alg, target.as_bytes(), &signature_bytes) {
        None => Err(JwsError::UnmatchedAlgorithm),
        Some(Err(error)) => Err(JwsError::AlgError(Box::new(error))),
        Some(Ok(false)) => Err(JwsError::InvalidSignature),
        Some(Ok(true)) => Ok(payload_bytes)
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::hs::HS256Private;
    use crate::modules::signature::error::JwsError;
    use crate::modules::signature::functions::verify_compact::verify_compact;

    #[test]
    fn correct_signature_returns_payload() {
        let signature =
            "eyJhbGciOiJIUzI1NiJ9.SGVsbG8gd29ybGQ.lx8XX3uMIc57Na8JUblW-_qwlZ3H2bwkSZwvL8Iqa5w";
        let hs256 = HS256Private::new(b"secret").unwrap();

        let payload = verify_compact(signature, &hs256).unwrap();

        assert_eq!(payload, b"Hello world");
    }

    #[test]
    fn incorrect_signature_returns_error() {
        let signature =
            "eyJhbGciOiJIUzI1NiJ9.SGVsbG8gdG8geW91.lx8XX3uMIc57Na8JUblW-_qwlZ3H2bwkSZwvL8Iqa5w";
        let hs256 = HS256Private::new(b"secret").unwrap();

        let result = verify_compact(signature, &hs256);

        assert!(matches!(result.unwrap_err(), JwsError::InvalidSignature));
    }
}
