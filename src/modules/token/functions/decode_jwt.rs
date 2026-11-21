use crate::modules::header::JoseHeader;
use crate::token::{JwtClaims, JwtError};
use serde::de::DeserializeOwned;
use crate::modules::signature::{verify_compact, PartialJwAlgVerify};

/// Decodes the given JWT token and verifies its signature. It DOES NOT perform any validation on
/// the claims. Use [JwtClaims::verify] to perform validation.
pub fn decode_jwt<T, A>(
    token: &str,
    alg: &A,
) -> Result<(JoseHeader, JwtClaims, T), JwtError>
where
    T: DeserializeOwned,
    A: PartialJwAlgVerify,
{
    let (header, payload_bytes) = verify_compact(token, alg)?;
    let payload: T = serde_json::from_slice(&payload_bytes)?;

    // Unwrap or default as these would then be checked later.
    let claims = serde_json::from_slice(&payload_bytes)
        .unwrap_or_default();

    Ok((header, claims, payload))
}
