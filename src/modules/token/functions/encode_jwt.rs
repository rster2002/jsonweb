use crate::algorithm::{JwAlg};
use crate::modules::header::JoseHeader;
use crate::modules::signature::{sign_compact, JwSign};
use crate::token::{JwtClaims, JwtError};
use serde::Serialize;

/// Encodes a JWT using the provided header, claims, payload, and algorithm.
pub fn encode_jwt<T, A>(
    header: &JoseHeader,
    claims: &JwtClaims,
    payload: &T,
    alg: &A,
) -> Result<String, JwtError>
where
    T: Serialize,
    A: JwAlg + JwSign,
{
    let header = header.clone().or(JoseHeader {
        alg: Some(A::alg().as_ref().to_string()),
        typ: Some("JWT".to_string()),
        ..Default::default()
    });

    let mut json_value = serde_json::to_value(&payload)?;

    if !claims.is_empty() {
        let Some(payload_object) = json_value.as_object_mut() else {
            return Err(JwtError::PayloadNotAnObject);
        };

        let mut claims_value = serde_json::to_value(&claims)?;
        let claims_object = claims_value
            .as_object_mut()
            .expect("This should always result in an object");

        payload_object.append(claims_object);
    }

    let bytes = serde_json::to_vec(&json_value)?;

    Ok(sign_compact(header, &bytes, alg)?)
}
