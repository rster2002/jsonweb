use crate::modules::params::models::rsa::rsa_private_params::RSAPrivateParams;
use crate::modules::params::rsa::RSAParamsError;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use elliptic_curve::bigint::BoxedUint;
use rsa::PublicKey;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RSAPublicParams {
    pub n: String,
    pub e: String,
}

impl RSAPublicParams {
    /// Creates new parameters from a public key.
    pub fn from_public_key(public_key: PublicKey) -> Result<Self, RSAParamsError> {
        let n = BASE64_URL_SAFE_NO_PAD.encode(public_key.n().to_be_bytes());
        let e = BASE64_URL_SAFE_NO_PAD.encode(public_key.e_bytes());

        Ok(RSAPublicParams {
            n,
            e,
        })
    }

    /// Returns the public key corresponding to the given RSA public parameters.
    pub fn public_key(&self) -> Result<PublicKey, RSAParamsError> {
        let n = BASE64_URL_SAFE_NO_PAD
            .decode(&self.n)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSAParamsError::FailedToBase64DecodeN(e))?
            .map_err(|e| RSAParamsError::FailedToRepresentN(rsa::Error::Decode(e)))?;

        let e = BASE64_URL_SAFE_NO_PAD
            .decode(&self.e)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSAParamsError::FailedToBase64DecodeE(e))?
            .map_err(|e| RSAParamsError::FailedToRepresentE(rsa::Error::Decode(e)))?;

        let public_key = PublicKey::new(n, e)
            .map_err(|e| RSAParamsError::FailedToCreatePublicKeyFromParameters(e))?;

        Ok(public_key)
    }
}

impl TryFrom<PublicKey> for RSAPublicParams {
    type Error = RSAParamsError;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        RSAPublicParams::from_public_key(value)
    }
}

impl TryFrom<RSAPublicParams> for PublicKey {
    type Error = RSAParamsError;

    fn try_from(value: RSAPublicParams) -> Result<Self, Self::Error> {
        value.public_key()
    }
}

impl From<RSAPrivateParams> for RSAPublicParams {
    fn from(value: RSAPrivateParams) -> Self {
        RSAPublicParams {
            n: value.n,
            e: value.e,
        }
    }
}