use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use elliptic_curve::bigint::BoxedUint;
use rsa::{PrivateKey, PublicKey};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde::{Deserialize, Serialize};
use crate::modules::params::rsa::RSAParamsError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RSAPrivateParams {
    pub n: String,
    pub e: String,
    pub d: String,
    pub p: String,
    pub q: String,
    pub dp: String,
    pub dq: String,
    pub qi: String,
}

impl RSAPrivateParams {
    /// Construct a new RSAPrivateParams from a PrivateKey.
    pub fn from_private_key(mut private_key: PrivateKey) -> Result<Self, RSAParamsError> {
        private_key
            .precompute()
            .map_err(|e| RSAParamsError::FailedToPrecompute(e))?;

        let n = BASE64_URL_SAFE_NO_PAD.encode(private_key.n_bytes());
        let e = BASE64_URL_SAFE_NO_PAD.encode(private_key.e_bytes());
        let d = BASE64_URL_SAFE_NO_PAD.encode(private_key.d().to_be_bytes());
        let p = BASE64_URL_SAFE_NO_PAD.encode(
            private_key
                .p()
                .ok_or(RSAParamsError::MissingPrecompute)?
                .modulus()
                .to_be_bytes(),
        );

        let q = BASE64_URL_SAFE_NO_PAD.encode(
            private_key
                .q()
                .ok_or(RSAParamsError::MissingPrecompute)?
                .modulus()
                .to_be_bytes(),
        );

        let dp = BASE64_URL_SAFE_NO_PAD.encode(
            private_key
                .dp()
                .ok_or(RSAParamsError::MissingPrecompute)?
                .to_be_bytes(),
        );

        let dq = BASE64_URL_SAFE_NO_PAD.encode(
            private_key
                .dq()
                .ok_or(RSAParamsError::MissingPrecompute)?
                .to_be_bytes(),
        );

        let qi = BASE64_URL_SAFE_NO_PAD.encode(
            private_key
                .crt_coefficient()
                .ok_or(RSAParamsError::MissingPrecompute)?
                .to_be_bytes(),
        );

        Ok(RSAPrivateParams {
            n,
            e,
            d,
            p,
            q,
            dp,
            dq,
            qi,
        })
    }

    /// Returns a public key from the parameters.
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

    /// Returns a private key from the parameters and validates it against the `n`, `dp`, `dq`, and
    /// `qi` parameters.
    pub fn private_key(&self) -> Result<PrivateKey, RSAParamsError> {
        let n = BASE64_URL_SAFE_NO_PAD
            .decode(&self.n)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(RSAParamsError::FailedToBase64DecodeN)?
            .map_err(|e| RSAParamsError::FailedToRepresentN(rsa::Error::Decode(e)))?;

        let p = BASE64_URL_SAFE_NO_PAD
            .decode(&self.p)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(RSAParamsError::FailedToBase64DecodeP)?
            .map_err(|e| RSAParamsError::FailedToRepresentP(rsa::Error::Decode(e)))?;

        let q = BASE64_URL_SAFE_NO_PAD
            .decode(&self.q)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSAParamsError::FailedToBase64DecodeQ(e))?
            .map_err(|e| RSAParamsError::FailedToRepresentQ(rsa::Error::Decode(e)))?;

        let e = BASE64_URL_SAFE_NO_PAD
            .decode(&self.e)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSAParamsError::FailedToBase64DecodeE(e))?
            .map_err(|e| RSAParamsError::FailedToRepresentE(rsa::Error::Decode(e)))?;

        let dp = BASE64_URL_SAFE_NO_PAD
            .decode(&self.dp)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSAParamsError::FailedToBase64DecodeDP(e))?
            .map_err(|e| RSAParamsError::FailedToRepresentDP(rsa::Error::Decode(e)))?;

        let dq = BASE64_URL_SAFE_NO_PAD
            .decode(&self.dq)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSAParamsError::FailedToBase64DecodeDQ(e))?
            .map_err(|e| RSAParamsError::FailedToRepresentDQ(rsa::Error::Decode(e)))?;

        let qi = BASE64_URL_SAFE_NO_PAD
            .decode(&self.qi)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSAParamsError::FailedToBase64DecodeQI(e))?
            .map_err(|e| RSAParamsError::FailedToRepresentQI(rsa::Error::Decode(e)))?;

        let mut private_key = PrivateKey::from_p_q(p, q, e)
            .map_err(|e| RSAParamsError::FailedToCreatePrivateKeyFromParameters(e))?;

        private_key
            .precompute()
            .map_err(|e| RSAParamsError::FailedToPrecompute(e))?;

        if n != private_key.n().as_ref() {
            return Err(RSAParamsError::MismatchedN);
        }

        if dp != private_key.dp().ok_or(RSAParamsError::MissingPrecompute)? {
            return Err(RSAParamsError::MismatchedDP);
        }

        if dq != private_key.dq().ok_or(RSAParamsError::MissingPrecompute)? {
            return Err(RSAParamsError::MismatchedDQ);
        }

        if qi
            != private_key
            .crt_coefficient()
            .ok_or(RSAParamsError::MissingPrecompute)?
        {
            return Err(RSAParamsError::MismatchedQI);
        }

        Ok(private_key)
    }
}

impl TryFrom<PrivateKey> for RSAPrivateParams {
    type Error = RSAParamsError;

    fn try_from(value: PrivateKey) -> Result<Self, Self::Error> {
        Self::from_private_key(value)
    }
}