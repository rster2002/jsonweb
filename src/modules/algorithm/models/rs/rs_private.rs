use crate::algorithm::rs::rs_private_params::RSPrivateParams;
use crate::algorithm::{JwAlgSign, JwAlgVerify};
use crate::modules::key::{JwkPrivateParams, JwkType};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use const_oid::AssociatedOid;
use digest::Digest;
use rsa::BoxedUint;
use rsa::PrivateKey;
use std::marker::PhantomData;
use std::ops::Deref;

use crate::algorithm::rs::error::RSError;
#[cfg(feature = "pkcs1")]
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use crate::algorithm::rs::RSPublic;

#[derive(Debug, Clone)]
pub struct RSPrivate<D>
where
    D: Digest + AssociatedOid,
{
    pub(crate) private_key: PrivateKey,
    _p: PhantomData<D>,
}

impl<D> RSPrivate<D>
where
    D: Digest + AssociatedOid,
{
    // /// Create a new RSA private key using the default size of 4096 bits.
    // #[cfg(feature = "rand")]
    // pub fn rand() -> Result<Self, rsa::Error> {
    //     Self::rand_size(4096)
    // }

    // /// Create a new RSA private key with the provided size in bits.
    // #[cfg(feature = "rand")]
    // pub fn rand_size(size: usize) -> Result<Self, rsa::Error> {
    //     let mut rng = rand::thread_rng();
    //     // Ok(RSPrivate::from(SigningKey::random(&mut rng, size)?))
    // }

    // #[cfg(feature = "pkcs1")]
    // pub fn to_pkcs1_der_bytes(&self) -> Result<Vec<u8>, rsa::Error> {
    //     Ok(self.private_key.to_pkcs1_der()?.to_bytes().to_vec())
    // }

    // #[cfg(feature = "pkcs1")]
    // pub fn from_pkcs1_der_bytes(bytes: &[u8]) -> Result<Self, rsa::Error> {
    //     Ok(RSPrivate::from(RS::from_pkcs1_der(bytes)?))
    // }
}

impl<D> JwAlgVerify for RSPrivate<D>
where
    D: Digest + AssociatedOid,
{
    type Error = RSError;

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, RSError> {
        let public_key = self.private_key.as_public_key();

        match public_key.pkcs1v15_verify::<D>(payload, signature) {
            Ok(()) => Ok(true),
            Err(rsa::Error::Verification) => Ok(false),
            Err(error) => Err(RSError::FailedToVerify(error)),
        }
    }
}

impl<D> JwAlgSign for RSPrivate<D>
where
    D: Digest + AssociatedOid,
{
    type Error = RSError;

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, RSError> {
        Ok(self
            .private_key
            .pkcs1v15_sign::<D>(payload)
            .map_err(|e| RSError::FailedToSign(e))?
            .to_vec())
    }
}

impl<D> JwkType for RSPrivate<D>
where
    D: AssociatedOid + Digest,
{
    fn kty() -> impl AsRef<str> {
        "RSA"
    }
}

impl<D> JwkPrivateParams for RSPrivate<D>
where
    D: Digest + AssociatedOid,
{
    type PrivateParams = RSPrivateParams;
}

impl<D> TryFrom<RSPrivateParams> for RSPrivate<D>
where
    D: AssociatedOid + Digest,
{
    type Error = RSError;

    fn try_from(value: RSPrivateParams) -> Result<Self, RSError> {
        let n = BASE64_URL_SAFE_NO_PAD
            .decode(value.n)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSError::FailedToBase64DecodeN(e))?
            .map_err(|e| RSError::FailedToRepresentN(rsa::Error::Decode(e)))?;

        let p = BASE64_URL_SAFE_NO_PAD
            .decode(value.p)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSError::FailedToBase64DecodeP(e))?
            .map_err(|e| RSError::FailedToRepresentP(rsa::Error::Decode(e)))?;

        let q = BASE64_URL_SAFE_NO_PAD
            .decode(value.q)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSError::FailedToBase64DecodeQ(e))?
            .map_err(|e| RSError::FailedToRepresentQ(rsa::Error::Decode(e)))?;

        let e = BASE64_URL_SAFE_NO_PAD
            .decode(value.e)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSError::FailedToBase64DecodeE(e))?
            .map_err(|e| RSError::FailedToRepresentE(rsa::Error::Decode(e)))?;

        let dp = BASE64_URL_SAFE_NO_PAD
            .decode(value.dp)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSError::FailedToBase64DecodeDP(e))?
            .map_err(|e| RSError::FailedToRepresentDP(rsa::Error::Decode(e)))?;

        let dq = BASE64_URL_SAFE_NO_PAD
            .decode(value.dq)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSError::FailedToBase64DecodeDQ(e))?
            .map_err(|e| RSError::FailedToRepresentDQ(rsa::Error::Decode(e)))?;

        let qi = BASE64_URL_SAFE_NO_PAD
            .decode(value.qi)
            .map(|bytes| BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32))
            .map_err(|e| RSError::FailedToBase64DecodeQI(e))?
            .map_err(|e| RSError::FailedToRepresentQI(rsa::Error::Decode(e)))?;

        let mut private_key = PrivateKey::from_p_q(p, q, e)
            .map_err(|e| RSError::FailedToCreatePrivateKeyFromParameters(e))?;

        private_key
            .precompute()
            .map_err(|e| RSError::FailedToPrecompute(e))?;

        if n != private_key.n().as_ref() {
            return Err(RSError::MismatchedN);
        }

        if dp != private_key.dp().ok_or(RSError::MissingPrecompute)? {
            return Err(RSError::MismatchedDP);
        }

        if dq != private_key.dq().ok_or(RSError::MissingPrecompute)? {
            return Err(RSError::MismatchedDQ);
        }

        if qi
            != private_key
                .crt_coefficient()
                .ok_or(RSError::MissingPrecompute)?
        {
            return Err(RSError::MismatchedQI);
        }

        Ok(Self::from(private_key))
    }
}

impl<D> TryInto<RSPrivateParams> for RSPrivate<D>
where
    D: AssociatedOid + Digest,
{
    type Error = RSError;

    fn try_into(mut self) -> Result<RSPrivateParams, RSError> {
        self.private_key
            .precompute()
            .map_err(|e| RSError::FailedToPrecompute(e))?;

        let n = BASE64_URL_SAFE_NO_PAD.encode(self.private_key.n_bytes());
        let e = BASE64_URL_SAFE_NO_PAD.encode(self.private_key.e_bytes());
        let d = BASE64_URL_SAFE_NO_PAD.encode(self.private_key.d().to_be_bytes());
        let p = BASE64_URL_SAFE_NO_PAD.encode(
            self.private_key
                .p()
                .ok_or(RSError::MissingPrecompute)?
                .modulus()
                .to_be_bytes(),
        );

        let q = BASE64_URL_SAFE_NO_PAD.encode(
            self.private_key
                .q()
                .ok_or(RSError::MissingPrecompute)?
                .modulus()
                .to_be_bytes(),
        );

        let dp = BASE64_URL_SAFE_NO_PAD.encode(
            self.private_key
                .dp()
                .ok_or(RSError::MissingPrecompute)?
                .to_be_bytes(),
        );

        let dq = BASE64_URL_SAFE_NO_PAD.encode(
            self.private_key
                .dq()
                .ok_or(RSError::MissingPrecompute)?
                .to_be_bytes(),
        );

        let qi = BASE64_URL_SAFE_NO_PAD.encode(
            self.private_key
                .crt_coefficient()
                .ok_or(RSError::MissingPrecompute)?
                .to_be_bytes(),
        );

        Ok(RSPrivateParams {
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
}

impl<D> From<PrivateKey> for RSPrivate<D>
where
    D: Digest + AssociatedOid,
{
    fn from(key: PrivateKey) -> Self {
        Self {
            private_key: key.clone(),
            _p: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::rs::RS256Private;
    use crate::algorithm::rs::rs_private_params::RSPrivateParams;
    use crate::algorithm::{JwAlgSign, JwAlgVerify};

    fn rfc_7517_a_2_rsa_params() -> RSPrivateParams {
        // https://www.rfc-editor.org/info/rfc7517/#appendix-A.2
        RSPrivateParams {
            n: String::from(
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            ),
            e: String::from("AQAB"),
            d: String::from(
                "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
            ),
            p: String::from(
                "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
            ),
            q: String::from(
                "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
            ),
            dp: String::from(
                "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
            ),
            dq: String::from(
                "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
            ),
            qi: String::from(
                "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
            ),
        }
    }

    #[test]
    fn rs_private_key_can_be_deserialized_from_jwk_params() {
        let private_components = rfc_7517_a_2_rsa_params();

        let key = RS256Private::try_from(private_components).unwrap();
        let signature = key.sign(b"something").unwrap();

        key.verify(b"something", &signature).unwrap();
    }

    #[test]
    fn rs_private_key_can_be_serialized_to_jwk_params() {
        let private_components = rfc_7517_a_2_rsa_params();

        let key = RS256Private::try_from(private_components).unwrap();
        let jwk_params: RSPrivateParams = key.try_into().unwrap();

        assert_eq!(rfc_7517_a_2_rsa_params(), jwk_params);
    }

    // TODO malformed key check tests.
}

// #[cfg(all(test, feature = "pkcs1"))]
// mod tests2 {
//     use crate::algorithm::{JwAlgSign, JwAlgVerify};
//     use base64::Engine;
//     use base64::prelude::BASE64_URL_SAFE_NO_PAD;
//     pub use rsa::RsaPrivateKey;
//     use crate::algorithm::rs::RS256Private;
//
//     #[test]
//     fn rs256_algorithm_works_as_expected() {
//         let payload = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJoaiI6dHJ1ZX0";
//
//         let private_key = RsaPrivateKey::from_pkcs1_pem(include_str!("../../../../../test-files/rs256.key")).unwrap();
//         let alg = RS256Private::from(private_key);
//
//         let signature_bytes = alg.sign(payload);
//         let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature_bytes);
//
//         assert_eq!(signature_string, "ptH8Vc-nhm4gTl7HqaictKQyK3fxiJmSfyu-ouYlmIfyyRBIYw2tUdKxIsxgYMPXC7oV0-ShYtlUm73-q2buLoYGc52d-03RQghcVvZrag2nQCKsBBmTXFUADEaVopO65aND5h7Uif_1aQJXmX-40-V5te0fT3WSyU_1oKayxpi53_c7RXD7gDlWSXAZFDNhPopcRnq2_4FQylzFf4qbwtGWUNdJA4SGOikr1lsTrQRPGXLNXREG0PWv9GFoobQDTj9DWBG4B_cCAUVAjYUCx8BbgHSY9jeiYE_FbDykW0tRSA3XAYpf1QCPZmrCPButUixWY03FTTxsQxlJuY8r-w");
//
//         let verify = alg.verify(payload, &signature_bytes).unwrap();
//
//         assert!(verify);
//     }
// }
