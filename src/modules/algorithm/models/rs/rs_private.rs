use crate::algorithm::{JwAlgSign, JwAlgVerify};
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use const_oid::AssociatedOid;
use digest::Digest;
use rsa::signature::{SignatureEncoding, Signer};
use std::marker::PhantomData;

use crate::algorithm::rs::rs_private_params::RSPrivateParams;
use crate::modules::key::JwkPrivateParams;
use rsa::pkcs1::EncodeRsaPrivateKey;
#[cfg(feature = "pkcs1")]
use rsa::{Pkcs1v15Sign, PrivateKey};
use rsa::BoxedUint;

#[derive(Debug, Clone)]
pub struct RSPrivate<D>
where
    D: Digest + AssociatedOid,
{
    private_key: PrivateKey,
    _p: PhantomData<D>,
}

impl<D> RSPrivate<D>
where D: Digest + AssociatedOid,
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

    #[cfg(feature = "pkcs1")]
    pub fn to_pkcs1_der_bytes(&self) -> Result<Vec<u8>, rsa::Error> {
        Ok(self.private_key.to_pkcs1_der()?
            .to_bytes()
            .to_vec())
    }

    // #[cfg(feature = "pkcs1")]
    // pub fn from_pkcs1_der_bytes(bytes: &[u8]) -> Result<Self, rsa::Error> {
    //     Ok(RSPrivate::from(RS::from_pkcs1_der(bytes)?))
    // }
}

impl<D> JwAlgVerify for RSPrivate<D>
where D: Digest + AssociatedOid,
{
    type Error = rsa::signature::Error;

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let public_key = self.private_key.as_public_key();
        Ok(public_key.pkcs1v15_verify::<D>(payload, signature).is_ok())
    }
}

impl<D> JwAlgSign for RSPrivate<D>
where D: Digest + AssociatedOid,
{
    type Error = rsa::Error;
    
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, rsa::Error> {
        Ok(self.private_key.pkcs1v15_sign::<D>(payload)?.to_vec())
    }
}

impl<D> TryFrom<RSPrivateParams> for RSPrivate<D>
where
    D: AssociatedOid + Digest,
{
    type Error = ();

    fn try_from(value: RSPrivateParams) -> Result<Self, Self::Error> {
        let n = BASE64_URL_SAFE_NO_PAD.decode(value.n)
            .unwrap();

        let size = (n.len() / 2) * 8;

        let p = BASE64_URL_SAFE_NO_PAD.decode(value.p)
            .unwrap();

        let q = BASE64_URL_SAFE_NO_PAD.decode(value.q)
            .unwrap();

        let e = BASE64_URL_SAFE_NO_PAD.decode(value.e)
            .unwrap();

        let private_key = PrivateKey::from_p_q(
            BoxedUint::from_be_slice(&p, size as u32).unwrap(),
            BoxedUint::from_be_slice(&q, size as u32).unwrap(),
            BoxedUint::from_be_slice(&e, size as u32).unwrap(),
        )
            .unwrap();

        Ok(Self::from(private_key))
    }
}

impl<D> Into<RSPrivateParams> for RSPrivate<D>
where
    D: AssociatedOid + Digest,
{
    fn into(self) -> RSPrivateParams {
        todo!()
    }
}

impl<D> JwkPrivateParams for RSPrivate<D>
where D: Digest + AssociatedOid,
{
    type PrivateParams = RSPrivateParams;
}

impl<D> From<PrivateKey> for RSPrivate<D>
where D: Digest + AssociatedOid,
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

    #[test]
    fn rs_private_key_can_be_deserialized_from_jwk_params() {
        let private_components = RSPrivateParams {
            n: String::from("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"),
            e: String::from("AQAB"),
            d: String::from("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q"),
            p: String::from("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs"),
            q: String::from("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk"),
            dp: String::from("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0"),
            dq: String::from("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk"),
            qi: String::from("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU")
        };

        let key = RS256Private::try_from(private_components)
            .unwrap();
    }
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
