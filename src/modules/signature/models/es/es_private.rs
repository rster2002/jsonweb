
use crate::modules::key::JwkType;
use crate::modules::signature::es::ESError;
use ecdsa::elliptic_curve::CurveArithmetic;
use ecdsa::signature::{Signer, Verifier};
use ecdsa::{EcdsaCurve, Signature, SigningKey};
use elliptic_curve::SecretKey;
use std::convert::Infallible;
use crate::modules::signature::{JwSign, JwVerify};

#[derive(Debug, Clone)]
pub struct ESPrivate<C>
where
    C: CurveArithmetic + EcdsaCurve + ecdsa::DigestAlgorithm,
// AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
// FieldBytesSize<C>: sec1::ModulusSize,
{
    pub(crate) signing_key: SigningKey<C>,
}

impl<C> JwVerify for ESPrivate<C>
where
    C: CurveArithmetic + EcdsaCurve + ecdsa::DigestAlgorithm,
{
    type Error = ESError;

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let verifying_key = self.signing_key.verifying_key();
        let signature = Signature::try_from(signature).map_err(|_| ESError::MalformedSignature)?;
        let verification = verifying_key.verify(payload, &signature);

        Ok(verification.is_ok())
    }
}

impl<C> JwSign for ESPrivate<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
{
    type Error = Infallible;

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, <Self as JwSign>::Error> {
        let signature: Signature<C> = Signer::sign(&self.signing_key, payload);
        Ok(signature.to_vec())
    }
}

impl<C> JwkType for ESPrivate<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
{
    fn kty() -> impl AsRef<str> {
        "EC"
    }
}

impl<C> From<SecretKey<C>> for ESPrivate<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
{
    fn from(key: SecretKey<C>) -> Self {
        ESPrivate { signing_key: SigningKey::from(key) }
    }
}

impl<C> From<SigningKey<C>> for ESPrivate<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
{
    fn from(key: SigningKey<C>) -> Self {
        ESPrivate { signing_key: key }
    }
}

#[cfg(test)]
mod tests {
    use crate::modules::params::ec::ECPrivateParams;
    use crate::modules::signature::es::ES256Private;
    use crate::modules::signature::{JwSign, JwVerify};

    #[test]
    fn inner_from_params_works() {
        let a = ES256Private::try_from(
            ECPrivateParams {
                crv: "P-256".to_string(),
                x: "Q5PISQVZ7LMwDNrjCNUcPLR45-zArUIqVazbscbLZ5Y".to_string(),
                y: "cum17-MtTGX2X7yrI0tvp0Xl9NVEmHUuotAwyJHOv7I".to_string(),
                d: "3XAy6ko-fegKfkV5uE5nKY4wTncjvFMYTJM0uh4rj8E".to_string(),
            },
        )
            .expect("To have been generated");

        let signature = a.sign(b"Hello world")
            .expect("infallible");

        let correct = a.verify(b"Hello world", &signature)
            .expect("To have been verified");

        assert!(correct);
    }

    // #[test]
    // #[cfg(feature = "rand")]
    // fn es256_can_be_generated_randomly() {
    //     ES256Private::rand();
    // }
    //
    // #[test]
    // #[cfg(feature = "rand")]
    // fn es256_to_and_from_bytes() {
    //     let alg = ES256Private::rand();
    //     let bytes = alg.to_bytes();
    //
    //     let alg2 = ES256Private::from_bytes(&bytes).unwrap();
    //     assert_eq!(alg.0, alg2.0);
    // }
}
