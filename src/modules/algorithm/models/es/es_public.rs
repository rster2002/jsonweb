use crate::algorithm::JwAlgVerify;
use ecdsa::elliptic_curve::CurveArithmetic;
use ecdsa::signature::Verifier;
use ecdsa::{EcdsaCurve, Signature, VerifyingKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ESPublic<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
{
    pub(crate) verifying_key: VerifyingKey<C>,
}

impl<C> JwAlgVerify for ESPublic<C>
where
    C: EcdsaCurve + CurveArithmetic + ecdsa::DigestAlgorithm,
{
    type Error = ecdsa::Error;

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let signature = match Signature::<C>::try_from(signature) {
            Ok(sig) => sig,
            Err(_) => return Ok(false),
        };

        Ok(self.verifying_key.verify(payload, &signature).is_ok())
    }
}
