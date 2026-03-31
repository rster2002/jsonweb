use crate::algorithm::any::any_error::AnyError;
use crate::algorithm::JwAlgVerify;

#[derive(Debug, Clone)]
pub enum AnyPublic {
    #[cfg(feature = "es256")]
    ES256Public(crate::algorithm::es::ES256Public),

    #[cfg(feature = "es384")]
    ES384Public(crate::algorithm::es::es384::ES384Public),

    #[cfg(feature = "rs256")]
    RS256Public(crate::algorithm::rs::RS256Public),

    #[cfg(feature = "rs384")]
    RS384Public(crate::algorithm::rs::RS384Public),

    #[cfg(feature = "rs512")]
    RS512Public(crate::algorithm::rs::RS512Public),
}

impl JwAlgVerify for AnyPublic {
    type Error = AnyError;

    fn verify(&self, payload: &str, signature: &[u8]) -> Result<bool, Self::Error> {
        Ok(match self {
            #[cfg(feature = "es256")]
            AnyPublic::ES256Public(inner) => inner.verify(payload, signature)?,

            #[cfg(feature = "es384")]
            AnyPublic::ES384Public(inner) => inner.verify(payload, signature)?,

            #[cfg(feature = "rs256")]
            AnyPublic::RS256Public(inner) => inner.verify(payload, signature)?,

            #[cfg(feature = "rs384")]
            AnyPublic::RS384Public(inner) => inner.verify(payload, signature)?,

            #[cfg(feature = "rs512")]
            AnyPublic::RS512Public(inner) => inner.verify(payload, signature)?,

            _ => false,
        })
    }
}
