use crate::algorithm::es::{ESError, ESPrivateParams, ESPublic, ESPublicParams};
use crate::algorithm::models::es::es_private::ESPrivate;
use crate::algorithm::JwAlg;
use crate::modules::key::{JwkPrivateParams, JwkPublicParams};

// Private
pub type ES256Private = ESPrivate<p256::NistP256>;

impl JwAlg for ES256Private {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

impl TryFrom<ESPrivateParams> for ES256Private {
    type Error = ESError;

    fn try_from(value: ESPrivateParams) -> Result<Self, Self::Error> {
        Self::from_private_parameters(value, "P-256")
    }
}

impl TryInto<ESPrivateParams> for ES256Private {
    type Error = ESError;

    fn try_into(self) -> Result<ESPrivateParams, Self::Error> {
        Self::into_private_parameters(&self.signing_key, "P-256")
    }
}

impl JwkPrivateParams for ES256Private {
    type PrivateParams = ESPrivateParams;
}

// Public
pub type ES256Public = ESPublic<p256::NistP256>;

impl JwAlg for ES256Public {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

impl TryFrom<ESPublicParams> for ES256Public {
    type Error = ESError;

    fn try_from(value: ESPublicParams) -> Result<Self, Self::Error> {
        Self::from_public_parameters(value, "P-256")
    }
}

impl TryInto<ESPublicParams> for ES256Public {
    type Error = ESError;

    fn try_into(self) -> Result<ESPublicParams, Self::Error> {
        Self::into_public_parameters(&self.verifying_key, "P-256")
    }
}

impl JwkPublicParams for ES256Public {
    type PublicParams = ESPublicParams;
}