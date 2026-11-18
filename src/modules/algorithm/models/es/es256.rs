use crate::algorithm::es::{ESError, ESPublic};
use crate::algorithm::models::es::es_private::ESPrivate;
use crate::algorithm::JwAlg;
use crate::modules::key::{JwkPrivateParams, JwkPublicParams};
use crate::modules::params::ec::{ECPrivateParams, ECPublicParams};

// Private
pub type ES256Private = ESPrivate<p256::NistP256>;

impl JwAlg for ES256Private {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

impl TryFrom<ECPrivateParams> for ES256Private {
    type Error = ESError;

    fn try_from(value: ECPrivateParams) -> Result<Self, Self::Error> {
        Self::from_private_parameters(value, "P-256")
    }
}

impl TryInto<ECPrivateParams> for ES256Private {
    type Error = ESError;

    fn try_into(self) -> Result<ECPrivateParams, Self::Error> {
        Self::into_private_parameters(&self.signing_key, "P-256")
    }
}

impl TryInto<ECPublicParams> for ES256Private {
    type Error = ESError;

    fn try_into(self) -> Result<ECPublicParams, Self::Error> {
        ESPublic::into_public_parameters(self.signing_key.verifying_key(), "P-256")
    }
}

impl JwkPrivateParams for ES256Private {
    type PrivateParams = ECPrivateParams;
}

impl JwkPublicParams for ES256Private {
    type PublicParams = ECPublicParams;
}

// Public
pub type ES256Public = ESPublic<p256::NistP256>;

impl JwAlg for ES256Public {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

impl TryFrom<ECPublicParams> for ES256Public {
    type Error = ESError;

    fn try_from(value: ECPublicParams) -> Result<Self, Self::Error> {
        Self::from_public_parameters(value, "P-256")
    }
}

impl TryInto<ECPublicParams> for ES256Public {
    type Error = ESError;

    fn try_into(self) -> Result<ECPublicParams, Self::Error> {
        Self::into_public_parameters(&self.verifying_key, "P-256")
    }
}

impl JwkPublicParams for ES256Public {
    type PublicParams = ECPublicParams;
}