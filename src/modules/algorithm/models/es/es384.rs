use crate::algorithm::es::{ESError, ECPrivateParams, ECPublicParams};
use crate::algorithm::models::es::es_private::ESPrivate;
use crate::algorithm::models::es::es_public::ESPublic;
use crate::algorithm::JwAlg;
use crate::modules::key::{JwkPrivateParams, JwkPublicParams};

// Private
pub type ES384Private = ESPrivate<p384::NistP384>;

impl JwAlg for ES384Private {
    fn alg() -> impl AsRef<str> {
        "ES384"
    }
}

impl TryFrom<ECPrivateParams> for ES384Private {
    type Error = ESError;

    fn try_from(value: ECPrivateParams) -> Result<Self, Self::Error> {
        Self::from_private_parameters(value, "P-384")
    }
}

impl TryInto<ECPrivateParams> for ES384Private {
    type Error = ESError;

    fn try_into(self) -> Result<ECPrivateParams, Self::Error> {
        Self::into_private_parameters(&self.signing_key, "P-384")
    }
}

impl JwkPrivateParams for ES384Private {
    type PrivateParams = ECPrivateParams;
}

impl TryInto<ECPublicParams> for ES384Private {
    type Error = ESError;

    fn try_into(self) -> Result<ECPublicParams, Self::Error> {
        ESPublic::into_public_parameters(self.signing_key.verifying_key(), "P-384")
    }
}

impl JwkPublicParams for ES384Private {
    type PublicParams = ECPublicParams;
}

// Public
pub type ES384Public = ESPublic<p384::NistP384>;

impl JwAlg for ES384Public {
    fn alg() -> impl AsRef<str> {
        "ES384"
    }
}

impl TryFrom<ECPublicParams> for ES384Public {
    type Error = ESError;

    fn try_from(value: ECPublicParams) -> Result<Self, Self::Error> {
        Self::from_public_parameters(value, "P-384")
    }
}

impl TryInto<ECPublicParams> for ES384Public {
    type Error = ESError;

    fn try_into(self) -> Result<ECPublicParams, Self::Error> {
        Self::into_public_parameters(&self.verifying_key, "P-384")
    }
}

impl JwkPublicParams for ES384Public {
    type PublicParams = ECPublicParams;
}
