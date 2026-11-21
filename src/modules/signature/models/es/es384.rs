use crate::algorithm::JwAlg;
use crate::modules::key::{JwkPrivateParams, JwkPublicParams};
use crate::modules::params::ec::{ECPrivateParams, ECPublicParams};
use crate::modules::signature::es::{ESError, ESPrivate, ESPublic};

// Private
pub type ES384Private = ESPrivate<p384::NistP384>;

impl JwAlg for ES384Private {
    fn alg() -> impl AsRef<str> {
        "ES384"
    }
}

impl TryFrom<ECPrivateParams> for ES384Private {
    type Error = ESError;

    fn try_from(params: ECPrivateParams) -> Result<Self, Self::Error> {
        if params.crv != "P-384" {
            return Err(ESError::MismatchedCurve(params.crv, "P-384".to_string()));
        }

        Ok(ESPrivate::from(params.secret_key()?))
    }
}

impl TryInto<ECPrivateParams> for ES384Private {
    type Error = ESError;

    fn try_into(self) -> Result<ECPrivateParams, Self::Error> {
        Ok(ECPrivateParams::from_secret_key(&self.signing_key.into(), "P-384")?)
    }
}

impl JwkPrivateParams for ES384Private {
    type PrivateParams = ECPrivateParams;
}

impl TryInto<ECPublicParams> for ES384Private {
    type Error = ESError;

    fn try_into(self) -> Result<ECPublicParams, Self::Error> {
        Ok(ECPublicParams::from_public_key(&self.signing_key.verifying_key().into(), "P-384")?)
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

    fn try_from(params: ECPublicParams) -> Result<Self, Self::Error> {
        if params.crv != "P-384" {
            return Err(ESError::MismatchedCurve(params.crv, "P-384".to_string()));
        }

        Ok(ESPublic::from(params.public_key()?))
    }
}

impl TryInto<ECPublicParams> for ES384Public {
    type Error = ESError;

    fn try_into(self) -> Result<ECPublicParams, Self::Error> {
        Ok(ECPublicParams::from_public_key(&self.verifying_key.into(), "P-384")?)
    }
}

impl JwkPublicParams for ES384Public {
    type PublicParams = ECPublicParams;
}
