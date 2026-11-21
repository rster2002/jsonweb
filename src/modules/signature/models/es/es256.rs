use crate::algorithm::JwAlg;
use crate::modules::key::{JwkPrivateParams, JwkPublicParams};
use crate::modules::params::ec::{ECPrivateParams, ECPublicParams};
use crate::modules::signature::es::{ESError, ESPrivate, ESPublic};

// Private
pub type ES256Private = ESPrivate<p256::NistP256>;

impl JwAlg for ES256Private {
    fn alg() -> impl AsRef<str> {
        "ES256"
    }
}

impl TryFrom<ECPrivateParams> for ES256Private {
    type Error = ESError;

    fn try_from(params: ECPrivateParams) -> Result<Self, Self::Error> {
        if params.crv != "P-256" {
            return Err(ESError::MismatchedCurve(params.crv, "P-256".to_string()));
        }

        Ok(ESPrivate::from(params.secret_key()?))
    }
}

impl TryInto<ECPrivateParams> for ES256Private {
    type Error = ESError;

    fn try_into(self) -> Result<ECPrivateParams, Self::Error> {
        Ok(ECPrivateParams::from_secret_key(&self.signing_key.into(), "P-256")?)
    }
}

impl TryInto<ECPublicParams> for ES256Private {
    type Error = ESError;

    fn try_into(self) -> Result<ECPublicParams, Self::Error> {
        Ok(ECPublicParams::from_public_key(&self.signing_key.verifying_key().into(), "P-256")?)
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

    fn try_from(params: ECPublicParams) -> Result<Self, Self::Error> {
        if params.crv != "P-256" {
            return Err(ESError::MismatchedCurve(params.crv, "P-256".to_string()));
        }

        Ok(ESPublic::from(params.public_key()?))
    }
}

impl TryInto<ECPublicParams> for ES256Public {
    type Error = ESError;

    fn try_into(self) -> Result<ECPublicParams, Self::Error> {
        Ok(ECPublicParams::from_public_key(&self.verifying_key.into(), "P-256")?)
    }
}

impl JwkPublicParams for ES256Public {
    type PublicParams = ECPublicParams;
}