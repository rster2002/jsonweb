use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JwkParams {
    #[cfg(any(feature = "es256", feature = "es384"))]
    ESPrivateParams(crate::algorithm::es::ESPrivateParams),

    #[cfg(any(feature = "es256", feature = "es384"))]
    ESPublicParams(crate::algorithm::es::ESPublicParams),

    #[cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]
    RSPrivateParams(crate::algorithm::rs::rs_private_params::RSPrivateParams),

    #[cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]
    RSPublicParams(crate::algorithm::rs::rs_public_params::RSPublicParams),
}