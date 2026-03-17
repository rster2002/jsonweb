mod models;
mod traits;

pub use models::none_algorithm::NoneAlgorithm;

#[cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]
use crate::algorithm::models::hs_algorithm::HSAlg;

#[cfg(feature = "hs256")]
pub type HS256Private = HSAlg<sha2::Sha256>;

#[cfg(feature = "hs384")]
pub type HS384Private = HSAlg<sha2::Sha384>;

#[cfg(feature = "hs512")]
pub type HS512Private = HSAlg<sha2::Sha512>;

#[cfg(feature = "rs256")]
pub use models::rs256_algorithm::rs256_public::RS256Public;
pub use models::rs256_algorithm::rs256_private::RS256Private;

#[cfg(any(feature = "es256", feature = "es384"))]
use crate::algorithm::models::es_algorithm::es_private::ESPrivate;

#[cfg(feature = "es256")]
pub type ES256Private = ESPrivate<p256::NistP256>;

#[cfg(feature = "es384")]
pub type ES384Private = ESPrivate<p384::NistP384>;

pub use traits::jw_alg_verify::JwAlgVerify;
pub use traits::jw_alg_sign::JwAlgSign;
pub use traits::jw_alg::JwAlg;
