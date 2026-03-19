mod models;
mod traits;
mod algorithms;

pub use traits::jw_alg_verify::JwAlgVerify;
pub use traits::jw_alg_sign::JwAlgSign;
pub use traits::jw_alg::JwAlg;
pub use traits::partial_jw_alg::PartialJwAlg;

pub use models::none_algorithm::NoneAlgorithm;

// ES
#[cfg(any(feature = "es256", feature = "es384"))]
use crate::algorithm::models::es_algorithm::es_private::ESPrivate;

#[cfg(any(feature = "es256", feature = "es384"))]
use crate::algorithm::models::es_algorithm::es_public::ESPublic;

#[cfg(feature = "es256")]
pub type ES256Private = ESPrivate<p256::NistP256>;

#[cfg(feature = "es256")]
pub type ES256Public = ESPublic<p256::NistP256>;

#[cfg(feature = "es384")]
pub type ES384Private = ESPrivate<p384::NistP384>;

#[cfg(feature = "es384")]
pub type ES384Public = ESPublic<p384::NistP384>;

// HS
#[cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]
use crate::algorithm::models::hs_algorithm::HSPrivate;

#[cfg(feature = "hs256")]
pub type HS256Private = HSPrivate<sha2::Sha256>;

#[cfg(feature = "hs384")]
pub type HS384Private = HSPrivate<sha2::Sha384>;

#[cfg(feature = "hs512")]
pub type HS512Private = HSPrivate<sha2::Sha512>;

// RS
#[cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]
use crate::algorithm::models::rs_algorithm::rs_private::RSPrivate;

#[cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]
use crate::algorithm::models::rs_algorithm::rs_public::RSPublic;

#[cfg(feature = "rs256")]
pub type RS256Private = RSPrivate<sha2::Sha256>;

#[cfg(feature = "rs256")]
pub type RS256Public = RSPublic<sha2::Sha256>;

#[cfg(feature = "rs384")]
pub type RS384Private = RSPrivate<sha2::Sha384>;

#[cfg(feature = "rs384")]
pub type RS384Public = RSPublic<sha2::Sha384>;

#[cfg(feature = "rs512")]
pub type RS512Private = RSPrivate<sha2::Sha512>;

#[cfg(feature = "rs512")]
pub type RS512Public = RSPublic<sha2::Sha512>;
