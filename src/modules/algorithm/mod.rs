mod models;
mod traits;
mod algorithms;

pub use traits::jw_alg_verify::JwAlgVerify;
pub use traits::jw_alg_sign::JwAlgSign;
pub use traits::jw_alg::JwAlg;
pub use traits::partial_jw_alg::PartialJwAlg;

pub use models::none_algorithm::NoneAlgorithm;

#[cfg(any(feature = "es256", feature = "es384"))]
pub use models::es;

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
