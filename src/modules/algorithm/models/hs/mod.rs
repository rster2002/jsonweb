mod hs_private;

pub use hs_private::HSPrivate;
pub use crate::modules::params::models::oct::oct_private_params::OctPrivateParams;

#[cfg(feature = "rand")]
use rand::RngCore;

#[cfg(feature = "hs256")]
mod hs256;
mod error;

#[cfg(feature = "hs256")]
pub use hs256::HS256Private;
