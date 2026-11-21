mod hs_private;

pub use hs_private::HSPrivate;

#[cfg(feature = "rand")]
use rand::RngCore;

#[cfg(feature = "hs256")]
mod hs256;
mod error;

#[cfg(feature = "hs256")]
pub use hs256::HS256Private;
