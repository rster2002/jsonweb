pub mod rs_public;
pub mod rs_private;

#[cfg(feature = "rs256")]
mod rs256;

#[cfg(feature = "rs256")]
pub use rs256::*;

#[cfg(feature = "rs384")]
mod rs384;

#[cfg(feature = "rs384")]
pub use rs384::*;

#[cfg(feature = "rs512")]
pub mod rs512;
pub mod rs_private_params;
pub mod rs_public_params;

#[cfg(feature = "rs512")]
pub use rs512::*;