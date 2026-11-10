mod error;
mod rs_public;
mod rs_private;
mod rs_private_params;
mod rs_public_params;

pub use rs_public::RSPublic;
pub use rs_private::RSPrivate;
pub use rs_private_params::RSPrivateParams;
pub use rs_public_params::RSPublicParams;

pub use error::RSError;

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

#[cfg(feature = "rs512")]
pub use rs512::*;