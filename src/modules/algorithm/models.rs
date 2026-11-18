mod private_enum_error;
mod public_enum_error;

pub mod set;

pub use private_enum_error::PrivateEnumError;
pub use public_enum_error::PublicEnumError;

pub mod none_algorithm;

#[cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]
pub mod hs;

#[cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]
pub mod rs;

#[cfg(any(feature = "es256", feature = "es384"))]
pub mod es;
