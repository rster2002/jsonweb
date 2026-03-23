pub mod none_algorithm;

#[cfg(any(feature = "hs256", feature = "hs384", feature = "hs512"))]
pub mod hs_algorithm;

#[cfg(any(feature = "rs256", feature = "rs384", feature = "rs512"))]
pub mod rs_algorithm;

#[cfg(any(feature = "es256", feature = "es384"))]
pub mod es;