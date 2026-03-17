pub mod none_algorithm;

#[cfg(any(feature = "hs256"))]
pub mod hs_algorithm;

#[cfg(feature = "rs256")]
pub mod rs256_algorithm;

#[cfg(any(feature = "es256", feature = "es384"))]
pub mod es_algorithm;