#[cfg(feature = "deflate")]
pub mod deflate_compression;

#[cfg(feature = "deflate")]
pub use deflate_compression::*;
