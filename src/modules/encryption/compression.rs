mod none_compression;

pub use none_compression::*;

#[cfg(feature = "deflate")]
pub mod deflate_compression;

#[cfg(feature = "deflate")]
pub use deflate_compression::*;
