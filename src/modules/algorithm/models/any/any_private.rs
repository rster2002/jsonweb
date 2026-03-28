pub enum AnyPrivate {
    #[cfg(feature = "es256")]
    ES256Private(crate::algorithm::es::ES256Private),

    #[cfg(feature = "es384")]
    ES384Private(crate::algorithm::es::es384::ES384Private),

    #[cfg(feature = "hs256")]
    HS256Private(crate::algorithm::hs::HS256Private),

    #[cfg(feature = "rs256")]
    RS256Private(crate::algorithm::rs::RS256Private),

    #[cfg(feature = "rs384")]
    RS384Private(crate::algorithm::rs::RS384Private),

    #[cfg(feature = "rs512")]
    RS512Private(crate::algorithm::rs::RS512Private),
}