use serde::de::DeserializeOwned;
use serde::Serialize;

/// Implement for algorithms that have public parameters. Symmetric algorithms MUST NOT implement
/// this trait.
pub trait JwkPublicParams: TryFrom<Self::PublicParams> + TryInto<Self::PublicParams> {
    type PublicParams: Serialize + DeserializeOwned;
}