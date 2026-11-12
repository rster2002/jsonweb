use serde::de::DeserializeOwned;
use serde::Serialize;
use crate::modules::key::JwkType;

/// Implement for algorithms that have public parameters. Symmetric algorithms MUST NOT implement
/// this trait.
pub trait JwkPublicParams: JwkType + TryFrom<Self::PublicParams> + TryInto<Self::PublicParams> {
    type PublicParams: Serialize + DeserializeOwned;
}