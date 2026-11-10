use serde::de::DeserializeOwned;
use serde::Serialize;

/// Implement for algorithms that have private parameters.
pub trait JwkPrivateParams: TryFrom<Self::PrivateParams> + TryInto<Self::PrivateParams> {
    type PrivateParams: Serialize + DeserializeOwned;
}
