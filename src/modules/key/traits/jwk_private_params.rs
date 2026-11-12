use crate::modules::key::JwkType;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Implement for algorithms that have private parameters.
pub trait JwkPrivateParams: JwkType + TryFrom<Self::PrivateParams> + TryInto<Self::PrivateParams>
{
    type PrivateParams: Serialize + DeserializeOwned;
}
