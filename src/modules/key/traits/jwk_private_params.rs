use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait JwkPrivateParams: TryFrom<Self::PrivateParams> + TryInto<Self::PrivateParams> {
    type PrivateParams: Serialize + DeserializeOwned;
}
