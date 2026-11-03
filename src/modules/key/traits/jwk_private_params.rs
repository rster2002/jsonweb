use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

pub trait JwkPrivateParams: TryFrom<Self::PrivateParams> + Into<Self::PrivateParams> {
    type PrivateParams: Serialize + DeserializeOwned;
}
