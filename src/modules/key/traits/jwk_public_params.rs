use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait JwkPublicParams: TryFrom<Self::PublicParams> + TryInto<Self::PublicParams> {
    type PublicParams: Serialize + DeserializeOwned;
}