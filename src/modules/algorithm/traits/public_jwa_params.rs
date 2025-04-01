use serde::de::DeserializeOwned;
use serde::Serialize;

pub trait PublicJwaParams {
    type Params: Serialize + DeserializeOwned;

    fn public_params(&self) -> Self::Params;
}
