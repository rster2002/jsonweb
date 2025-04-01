use serde::de::DeserializeOwned;
use serde::Serialize;
use crate::algorithm::traits::public_jwa_params::PublicJwaParams;

pub trait PrivateJwaParams: PublicJwaParams {
    type Params: Serialize + DeserializeOwned;
}
