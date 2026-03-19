use serde::{Deserialize, Serialize};

pub trait JwkPrivateParams<'a> {
    type PrivateParams: Serialize + Deserialize<'a>;
    
    fn get_private_params(&self) -> Self::PrivateParams;
}