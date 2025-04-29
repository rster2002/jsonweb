use serde::{Deserialize, Serialize};

pub trait JwKeyType<'a> {
    type Public: Serialize + Deserialize<'a>;
    type Private: Serialize + Deserialize<'a>;
    
    fn kty() -> impl AsRef<str>;
    fn public_params(&self) -> Self::Public;
    fn private_parameters(&self) -> Option<Self::Private> {
        None
    }
}
