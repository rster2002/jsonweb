use serde::{Deserialize, Serialize};

pub trait JwKeyType<'a> {
    type Params: Serialize + Deserialize<'a>;

    fn kty() -> impl AsRef<str>;
    fn parms(&self) -> Self::Params;
}
