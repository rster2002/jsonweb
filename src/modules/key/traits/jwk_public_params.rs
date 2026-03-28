use serde::{Deserialize, Serialize};

pub trait JwkPublicParams<'a> {
    type PublicParams: Serialize + Deserialize<'a>;

    fn get_public_params(&self) -> Option<Self::PublicParams>;
}