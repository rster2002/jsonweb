use crate::modules::key::JwKeyType;

pub struct Jwk<'a, T>
where T : JwKeyType<'a>
{
    inner: &'a T,
}

impl<'a, T> Jwk<'a, T>
where T : JwKeyType<'a>
{
    pub fn new(inner: &'a T) -> Self {
        Self { inner }
    }
}
