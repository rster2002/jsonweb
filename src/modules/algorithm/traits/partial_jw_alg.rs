use crate::algorithm::JwAlg;

pub trait PartialJwAlg {
    /// Whether an algorithm is able to handle a given `alg` string.
    fn eq_alg(&self, alg: &str) -> bool;
}

impl<T> PartialJwAlg for T
where T : JwAlg
{
    fn eq_alg(&self, alg: &str) -> bool {
        T::alg().as_ref() == alg
    }
}