use crate::algorithm::JwAlg;

pub trait HandlesJwAlg {
    /// Whether an algorithm is able to handle a given `alg` string.
    fn handles_alg(&self, alg: &str) -> bool;
}

impl<T> HandlesJwAlg for T
where T : JwAlg
{
    fn handles_alg(&self, alg: &str) -> bool {
        T::alg().as_ref() == alg
    }
}