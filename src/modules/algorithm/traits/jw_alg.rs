use crate::algorithm::traits::partial_jw_alg::PartialJwAlg;

pub trait JwAlg: PartialJwAlg {
    fn alg() -> impl AsRef<str>;
}