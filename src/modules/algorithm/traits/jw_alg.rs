use crate::algorithm::traits::handles_jw_alg::HandlesJwAlg;

pub trait JwAlg: HandlesJwAlg {
    fn alg() -> impl AsRef<str>;
}