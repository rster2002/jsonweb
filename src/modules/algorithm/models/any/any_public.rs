use crate::algorithm::{HandlesJwAlg, JwAlgVerify, PartialJwAlgVerify};
use crate::algorithm::any::error::AnyError;

/// Represents a set of the same algorithm that can handle any of the provided algorithms.
pub struct AnyPublic<A>
where
    A: HandlesJwAlg + JwAlgVerify,
{
    algorithms: Vec<A>,
}

impl<A> HandlesJwAlg for AnyPublic<A>
where
    A: HandlesJwAlg + JwAlgVerify,
{
    fn handles_alg(&self, alg: &str) -> bool {
        self.algorithms.iter().any(|candidate| candidate.handles_alg(alg))
    }
}

impl<A> PartialJwAlgVerify for AnyPublic<A>
where
    A: HandlesJwAlg + JwAlgVerify,
{
    type Error = AnyError;

    fn partial_verify(
        &self,
        alg: &str,
        payload: &[u8],
        signature: &[u8],
    ) -> Option<Result<bool, Self::Error>> {
        let candidates = self.algorithms
            .iter()
            .filter(|candidate| candidate.handles_alg(alg));

        for candidate in candidates {
            match candidate.verify(payload, signature) {
                Ok(true) => return Some(Ok(true)),
                Err(err) => return Some(Err(AnyError::FailedToVerify(err.to_string()))),
                _ => {},
            }
        }

        None
    }
}
