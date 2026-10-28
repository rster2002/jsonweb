use std::collections::HashMap;
use crate::algorithm::{JwAlg, JwAlgVerify, PartialJwAlg, PartialJwAlgVerify};

#[derive(Default)]
pub struct VerifierSet {
    verifiers: HashMap<String, Box<dyn JwAlgVerify<Error = dyn std::error::Error>>>,
}

impl VerifierSet {
    pub fn add<A>(&mut self, alg: A)
    where A : JwAlg + JwAlgVerify<Error = dyn std::error::Error> + 'static
    {
        self.verifiers.insert(A::alg().as_ref().to_string(), Box::new(alg));
    }
}

impl PartialJwAlg for VerifierSet {
    fn eq_alg(&self, alg: &str) -> bool {
        self.verifiers.contains_key(alg)
    }
}

impl PartialJwAlgVerify for VerifierSet {
    type Error = ();

    fn partial_verify(&self, alg: &str, payload: &[u8], signature: &[u8]) -> Option<Result<bool, Self::Error>> {
        todo!()
    }
}
