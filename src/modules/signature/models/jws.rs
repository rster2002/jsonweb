use std::borrow::Cow;
use crate::algorithm::{JwAlg, JwAlgSign};
use crate::modules::signature::models::signature_header::SignatureHeader;

pub struct Jws<'a> {
    payload: &'a [u8],
}

impl Jws<'_> {
    pub fn new(payload: &[u8]) -> Jws<'_> {
        Jws {
            payload
        }
    }

    pub fn sign_compact<A: JwAlg + JwAlgSign>(&self, algorithm: &A) -> String {
        let header = SignatureHeader {
            alg: Cow::Borrowed(A::alg().as_ref()),
            jku: None,
            jwk: None,
            kid: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            typ: None,
            cty: None,
            crit: None,
        };
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::hs::HS256Private;
    use crate::modules::signature::models::jws::Jws;

    fn jws_example_hmac_sha256() {
        let algorithm = HS256Private::new("abc".as_bytes())
            .unwrap();

        let jws = Jws::new(b"Hello world")
            .
            .sign_compact(&algorithm);
        //
        // let jws = Jws::compact(&algorithm, b"Hello world");
    }
}