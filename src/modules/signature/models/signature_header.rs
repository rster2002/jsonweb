use std::borrow::Cow;
use serde::{Deserialize, Serialize};
use crate::algorithm::{JwAlg, JwAlgSign};

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureHeader<'a> {
    pub alg: Cow<'a, str>,
    pub jku: Option<Cow<'a, str>>,
    pub jwk: Option<Cow<'a, str>>,
    pub kid: Option<Cow<'a, str>>,
    pub x5u: Option<Cow<'a, str>>,
    pub x5c: Option<Cow<'a, str>>,
    pub x5t: Option<Cow<'a, str>>,

    #[serde(rename = "x5t#S256")]
    pub x5t_s256: Option<Cow<'a, str>>,
    pub typ: Option<Cow<'a, str>>,
    pub cty: Option<Cow<'a, str>>,

    // TODO
    pub crit: Option<Cow<'a, [Cow<'a, str>]>>,
}

impl<'a> From<&'a str> for SignatureHeader<'a> {
    fn from(alg: &'a str) -> Self {
        SignatureHeader {
            alg: alg.into(),
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
        }
    }
}

impl From<String> for SignatureHeader<'_> {
    fn from(value: String) -> Self {
        SignatureHeader {
            alg: value.into(),
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
        }
    }
}

impl<A> From<&A> for SignatureHeader<'_>
where A : JwAlg + JwAlgSign
{
    fn from(_value: &A) -> Self {
        SignatureHeader::from(A::alg().as_ref().to_string())
    }
}