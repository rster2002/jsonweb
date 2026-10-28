use std::borrow::Cow;
use bon::Builder;
use serde::{Deserialize, Serialize};
use crate::algorithm::JwAlg;

#[derive(Debug, Serialize, Deserialize, Default, Builder)]
pub struct JoseHeader {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    #[serde(rename = "x5t#S256")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,

    // TODO
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
}

impl JoseHeader {
    pub fn or(self, other: JoseHeader) -> JoseHeader {
        JoseHeader {
            alg: self.alg.or(other.alg),
            jku: self.jku.or(other.jku),
            jwk: self.jwk.or(other.jwk),
            kid: self.kid.or(other.kid),
            x5u: self.x5u.or(other.x5u),
            x5c: self.x5c.or(other.x5c),
            x5t: self.x5t.or(other.x5t),
            x5t_s256: self.x5t_s256.or(other.x5t_s256),
            typ: self.typ.or(other.typ),
            cty: self.cty.or(other.cty),
            crit: self.crit.or(other.crit),
        }
    }
}

impl<A> From<&A> for JoseHeader
where A : JwAlg
{
    fn from(_: &A) -> Self {
        JoseHeader {
            alg: Some(A::alg().as_ref().to_string()),
            ..Default::default()
        }
    }
}