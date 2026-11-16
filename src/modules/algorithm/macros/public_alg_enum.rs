#[macro_export]
/// Creates an enum covering all the public algorithms and their parameters.
macro_rules! public_alg_enum {
    ($i:ident, $($j:ident),+ $(,)?) => {
        pastey::paste! {
            enum $i {
                $($j($j),)+
            }

            #[derive(serde::Serialize, serde::Deserialize)]
            #[serde(untagged)]
            enum [< $i Params >] {
                $($j(<$j as crate::key::JwkPublicParams>::PublicParams),)+
            }

            impl crate::key::JwkPublicParams for $i {
                type PublicParams = [< $i Params >];
            }

            impl crate::algorithm::PartialJwAlg for $i {
                fn eq_alg(&self, alg: &str) -> bool {
                    $(
                        if alg == <$j as crate::algorithm::JwAlg>::alg().as_ref() {
                            return true;
                        }
                    )+

                    false
                }
            }

            impl crate::algorithm::JwAlgVerify for $i {
                type Error = crate::algorithm::PublicSetError;

                fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, crate::algorithm::PublicSetError> {
                    match self {
                        $($i::$j(v) => v.verify(payload, signature).map_err(|_| crate::algorithm::PublicSetError::FailedToVerify),)+
                    }
                }
            }

            impl TryFrom<[< $i Params >]> for $i {
                type Error = crate::algorithm::PublicSetError;

                fn try_from(value: [< $i Params >]) -> Result<$i, Self::Error> {
                    Ok(match value {
                        $([< $i Params >]::$j(v) => $i::$j($j::try_from(v).map_err(|e| crate::algorithm::PublicSetError::FailedToParse(e.to_string()))?),)+
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::algorithm::es::ES256Public;
    use crate::algorithm::rs::RS256Public;

    public_alg_enum!(TestAlgSet, RS256Public, ES256Public);
}