#[macro_export]
macro_rules! private_alg_set {
    ($i:ident, $($j:ident),+ $(,)?) => {
        pastey::paste! {
            enum $i {
                $($j($j),)+
            }
            
            #[derive(serde::Serialize, serde::Deserialize)]
            #[serde(untagged)]
            enum [< $i Params >] {
                $($j(<$j as crate::key::JwkPrivateParams>::PrivateParams),)+
            }

            impl crate::key::JwkPrivateParams for $i {
                type PrivateParams = [< $i Params >];
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
                type Error = crate::algorithm::PrivateSetError;

                fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, crate::algorithm::PrivateSetError> {
                    match self {
                        $($i::$j(v) => v.verify(payload, signature).map_err(|_| crate::algorithm::PrivateSetError::FailedToVerify),)+
                    }
                }
            }

            impl crate::algorithm::JwAlgSign for $i {
                type Error = crate::algorithm::PrivateSetError;

                fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, crate::algorithm::PrivateSetError> {
                    match self {
                        $($i::$j(v) => v.sign(payload).map_err(|_| crate::algorithm::PrivateSetError::FailedToSign),)+
                    }
                }
            }

            impl TryFrom<[< $i Params >]> for $i {
                type Error = ();

                fn try_from(value: [< $i Params >]) -> Result<$i, ()> {
                    Ok(match value {
                        $([< $i Params >]::$j(v) => $i::$j($j::try_from(v).map_err(|_| ())?),)+
                    })
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use crate::algorithm::es::ES256Private;
    use crate::algorithm::JwAlgSign;
    use crate::algorithm::rs::{RS256Private};
    use crate::key::Jwk;

    private_alg_set!(MySet, RS256Private, ES256Private);

    #[test]
    fn rsa_key_can_be_extracted() {
        let private_key = json!({
            "kty":"RSA",
            "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e":"AQAB",
            "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
            "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
            "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
            "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
            "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
            "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
            "alg":"RS256",
            "kid":"2011-04-29"
        });

        let jwk = Jwk::try_from(private_key).unwrap();
        let alg: MySet = jwk.to_private().unwrap();

        let signature = alg.sign(b"Hello world");
        assert!(signature.is_ok());
    }

    #[test]
    fn es_key_can_be_extracted() {
        let private_key = json!({
            "kty":"EC",
            "alg":"ES256",
            "crv": "P-256",
            "x": "Q5PISQVZ7LMwDNrjCNUcPLR45-zArUIqVazbscbLZ5Y",
            "y": "cum17-MtTGX2X7yrI0tvp0Xl9NVEmHUuotAwyJHOv7I",
            "d": "3XAy6ko-fegKfkV5uE5nKY4wTncjvFMYTJM0uh4rj8E",
        });

        let jwk = Jwk::try_from(private_key).unwrap();
        let alg: MySet = jwk.to_private().unwrap();

        let signature = alg.sign(b"Hello world");
        assert!(signature.is_ok());
    }
}