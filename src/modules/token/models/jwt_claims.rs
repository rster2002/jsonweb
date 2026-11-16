use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use crate::token::JwtError;

/// Claims as defined in [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519). Should be included in
/// the payload of a JWT token to add context and control to the token.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct JwtClaims {
    /// From [RFC 7519 section 4.1.1](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1):
    /// The "iss" (issuer) claim identifies the principal that issued the JWT. The processing of
    /// this claim is generally application specific. The "iss" value is a case-sensitive string
    /// containing a StringOrURI value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// From [RFC 7519 section 4.1.2](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2):
    /// The "sub" (subject) claim identifies the principal that is the subject of the JWT. The
    /// claims in a JWT are normally statements about the subject. The subject value MUST either be
    /// scoped to be locally unique in the context of the issuer or be globally unique. The
    /// processing of this claim is generally application specific. The "sub" value is a
    /// case-sensitive string containing a StringOrURI value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// From [RFC 7519 section 4.1.3](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3):
    /// The "aud" (audience) claim identifies the recipients that the JWT is intended for. Each
    /// principal intended to process the JWT MUST identify itself with a value in the audience
    /// claim. If the principal processing the claim does not identify itself with a value in the
    /// "aud" claim when this claim is present, then the JWT MUST be rejected. In the general case,
    /// the "aud" value is an array of case-sensitive strings, each containing a StringOrURI value.
    /// In the special case when the JWT has one audience, the "aud" value MAY be a single
    /// case-sensitive string containing a StringOrURI value. The interpretation of audience values
    /// is generally application specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// From [RFC 7519 section 4.1.4](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4):
    /// The "exp" (expiration time) claim identifies the expiration time on or after which the JWT
    /// MUST NOT be accepted for processing. The processing of the "exp" claim requires that the
    /// current date/time MUST be before the expiration date/time listed in the "exp" claim.
    /// Implementers MAY provide for some small leeway, usually no more than a few minutes, to
    /// account for clock skew. Its value MUST be a number containing a NumericDate value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// From [RFC 7519 section 4.1.5](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5):
    /// The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted
    /// for processing. The processing of the "nbf" claim requires that the current date/time MUST
    /// be after or equal to the not-before date/time listed in the "nbf" claim. Implementers MAY
    /// provide for some small leeway, usually no more than a few minutes, to account for clock
    /// skew. Its value MUST be a number containing a NumericDate value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// From [RFC 7519 section 4.1.6](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6):
    /// The "iat" (issued at) claim identifies the time at which the JWT was issued. This claim can
    /// be used to determine the age of the JWT. Its value MUST be a number containing a NumericDate
    /// value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// From [RFC 7519 section 4.1.7](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7):
    /// The "jti" (JWT ID) claim provides a unique identifier for the JWT. The identifier value MUST
    /// be assigned in a manner that ensures that there is a negligible probability that the same
    /// value will be accidentally assigned to a different data object; if the application uses
    /// multiple issuers, collisions MUST be prevented among values produced by different issuers as
    /// well. The "jti" claim can be used to prevent the JWT from being replayed. The "jti" value is
    /// a case-sensitive string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl JwtClaims {
    /// Whether the claims are empty.
    pub fn is_empty(&self) -> bool {
        let any_set = self.iss.is_some()
            || self.sub.is_some()
            || self.aud.is_some()
            || self.exp.is_some()
            || self.nbf.is_some()
            || self.iat.is_some()
            || self.jti.is_some();

        !any_set
    }

    /// Create a new set of claims that fill `exp`, `nbf` and `iat` with the current timestamp.
    pub fn now() -> JwtClaims {
        let now_timestamp = Utc::now().timestamp();

        JwtClaims {
            iss: None,
            sub: None,
            aud: None,
            exp: Some(now_timestamp),
            nbf: Some(now_timestamp),
            iat: Some(now_timestamp),
            jti: None,
        }
    }

    /// Create a new set of claims that fill `nbf` and `iat` with the current timestamp, but not
    /// the `exp` claim.
    pub fn no_expiry() -> JwtClaims {
        let now_timestamp = Utc::now().timestamp();

        JwtClaims {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: Some(now_timestamp),
            iat: Some(now_timestamp),
            jti: None,
        }
    }

    /// Create a new set of claims that fill `nbf` and `exp` with a grace period in seconds. The
    /// grade pushes the `exp` time to `now + grace` and the `nbf` time to `now - grace`. The `iat`
    /// claim is always filled with the current timestamp.
    pub fn grace(grace: i64) -> JwtClaims {
        let now_timestamp = Utc::now().timestamp();

        JwtClaims {
            iss: None,
            sub: None,
            aud: None,
            exp: Some(now_timestamp + grace),
            nbf: Some(now_timestamp - grace),
            iat: Some(now_timestamp),
            jti: None,
        }
    }

    /// Set the `iss` claim and return `Self`.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.iss = Some(issuer.into());
        self
    }

    /// Set the `sub` claim and return `Self`.
    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.sub = Some(subject.into());
        self
    }

    /// Set the `aud` claim and return `Self`.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.aud = Some(audience.into());
        self
    }

    /// Set the `iat` claim to the given datetime and return `Self`.
    pub fn issued_at(mut self, issued_at: DateTime<Utc>) -> Self {
        self.iat = Some(issued_at.timestamp());
        self
    }

    /// Set the `iat` claim to the given timestamp in seconds since Epoch and return `Self`.
    pub fn issued_at_timestamp(mut self, timestamp: i64) -> Self {
        self.iat = Some(timestamp);
        self
    }

    /// Set the `exp` claim to `now + duration` and return `Self`.
    pub fn expire_in(mut self, duration: Duration) -> Self {
        self.exp = Some(Utc::now().timestamp() + duration.num_seconds());
        self
    }

    /// Set the `exp` claim to `now + seconds` and return `Self`.
    pub fn expire_in_seconds(mut self, seconds: i64) -> Self {
        self.exp = Some(Utc::now().timestamp() + seconds);
        self
    }

    /// Set the `exp` claim to the given datetime and return `Self`.
    pub fn expire_at(mut self, expire_at: DateTime<Utc>) -> Self {
        self.exp = Some(expire_at.timestamp());
        self
    }

    /// Set the `nbf` claim to `now + duration` and return `Self`.
    pub fn not_before(mut self, duration: Duration) -> Self {
        self.nbf = Some(Utc::now().timestamp() + duration.num_seconds());
        self
    }

    /// Set the `nbf` claim to `now + seconds` and return `Self`.
    pub fn not_before_seconds(mut self, seconds: i64) -> Self {
        self.nbf = Some(Utc::now().timestamp() + seconds);
        self
    }

    /// Set the `nbf` claim to the given datetime and return `Self`.
    pub fn not_before_at(mut self, not_before: DateTime<Utc>) -> Self {
        self.nbf = Some(not_before.timestamp());
        self
    }

    /// Set the `jti` claim to the given value and return `Self`.
    pub fn id(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    /// Returns a new `JwtClaims` struct with the values from `self` and `other` merged, only
    /// setting the values of `other` if the value for `self` is `Some`.
    pub fn and(self, other: JwtClaims) -> JwtClaims {
        JwtClaims {
            iss: self.iss.and(other.iss),
            sub: self.sub.and(other.sub),
            aud: self.aud.and(other.aud),
            exp: self.exp.and(other.exp),
            nbf: self.nbf.and(other.nbf),
            iat: self.iat.and(other.iat),
            jti: self.jti.and(other.jti),
        }
    }

    /// Returns a new `JwtClaims` struct with the values from `self` and `other` merged, preferring
    /// the values of `self`.
    pub fn or(self, other: JwtClaims) -> JwtClaims {
        JwtClaims {
            iss: self.iss.or(other.iss),
            sub: self.sub.or(other.sub),
            aud: self.aud.or(other.aud),
            exp: self.exp.or(other.exp),
            nbf: self.nbf.or(other.nbf),
            iat: self.iat.or(other.iat),
            jti: self.jti.or(other.jti),
        }
    }

    /// Verify the claims of `self` against the expected claims in `other`.
    pub fn verify(&self, other: &JwtClaims) -> Result<(), JwtError> {
        if let Some(expected) = &other.nbf {
            let Some(received) = &self.nbf else {
                return Err(JwtError::MissingNbfClaim);
            };

            if expected < received {
                return Err(JwtError::MismatchedNbfClaim);
            }
        }

        if let Some(expected) = &other.exp {
            let Some(received) = &self.exp else {
                return Err(JwtError::MissingExpClaim);
            };

            if expected > received {
                return Err(JwtError::MismatchedExpClaim);
            }
        }

        if let Some(expected) = &other.iss {
            let Some(received) = &self.iss else {
                return Err(JwtError::MissingIssClaim);
            };

            if expected != received {
                return Err(JwtError::MissingIssClaim);
            }
        }

        if let Some(expected) = &other.aud {
            let Some(received) = &self.aud else {
                return Err(JwtError::MissingAudClaim);
            };

            if expected != received {
                return Err(JwtError::MismatchedAudClaim);
            }
        }

        if let Some(expected) = &other.jti {
            let Some(received) = &self.jti else {
                return Err(JwtError::MissingJtiClaim);
            };

            if expected != received {
                return Err(JwtError::MismatchedJtiClaim);
            }
        }

        Ok(())
    }
}