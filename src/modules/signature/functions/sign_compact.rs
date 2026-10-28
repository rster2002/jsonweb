use crate::algorithm::{JwAlg, JwAlgSign};
use crate::modules::header::JoseHeader;
use crate::modules::signature::error::JwsError;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;

pub fn sign_compact<A>(
    header: JoseHeader,
    payload: &[u8],
    algorithm: &A,
) -> Result<String, JwsError>
where
    A: JwAlg + JwAlgSign,
{
    let header = header.or(JoseHeader::from(algorithm));
    let header_bytes = serde_json::to_vec(&header)?;
    let header_string = BASE64_URL_SAFE_NO_PAD.encode(&header_bytes);

    let content_string = BASE64_URL_SAFE_NO_PAD.encode(payload);
    let target = format!("{}.{}", header_string, content_string);

    let signature_bytes = algorithm.sign(target.as_bytes());
    let signature_string = BASE64_URL_SAFE_NO_PAD.encode(&signature_bytes);

    Ok(format!("{}.{}", target, signature_string))
}

#[cfg(test)]
mod tests {
    use crate::algorithm::hs::HS256Private;
    use crate::modules::header::JoseHeader;
    use crate::modules::signature::functions::sign_compact::sign_compact;
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use serde_json::json;

    #[test]
    fn simple_example() {
        let payload = b"Hello world";
        let hs256 = HS256Private::new(b"secret").unwrap();

        let signed = sign_compact(
            JoseHeader::default(),
            payload,
            &hs256,
        )
        .unwrap();

        assert_eq!(signed, "eyJhbGciOiJIUzI1NiJ9.SGVsbG8gd29ybGQ.lx8XX3uMIc57Na8JUblW-_qwlZ3H2bwkSZwvL8Iqa5w");
    }

    #[test]
    fn rfc_example_hmac_sha256_works() {
        let payload = serde_json::to_vec(&json!({
            "iss": "joe",
            "exp": 1300819380,
            "http://example.com/is_root": true
        }))
        .unwrap();

        let key = BASE64_URL_SAFE_NO_PAD.decode("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
            .unwrap();
        let hs256 = HS256Private::new(&key).unwrap();

        let signed = sign_compact(
            JoseHeader::builder().typ("JWT".into()).build(),
            &payload,
            &hs256,
        )
        .unwrap();

        let expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlLCJpc3MiOiJqb2UifQ.LGyv4nF987S4V9z9qm-803XzhHTFe0o82-JsLGEZCjQ";
        assert_eq!(signed, expected);
    }
}
