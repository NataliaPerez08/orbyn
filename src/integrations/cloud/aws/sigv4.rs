//! AWS Signature Version 4 request signing.
//!
//! Implemented from the public specification so the AWS adapter needs no AWS
//! SDK. Only the pieces Orbyn uses are covered: signing a `GET` with no body
//! (the EC2 and STS query APIs), with optional session-token headers. The
//! credential and derived signature are returned as request headers, which the
//! client streams to curl on stdin — never in process arguments.
//!
//! Signing can be date-sensitive and hard to eyeball, so the module is
//! covered by the published AWS test vector.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// Hex-encode bytes in lowercase (`hex::encode` semantics, inlined so the
/// signature path does not depend on the crate's formatting).
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(std::char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(std::char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// URI-encode per the AWS SigV4 rules (RFC 3986 unreserved characters are
/// kept; everything else is `%XX` uppercase). `encode_slash` distinguishes
/// the canonical URI (slashes kept) from a query component (slashes encoded).
pub fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                out.push('%');
                out.push(
                    std::char::from_digit((byte >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    std::char::from_digit((byte & 0x0f) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// The canonical query string: parameters URI-encoded and sorted by encoded
/// key then value, joined with `&`. This is both what is signed and what must
/// be sent, so the server's recomputation matches.
pub fn canonical_query(params: &[(String, String)]) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The canonical URI: each path segment encoded, slashes preserved.
pub fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    path.split('/')
        .map(|segment| uri_encode(segment, true))
        .collect::<Vec<_>>()
        .join("/")
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_lower(&hasher.finalize())
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Derive the SigV4 signing key for a date/region/service.
pub fn signing_key(secret_key: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac(
        format!("AWS4{secret_key}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    hmac(&k_service, b"aws4_request")
}

/// A signed GET: the query string to send and the headers to attach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedGet {
    /// The canonical query string (append to `path?`).
    pub query: String,
    /// `Host`, `x-amz-date`, optional `x-amz-security-token`, `Authorization`.
    pub headers: Vec<String>,
}

/// Sign a bodyless GET request.
#[allow(clippy::too_many_arguments)]
pub fn sign_get(
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    region: &str,
    service: &str,
    host: &str,
    path: &str,
    params: &[(String, String)],
    now: DateTime<Utc>,
) -> SignedGet {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();
    let query = canonical_query(params);
    let canonical_uri = canonical_uri(path);

    let mut signed_header_names = vec!["host", "x-amz-date"];
    if session_token.is_some() {
        signed_header_names.push("x-amz-security-token");
    }
    let signed_headers = signed_header_names.join(";");

    let mut canonical_headers = format!("host:{host}\nx-amz-date:{amz_date}\n");
    if let Some(token) = session_token {
        canonical_headers.push_str(&format!("x-amz-security-token:{token}\n"));
    }

    let payload_hash = sha256_hex(b"");
    let canonical_request = format!(
        "GET\n{canonical_uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let key = signing_key(secret_key, &date_stamp, region, service);
    let signature = hex_lower(&hmac(&key, string_to_sign.as_bytes()));

    let authorization = format!(
        "{ALGORITHM} Credential={access_key}/{scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut headers = vec![format!("Host: {host}"), format!("x-amz-date: {amz_date}")];
    if let Some(token) = session_token {
        headers.push(format!("x-amz-security-token: {token}"));
    }
    headers.push(format!("Authorization: {authorization}"));

    SignedGet { query, headers }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn uri_encoding_follows_rfc3986() {
        assert_eq!(uri_encode("test space", true), "test%20space");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("a/b", false), "a/b");
        assert_eq!(uri_encode("AZaz09-_.~", true), "AZaz09-_.~");
        assert_eq!(uri_encode("*", true), "%2A");
        assert_eq!(uri_encode("é", true), "%C3%A9");
    }

    #[test]
    fn canonical_query_sorts_and_encodes() {
        let params = vec![
            ("Version".to_string(), "2016-11-15".to_string()),
            ("Action".to_string(), "DescribeInstances".to_string()),
        ];
        assert_eq!(
            canonical_query(&params),
            "Action=DescribeInstances&Version=2016-11-15"
        );
    }

    #[test]
    fn canonical_uri_keeps_slashes_and_encodes_segments() {
        assert_eq!(canonical_uri("/"), "/");
        assert_eq!(canonical_uri(""), "/");
        assert_eq!(canonical_uri("/a b/c"), "/a%20b/c");
    }

    /// The published AWS SigV4 test vector (GET, no body, service `service`).
    #[test]
    fn matches_the_aws_get_vanilla_test_vector() {
        let now = Utc.with_ymd_and_hms(2015, 8, 30, 12, 36, 0).unwrap();
        let signed = sign_get(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            None,
            "us-east-1",
            "service",
            "example.amazonaws.com",
            "/",
            &[],
            now,
        );
        assert_eq!(signed.query, "");
        assert!(signed
            .headers
            .contains(&"Host: example.amazonaws.com".to_string()));
        assert!(signed
            .headers
            .contains(&"x-amz-date: 20150830T123600Z".to_string()));
        assert!(
            signed.headers.contains(
                &"Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
                    .to_string()
            ),
            "{:?}",
            signed.headers
        );
    }

    #[test]
    fn session_token_is_signed_and_sent() {
        let now = Utc.with_ymd_and_hms(2015, 8, 30, 12, 36, 0).unwrap();
        let signed = sign_get(
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            Some("SESSIONTOKEN"),
            "us-east-1",
            "service",
            "example.amazonaws.com",
            "/",
            &[],
            now,
        );
        assert!(signed
            .headers
            .contains(&"x-amz-security-token: SESSIONTOKEN".to_string()));
        assert!(signed
            .headers
            .iter()
            .any(|h| h.contains("SignedHeaders=host;x-amz-date;x-amz-security-token")));
    }
}
