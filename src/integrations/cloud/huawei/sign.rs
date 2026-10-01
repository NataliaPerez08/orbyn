//! Huawei Cloud AK/SK request signing (`SDK-HMAC-SHA256`).
//!
//! Implemented from the public specification so the Huawei adapter needs no
//! cloud SDK. Only the pieces Orbyn uses are covered: signing a request with
//! an optional body, with the mandatory `X-Sdk-Date` and `Host` headers. The
//! credential and signature are returned as request headers, which the client
//! streams to curl on stdin — never in process arguments.
//!
//! Signing is date-sensitive and hard to eyeball, so the module is covered by
//! the published SDK test vectors (the `AccessKey`/`SecretKey` fixtures from
//! `huaweicloud-sdk-python-v3`).

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

const ALGORITHM: &str = "SDK-HMAC-SHA256";

/// Hex-encode bytes in lowercase.
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(std::char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(std::char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    out
}

/// URI-encode per RFC 3986: unreserved characters (`A-Z a-z 0-9 - _ . ~`)
/// are kept, everything else becomes uppercase `%XX`. `encode_slash`
/// distinguishes a path segment (slashes encoded) from the canonical URI
/// (slashes preserved).
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
/// key (then value), joined with `&`. This is both what is signed and what
/// must be sent, so the server's recomputation matches.
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

/// The canonical URI: each path segment encoded, slashes preserved, and a
/// trailing `/` appended (the specification requires it for signing even when
/// the transmitted path may omit it).
pub fn canonical_uri(path: &str) -> String {
    let mut uri = if path.is_empty() {
        "/".to_string()
    } else {
        path.split('/')
            .map(|segment| uri_encode(segment, true))
            .collect::<Vec<_>>()
            .join("/")
    };
    if !uri.ends_with('/') {
        uri.push('/');
    }
    uri
}

/// The canonical headers string and the `SignedHeaders` declaration, both
/// derived from the same sorted, lowercased header list.
fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    sorted.sort();
    let canonical = sorted
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<String>();
    let signed = sorted
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>()
        .join(";");
    (canonical, signed)
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

/// A signed request: the query string to send and the headers to attach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    /// The canonical query string (append to `path?`).
    pub query: String,
    /// `Host`, `X-Sdk-Date` plus any caller headers and `Authorization`.
    pub headers: Vec<String>,
    /// `HexEncode(Hash(CanonicalRequest))`, exposed so a test can pin the
    /// canonicalization against the published example.
    pub canonical_request_hash: String,
}

/// Sign a request.
///
/// `extra_headers` are included in the signature and sent (e.g. `content-type`
/// for a request with a body). `body` is empty for a GET.
#[allow(clippy::too_many_arguments)]
pub fn sign_request(
    method: &str,
    access_key: &str,
    secret_key: &str,
    host: &str,
    path: &str,
    params: &[(String, String)],
    extra_headers: &[(String, String)],
    body: &[u8],
    now: DateTime<Utc>,
) -> SignedRequest {
    let sdk_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let query = canonical_query(params);
    let uri = canonical_uri(path);

    let mut headers: Vec<(String, String)> = vec![
        ("host".to_string(), host.to_string()),
        ("x-sdk-date".to_string(), sdk_date.clone()),
    ];
    headers.extend(extra_headers.iter().cloned());
    let (canonical_headers, signed_headers) = canonical_headers(&headers);

    let payload_hash = sha256_hex(body);
    let canonical_request =
        format!("{method}\n{uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!("{ALGORITHM}\n{sdk_date}\n{canonical_request_hash}");
    let signature = hex_lower(&hmac(secret_key.as_bytes(), string_to_sign.as_bytes()));

    let authorization = format!(
        "{ALGORITHM} Access={access_key}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    let mut out_headers = vec![format!("Host: {host}"), format!("X-Sdk-Date: {sdk_date}")];
    for (name, value) in extra_headers {
        out_headers.push(format!("{name}: {value}"));
    }
    out_headers.push(format!("Authorization: {authorization}"));

    SignedRequest {
        query,
        headers: out_headers,
        canonical_request_hash,
    }
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
            ("size".to_string(), "1".to_string()),
            ("marker".to_string(), "abc".to_string()),
        ];
        assert_eq!(canonical_query(&params), "marker=abc&size=1");
        // An empty value keeps the `=`.
        let params = vec![("flavor".to_string(), String::new())];
        assert_eq!(canonical_query(&params), "flavor=");
    }

    #[test]
    fn canonical_uri_appends_a_trailing_slash() {
        assert_eq!(canonical_uri("/"), "/");
        assert_eq!(canonical_uri(""), "/");
        assert_eq!(canonical_uri("/resources"), "/resources/");
        assert_eq!(
            canonical_uri("/v2.1/abc/servers/detail"),
            "/v2.1/abc/servers/detail/"
        );
        assert_eq!(canonical_uri("/a b/c"), "/a%20b/c/");
    }

    /// The GET vector from `huaweicloud-sdk-python-v3` (`test_signer1`).
    #[test]
    fn matches_the_sdk_get_test_vector() {
        let now = Utc.with_ymd_and_hms(2020, 6, 8, 2, 39, 0).unwrap();
        let signed = sign_request(
            "GET",
            "AccessKey",
            "SecretKey",
            "service.endpoint.myhuaweicloud.com",
            "/resources",
            &[("size".to_string(), "1".to_string())],
            &[],
            b"",
            now,
        );
        assert_eq!(signed.query, "size=1");
        assert!(signed
            .headers
            .contains(&"Host: service.endpoint.myhuaweicloud.com".to_string()));
        assert!(signed
            .headers
            .contains(&"X-Sdk-Date: 20200608T023900Z".to_string()));
        assert!(
            signed.headers.contains(
                &"Authorization: SDK-HMAC-SHA256 Access=AccessKey, SignedHeaders=host;x-sdk-date, Signature=cfb4171acec81de07d50e53d57eb77edd537414d66ddb1d7d780f128e12cd842"
                    .to_string()
            ),
            "{:?}",
            signed.headers
        );
    }

    /// The POST vector from `huaweicloud-sdk-python-v3` (`test_signer2`): the
    /// request body's hash is part of the signature.
    #[test]
    fn matches_the_sdk_post_test_vector() {
        let now = Utc.with_ymd_and_hms(2020, 6, 8, 2, 39, 0).unwrap();
        let signed = sign_request(
            "POST",
            "AccessKey",
            "SecretKey",
            "service.endpoint.myhuaweicloud.com",
            "/resources",
            &[("size".to_string(), "1".to_string())],
            &[],
            br#"{"name":"test","id":1}"#,
            now,
        );
        assert!(
            signed.headers.contains(
                &"Authorization: SDK-HMAC-SHA256 Access=AccessKey, SignedHeaders=host;x-sdk-date, Signature=436b1ac0a1ae03705934bb70ef2f2e09f7bfed2117d731a38235053199323a1f"
                    .to_string()
            ),
            "{:?}",
            signed.headers
        );
    }

    /// The canonical-request example published by Huawei for the
    /// `ListVpcs` GET, pinning the canonicalization (query, trailing slash,
    /// sorted/trimmed headers) against the documented hash.
    #[test]
    fn matches_the_published_vpc_canonical_request() {
        let now = Utc.with_ymd_and_hms(2019, 11, 15, 3, 36, 55).unwrap();
        let signed = sign_request(
            "GET",
            "QTWAOYTTINDUT2QVKYUC",
            "secret",
            "service.region.example.com",
            "/v1/77b6a44cba5143ab91d13ab9a8ff44fd/vpcs",
            &[
                ("limit".to_string(), "2".to_string()),
                (
                    "marker".to_string(),
                    "13551d6b-755d-4757-b956-536f674975c0".to_string(),
                ),
            ],
            &[("content-type".to_string(), "application/json".to_string())],
            b"",
            now,
        );
        assert_eq!(
            signed.canonical_request_hash,
            "b25362e603ee30f4f25e7858e8a7160fd36e803bb2dfe206278659d71a9bcd7a"
        );
        assert!(signed
            .headers
            .iter()
            .any(|h| h.contains("SignedHeaders=content-type;host;x-sdk-date")));
    }
}
