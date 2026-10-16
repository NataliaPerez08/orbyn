//! Active service fingerprinting for the native collector
//! (ROADMAP_V2 v1.7).
//!
//! Versioned probe rules — bump [`RULES_VERSION`] whenever a probe or
//! parser changes, so results stay explainable across releases.
//!
//! Two probes, both unprivileged and read-only:
//! - **HTTP** (plaintext): `GET /` on open ports that stay silent, parse
//!   the status line and `Server` header.
//! - **TLS**: rustls handshake (sync, on the blocking pool — no new async
//!   plumbing) on known TLS ports, then either the post-handshake
//!   greeting (smtps/imaps/pop3s send one) or an HTTP `GET` inside the
//!   tunnel (https).
//!
//! Certificates are **not verified** — fingerprinting identifies a
//! service, it does not authenticate it, the same posture as nmap. Never
//! route anything security-relevant through these probes.
//!
//! Documented differences vs `nmap -sV` (ADR-0001): no probe cascade, no
//! payload matching beyond HTTP, no OS inference. Evidence beats the
//! port table: a parsed HTTP response renames the service to
//! `http`/`https` even on ports the table guessed differently.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream as StdTcpStream};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Version of the probe rules in this module. Surfaces in the HTTP
/// `User-Agent` so scanned services can identify the prober.
pub(crate) const RULES_VERSION: &str = "native-fingerprints/v1";

/// Open ports probed with a TLS handshake before anything else.
pub(crate) const TLS_PORTS: &[u16] = &[443, 465, 636, 993, 995, 2376, 4443, 5986, 6443, 8443, 8844];

/// Whole-probe budget for one read or write.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Shorter peek for post-handshake greetings; https stays silent, so
/// waiting the full probe budget would only slow the sweep down.
const GREETING_TIMEOUT: Duration = Duration::from_millis(1000);
/// Longest response prefix kept for parsing.
const MAX_RESPONSE_BYTES: usize = 4096;
/// Longest banner stored (matches the native collector's banner cap).
const MAX_BANNER_BYTES: usize = 128;

/// What a probe learned about one open port. `None` fields make no
/// claim; the port-table fallback applies.
pub(crate) struct Fingerprint {
    /// Evidence-based service name that overrides the port table.
    pub name: Option<&'static str>,
    /// Product/version line derived from the response.
    pub banner: Option<String>,
}

/// `GET /` on a connected plaintext port. `None` = not an HTTP service.
pub(crate) async fn probe_http(stream: &mut TcpStream, host: &str) -> Option<Fingerprint> {
    stream.write_all(&http_request(host)).await.ok()?;
    let mut buf = Vec::with_capacity(2048);
    read_http_response(stream, &mut buf).await;
    http_fingerprint(&buf, "http")
}

/// TLS handshake on a connected port, then greeting peek or HTTP `GET`
/// inside the tunnel. `None` = handshake failed or nothing parseable.
pub(crate) async fn probe_tls(stream: TcpStream, ip: IpAddr) -> Option<Fingerprint> {
    let sock = stream.into_std().ok()?;
    // Sync rustls on the blocking pool: the sweep already bounds
    // concurrency with its connect semaphore, and this avoids any
    // hand-rolled async TLS plumbing.
    tokio::task::spawn_blocking(move || tls_probe_blocking(sock, ip))
        .await
        .ok()?
}

fn tls_probe_blocking(mut sock: StdTcpStream, ip: IpAddr) -> Option<Fingerprint> {
    // `into_std` keeps the tokio socket non-blocking; blocking mode is
    // what makes the socket timeouts below meaningful.
    sock.set_nonblocking(false).ok()?;
    sock.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    sock.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;
    let mut conn = rustls::ClientConnection::new(client_config(), server_name(ip)).ok()?;
    conn.complete_io(&mut sock).ok()?; // handshake

    // Peek for a greeting (smtps/imaps/pop3s send one right after the
    // handshake); https stays silent and gets the HTTP probe instead.
    let mut buf = Vec::with_capacity(2048);
    if tls_read_once(&mut conn, &mut sock, &mut buf, GREETING_TIMEOUT).is_some() {
        return first_printable_line(&buf).map(|banner| Fingerprint {
            name: None,
            banner: Some(banner),
        });
    }
    {
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(&http_request(&ip.to_string())).ok()?;
    }
    while tls_read_once(&mut conn, &mut sock, &mut buf, PROBE_TIMEOUT).is_some()
        && !buf.windows(4).any(|w| w == b"\r\n\r\n")
        && buf.len() < MAX_RESPONSE_BYTES
    {}
    http_fingerprint(&buf, "https")
}

/// One bounded read through the TLS connection into `buf`; `None` on
/// timeout, clean close, or error.
fn tls_read_once(
    conn: &mut rustls::ClientConnection,
    sock: &mut StdTcpStream,
    buf: &mut Vec<u8>,
    timeout: Duration,
) -> Option<()> {
    sock.set_read_timeout(Some(timeout)).ok()?;
    let mut tls = rustls::Stream::new(conn, sock);
    let mut chunk = [0u8; 2048];
    match tls.read(&mut chunk) {
        Ok(0) => None,
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Some(())
        }
        Err(_) => None,
    }
}

/// Shared rustls client config: ring provider (already in the tree via
/// sqlx), TLS 1.2+1.3, certificates accepted but never verified.
fn client_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let builder = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring supports the safe default versions");
            Arc::new(
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(AcceptAllServerCerts))
                    .with_no_client_auth(),
            )
        })
        .clone()
}

fn server_name(ip: IpAddr) -> rustls::pki_types::ServerName<'static> {
    rustls::pki_types::ServerName::IpAddress(rustls::pki_types::IpAddr::from(ip))
}

/// Fingerprinting identifies services, it does not authenticate them.
/// Accept every certificate, the same posture as nmap's TLS probes.
#[derive(Debug)]
struct AcceptAllServerCerts;

impl rustls::client::danger::ServerCertVerifier for AcceptAllServerCerts {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

fn http_request(host: &str) -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: orbyn-native/{RULES_VERSION}\r\n\
         Accept: */*\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// Parsed HTTP response head: just what a fingerprint needs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HttpInfo {
    pub status: u16,
    pub server: Option<String>,
}

/// Parse an HTTP response head: status line plus `Server` header
/// (case-insensitive). `None` for anything that is not HTTP.
pub(crate) fn parse_http_response(bytes: &[u8]) -> Option<HttpInfo> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    for line in lines {
        if line.is_empty() {
            break; // end of headers
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case("server") {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(HttpInfo {
                        status,
                        server: Some(cap_banner(value)),
                    });
                }
            }
        }
    }
    Some(HttpInfo {
        status,
        server: None,
    })
}

/// Fingerprint from an HTTP response: the `Server` product string, or
/// the status line when no header exists. `None` = not HTTP.
fn http_fingerprint(bytes: &[u8], name: &'static str) -> Option<Fingerprint> {
    let info = parse_http_response(bytes)?;
    let banner = match &info.server {
        Some(server) => Some(server.clone()),
        None => std::str::from_utf8(bytes)
            .ok()?
            .split("\r\n")
            .next()
            .map(cap_banner),
    };
    Some(Fingerprint {
        name: Some(name),
        banner,
    })
}

/// First printable ASCII line of a greeting, capped. Shared with the
/// native collector's passive banner read.
pub(crate) fn first_printable_line(bytes: &[u8]) -> Option<String> {
    let line: Vec<u8> = bytes
        .iter()
        .copied()
        .take_while(|&b| b != b'\r' && b != b'\n')
        .filter(|&b| (0x20..0x7f).contains(&b))
        .take(MAX_BANNER_BYTES)
        .collect();
    if line.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&line).into_owned())
}

fn cap_banner(s: &str) -> String {
    s.chars().take(MAX_BANNER_BYTES).collect()
}

/// Read an HTTP response head into `buf`: until `\r\n\r\n`, the byte
/// cap, or the timeout. Best effort — callers parse whatever arrived.
async fn read_http_response(stream: &mut TcpStream, buf: &mut Vec<u8>) {
    let mut chunk = [0u8; 2048];
    loop {
        let n = match tokio::time::timeout(PROBE_TIMEOUT, stream.read(&mut chunk)).await {
            Ok(Ok(n)) => n,
            _ => return,
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= MAX_RESPONSE_BYTES {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_and_server_header() {
        let response =
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            parse_http_response(response),
            Some(HttpInfo {
                status: 200,
                server: Some("nginx/1.18.0 (Ubuntu)".to_string()),
            })
        );
    }

    #[test]
    fn server_header_is_case_insensitive_and_optional() {
        let response = b"HTTP/1.0 401 Unauthorized\r\nsErVeR: Apache/2.4.41\r\n\r\n";
        assert_eq!(
            parse_http_response(response),
            Some(HttpInfo {
                status: 401,
                server: Some("Apache/2.4.41".to_string()),
            })
        );
        assert_eq!(
            parse_http_response(b"HTTP/1.1 204 No Content\r\n\r\n"),
            Some(HttpInfo {
                status: 204,
                server: None,
            })
        );
    }

    #[test]
    fn non_http_input_is_rejected() {
        assert_eq!(parse_http_response(b"SSH-2.0-OpenSSH_9.6\r\n"), None);
        assert_eq!(parse_http_response(b"-ERR unknown command\r\n"), None);
        assert_eq!(parse_http_response(b""), None);
        assert_eq!(parse_http_response(&[0xff, 0xfe, 0x00]), None);
    }

    #[test]
    fn long_server_header_is_capped() {
        let server = "x".repeat(500);
        let response = format!("HTTP/1.1 200 OK\r\nServer: {server}\r\n\r\n");
        let info = parse_http_response(response.as_bytes()).unwrap();
        assert_eq!(info.server.unwrap().len(), MAX_BANNER_BYTES);
    }

    #[test]
    fn printable_line_extracts_greeting() {
        assert_eq!(
            first_printable_line(b"220 mail.example.com ESMTP Postfix\r\n250 OK"),
            Some("220 mail.example.com ESMTP Postfix".to_string())
        );
        assert_eq!(first_printable_line(b"\r\n"), None);
        assert_eq!(first_printable_line(&[0x16, 0x03, 0x01]), None);
    }

    #[test]
    fn tls_port_list_is_sorted_and_unique() {
        let mut sorted = TLS_PORTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(&sorted, TLS_PORTS);
    }

    #[test]
    fn http_fingerprint_names_and_banners() {
        let bytes = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\nbody";
        let fp = http_fingerprint(bytes, "https").unwrap();
        assert_eq!(fp.name, Some("https"));
        assert_eq!(fp.banner.as_deref(), Some("nginx/1.18.0"));
        // No Server header: banner falls back to the status line.
        let fp = http_fingerprint(b"HTTP/1.1 404 Not Found\r\n\r\n", "http").unwrap();
        assert_eq!(fp.name, Some("http"));
        assert_eq!(fp.banner.as_deref(), Some("HTTP/1.1 404 Not Found"));
        assert!(http_fingerprint(b"garbage", "http").is_none());
    }

    /// Test-only self-signed certificate (CN=localhost), committed as DER:
    /// `openssl req -x509 -newkey rsa:2048 -nodes` then `-outform DER`.
    fn server_config() -> Arc<rustls::ServerConfig> {
        let cert = rustls::pki_types::CertificateDer::from(
            include_bytes!("../../tests/fixtures/tls/cert.der").as_slice(),
        );
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
            include_bytes!("../../tests/fixtures/tls/key.der").as_slice(),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key.into())
            .unwrap();
        Arc::new(config)
    }

    #[tokio::test]
    async fn tls_probe_extracts_http_server_header() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let response: &'static [u8] =
            b"HTTP/1.1 200 OK\r\nServer: test-tls/7.3\r\nContent-Length: 0\r\n\r\n";
        let server = std::thread::spawn(move || {
            let config = server_config();
            for sock in listener.incoming().take(1) {
                let Ok(mut sock) = sock else { return };
                sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let Ok(mut conn) = rustls::ServerConnection::new(config.clone()) else {
                    return;
                };
                if conn.complete_io(&mut sock).is_err() {
                    return;
                }
                let mut tls = rustls::Stream::new(&mut conn, &mut sock);
                let mut req = [0u8; 1024];
                let _ = tls.read(&mut req); // the GET
                let _ = tls.write_all(response);
                tls.conn.send_close_notify();
                let _ = conn.complete_io(&mut sock);
            }
        });

        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let fp = probe_tls(stream, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            .await
            .expect("fingerprint");
        assert_eq!(fp.name, Some("https"));
        assert_eq!(fp.banner.as_deref(), Some("test-tls/7.3"));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn tls_probe_captures_greeting_banner() {
        // smtps-style server: greets right after the handshake.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let config = server_config();
            for sock in listener.incoming().take(1) {
                let Ok(mut sock) = sock else { return };
                sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let Ok(mut conn) = rustls::ServerConnection::new(config.clone()) else {
                    return;
                };
                if conn.complete_io(&mut sock).is_err() {
                    return;
                }
                let mut tls = rustls::Stream::new(&mut conn, &mut sock);
                let _ = tls.write_all(b"220 mail.example.com ESMTP Postfix\r\n");
                tls.conn.send_close_notify();
                let _ = conn.complete_io(&mut sock);
            }
        });

        let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let fp = probe_tls(stream, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
            .await
            .expect("fingerprint");
        assert_eq!(fp.name, None, "greeting is not HTTP: no name claim");
        assert_eq!(
            fp.banner.as_deref(),
            Some("220 mail.example.com ESMTP Postfix")
        );
        server.join().unwrap();
    }
}
