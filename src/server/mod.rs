//! Minimal single-tenant ingest server (ROADMAP_V2 v1.6, ADR-0002 D3).
//!
//! One endpoint: `POST /v1/ingest`, Bearer-token auth, JSON body
//! ([`IngestBatch`]). Deliberately tiny: hand-rolled HTTP/1.1 with
//! Content-Length only (chunked is refused), one request per
//! connection, handled sequentially — a localhost single-tenant
//! collector, not a framework. Enrollment tokens are random UUIDs shown
//! once; only their SHA-256 hashes are stored. Plain HTTP per ADR-0002
//! D3 (local-first; the default bind is loopback — data does not leave
//! the host until an operator deliberately binds elsewhere).
//!
//! Agents may submit only their own asset row, utilization samples, and
//! filesystem/connection facts — not arbitrary observations — and the
//! server forces every fact's `asset_id` from the authenticated batch,
//! so a compromised agent cannot pollute another asset's inventory.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::domain::{Asset, Connection, Filesystem, MetricSample, Observation};
use crate::store::traits::Store;

/// Longest request head accepted (request line + headers).
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Longest request body accepted.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Per-batch sample cap; agents batch at half this.
const MAX_SAMPLES_PER_BATCH: usize = 10_000;
/// Per-batch filesystem+connection cap.
const MAX_FACTS_PER_BATCH: usize = 10_000;
/// Whole-connection budget.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
const INGEST_PATH: &str = "/v1/ingest";

/// The ingest wire format, shared with the agent's sync client so the
/// two sides cannot drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestBatch {
    pub asset: Asset,
    pub samples: Vec<MetricSample>,
    pub filesystems: Vec<Filesystem>,
    pub connections: Vec<Connection>,
}

#[derive(Serialize)]
struct IngestAck {
    accepted_samples: usize,
    accepted_facts: usize,
}

/// Serve until SIGINT/SIGTERM. Binds `bind`, then accepts and handles
/// connections one at a time (single-tenant by design).
pub async fn run(store: &dyn Store, bind: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding {bind}"))?;
    serve(store, listener).await
}

/// The accept loop, split so tests can supply their own listener (and
/// learn the ephemeral port before serving starts).
pub(crate) async fn serve(store: &dyn Store, listener: TcpListener) -> Result<()> {
    let bind = listener.local_addr()?;
    tracing::info!(%bind, "ingest server listening (Ctrl-C to stop)");
    loop {
        tokio::select! {
            _ = crate::agent::shutdown_signal() => break,
            _ = tokio::signal::ctrl_c() => break,
            accepted = listener.accept() => {
                let (sock, _) = accepted?;
                handle(store, sock).await;
            }
        }
    }
    tracing::info!("ingest server stopped");
    Ok(())
}

/// One connection: read head, route, read body, ingest, respond.
async fn handle(store: &dyn Store, mut sock: TcpStream) {
    let _ = sock.set_nodelay(true);
    let (head, leftover) = match read_head(&mut sock).await {
        Ok(parts) => parts,
        Err(_) => return, // closed or garbage before a request: nothing to answer
    };
    let parsed = match parse_head(&head) {
        Ok(parsed) => parsed,
        Err(status) => {
            respond(&mut sock, status, &error_body(status)).await;
            return;
        }
    };
    if parsed.path != INGEST_PATH {
        respond(&mut sock, 404, &error_body(404)).await;
        return;
    }
    if parsed.method != "POST" {
        respond(&mut sock, 405, &error_body(405)).await;
        return;
    }
    let Some(bearer) = parsed.bearer else {
        respond(&mut sock, 401, &error_body(401)).await;
        return;
    };
    let Some(length) = parsed.content_length else {
        respond(&mut sock, 411, &error_body(411)).await;
        return;
    };
    if length > MAX_BODY_BYTES {
        respond(&mut sock, 413, &error_body(413)).await;
        return;
    }
    // The head read may have already consumed body bytes (TCP coalesces
    // them); they are the start of the body, not garbage.
    let mut body = leftover;
    if body.len() > length {
        respond(&mut sock, 400, &error_body(400)).await;
        return;
    }
    let remaining = length - body.len();
    if remaining > 0 {
        let mut rest = vec![0u8; remaining];
        if read_exact_timeout(&mut sock, &mut rest).await.is_err() {
            return;
        }
        body.extend_from_slice(&rest);
    }
    let (status, body) = ingest(store, &bearer, &body)
        .await
        .unwrap_or((500, error_body(500)));
    respond(&mut sock, status, &body).await;
}

/// Authenticate the bearer token against the batch's asset, then persist
/// the batch. Every write is idempotent, so a retried batch is safe.
/// Returns the status plus the JSON response body.
async fn ingest(store: &dyn Store, bearer: &str, body: &[u8]) -> Result<(u16, String)> {
    let batch: IngestBatch = match serde_json::from_slice(body) {
        Ok(batch) => batch,
        Err(_) => return Ok((400, error_body(400))),
    };
    if batch.samples.len() > MAX_SAMPLES_PER_BATCH
        || batch.filesystems.len() + batch.connections.len() > MAX_FACTS_PER_BATCH
    {
        return Ok((413, error_body(413)));
    }
    let token_hash = token_hash(bearer);
    if !store
        .agent_token_valid(&batch.asset.id, &token_hash)
        .await?
    {
        // Unknown and revoked are deliberately indistinguishable here.
        return Ok((403, error_body(403)));
    }
    let id = batch.asset.id.clone();
    let accepted_samples = batch.samples.len();
    store
        .store_observations(vec![Observation::Asset(batch.asset)])
        .await
        .context("ingesting asset")?;
    store
        .insert_metric_samples(&batch.samples)
        .await
        .context("ingesting samples")?;
    let facts: Vec<Observation> = batch
        .filesystems
        .into_iter()
        .map(|mut fs| {
            fs.asset_id = id.clone();
            Observation::Filesystem(fs)
        })
        .chain(batch.connections.into_iter().map(|mut c| {
            c.asset_id = id.clone();
            Observation::Connection(c)
        }))
        .collect();
    let accepted_facts = facts.len();
    store
        .store_observations(facts)
        .await
        .context("ingesting facts")?;
    let ack = serde_json::to_string(&IngestAck {
        accepted_samples,
        accepted_facts,
    })
    .unwrap_or_default();
    Ok((200, ack))
}

/// SHA-256 hex hash of an enrollment token — the only form ever stored.
pub fn token_hash(token: &str) -> String {
    crate::integrations::cloud::aws::sigv4::hex_lower(&sha2::Sha256::digest(token.as_bytes()))
}

/// A parsed request head: just what routing needs.
#[derive(Debug, PartialEq, Eq)]
struct RequestHead {
    method: String,
    path: String,
    bearer: Option<String>,
    content_length: Option<usize>,
}

/// Parse a request head (pure). Errors are the HTTP status to answer
/// with: malformed input 400, chunked bodies 501 (Content-Length only,
/// by design).
fn parse_head(bytes: &[u8]) -> Result<RequestHead, u16> {
    let text = std::str::from_utf8(bytes).map_err(|_| 400u16)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(400u16)?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().ok_or(400u16)?.to_string();
    let path = parts.next().ok_or(400u16)?.to_string();
    let mut bearer = None;
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "authorization" => {
                if let Some(token) = value.strip_prefix("Bearer ") {
                    bearer = Some(token.to_string());
                }
            }
            "content-length" => content_length = Some(value.parse().map_err(|_| 400u16)?),
            "transfer-encoding" if value.eq_ignore_ascii_case("chunked") => chunked = true,
            _ => {}
        }
    }
    if chunked {
        return Err(501);
    }
    Ok(RequestHead {
        method,
        path,
        bearer,
        content_length,
    })
}

/// Read until the end of the request head, within the caps. Returns the
/// head bytes (including the blank line) plus whatever body bytes were
/// read past it — TCP may coalesce both into one segment.
async fn read_head(sock: &mut TcpStream) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let leftover = buf.split_off(pos + 4);
            return Ok((buf, leftover));
        }
        if buf.len() > MAX_HEAD_BYTES {
            anyhow::bail!("request head too large");
        }
        let n = tokio::time::timeout(READ_TIMEOUT, sock.read(&mut chunk))
            .await
            .context("request head timeout")?
            .context("reading request head")?;
        if n == 0 {
            anyhow::bail!("connection closed before request head");
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn read_exact_timeout(sock: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
    tokio::time::timeout(READ_TIMEOUT, sock.read_exact(buf))
        .await
        .context("request body timeout")?
        .context("reading request body")?;
    Ok(())
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "Error",
    }
}

fn error_body(status: u16) -> String {
    let reason = reason_phrase(status);
    format!("{{\"error\":\"{reason}\"}}")
}

async fn respond(sock: &mut TcpStream, status: u16, body: &str) {
    let reason = reason_phrase(status);
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(text: &str) -> Vec<u8> {
        format!("{text}\r\n\r\n").into_bytes()
    }

    #[test]
    fn parses_post_with_bearer_and_length() {
        let parsed = parse_head(&head(
            "POST /v1/ingest HTTP/1.1\r\nAuthorization: Bearer abc\r\nContent-Length: 42",
        ))
        .unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/v1/ingest");
        assert_eq!(parsed.bearer.as_deref(), Some("abc"));
        assert_eq!(parsed.content_length, Some(42));
    }

    #[test]
    fn header_names_are_case_insensitive() {
        let parsed = parse_head(&head(
            "POST /v1/ingest HTTP/1.1\r\naUtHoRiZaTiOn: bearer abc\r\ncOnTeNt-LeNgTh: 7",
        ))
        .unwrap();
        // Lowercase scheme is not a Bearer token: no auth.
        assert_eq!(parsed.bearer, None);
        assert_eq!(parsed.content_length, Some(7));
    }

    #[test]
    fn chunked_is_refused_and_garbage_is_bad_request() {
        assert_eq!(
            parse_head(&head(
                "POST /v1/ingest HTTP/1.1\r\nTransfer-Encoding: chunked"
            )),
            Err(501)
        );
        assert_eq!(parse_head(b"\r\n\r\n"), Err(400));
        assert_eq!(
            parse_head(&head("POST /v1/ingest HTTP/1.1\r\nContent-Length: abc")),
            Err(400)
        );
        assert_eq!(parse_head(&[0xff, 0xfe]), Err(400));
    }

    #[tokio::test]
    async fn ingest_roundtrip_and_auth_failures() {
        use crate::store::sqlite::SqliteStore;
        let dir = std::env::temp_dir().join(format!("orbyn-server-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = std::sync::Arc::new(SqliteStore::open(&dir.join("server.db")).await.unwrap());

        // Enroll directly: the CLI path is covered by the e2e suite.
        let token = uuid::Uuid::new_v4().simple().to_string();
        let hash = token_hash(&token);
        store
            .upsert_agent_token("127-0-0-1", &hash, chrono::Utc::now())
            .await
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_store = std::sync::Arc::clone(&store);
        let server = tokio::spawn(async move {
            serve(server_store.as_ref(), listener).await.unwrap();
        });

        let batch = IngestBatch {
            asset: crate::domain::Asset {
                id: "127-0-0-1".into(),
                ip: "127.0.0.1".parse().unwrap(),
                hostname: Some("lab-host".into()),
                device_class: None,
                os_name: None,
                os_version: None,
                sys_descr: None,
                environment: None,
                owner: None,
                criticality: None,
                tags: Vec::new(),
                first_seen: chrono::Utc::now(),
                last_seen: chrono::Utc::now(),
            },
            samples: vec![MetricSample {
                asset_id: "127-0-0-1".into(),
                sampled_at: chrono::Utc::now(),
                cpu_usage_percent: Some(12.5),
                ram_used_mb: Some(1024),
                ram_available_mb: Some(2048),
                swap_used_mb: Some(0),
                load_1m: None,
                load_5m: None,
                load_15m: None,
            }],
            filesystems: Vec::new(),
            connections: Vec::new(),
        };
        let body = serde_json::to_vec(&batch).unwrap();

        // Good token: accepted, and the data lands in the store.
        assert_eq!(post(port, &token, &body).await, 200);
        assert_eq!(
            store
                .list_metric_samples("127-0-0-1", None)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(store.get_asset("127-0-0-1").await.unwrap().is_some());

        // Wrong token and revoked agents are refused; nothing is written.
        assert_eq!(post(port, "wrong-token", &body).await, 403);
        store.revoke_agent_token("127-0-0-1").await.unwrap();
        assert_eq!(post(port, &token, &body).await, 403);
        assert_eq!(
            store
                .list_metric_samples("127-0-0-1", None)
                .await
                .unwrap()
                .len(),
            1,
            "refused batches must not write"
        );

        // Routing and size gates.
        assert_eq!(post(port, &token, b"not json").await, 400);
        let mut huge = batch.clone();
        huge.samples = vec![batch.samples[0].clone(); MAX_SAMPLES_PER_BATCH + 1];
        let huge_body = serde_json::to_vec(&huge).unwrap();
        assert_eq!(post(port, &token, &huge_body).await, 413);

        server.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Minimal raw-TCP client: one POST with a Bearer token.
    async fn post(port: u16, token: &str, body: &[u8]) -> u16 {
        let mut sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let request = format!(
            "POST /v1/ingest HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        use tokio::io::AsyncWriteExt;
        sock.write_all(request.as_bytes()).await.unwrap();
        sock.write_all(body).await.unwrap();
        let mut response = Vec::new();
        use tokio::io::AsyncReadExt;
        let _ = tokio::time::timeout(Duration::from_secs(5), sock.read_to_end(&mut response)).await;
        let text = String::from_utf8_lossy(&response);
        text.split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }
}
