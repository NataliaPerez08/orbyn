//! Agent → server sync (ROADMAP_V2 v1.6).
//!
//! `orbyn agent sync` ships the local agent database to an ingest
//! server: samples strictly after the persisted sync cursor, plus the
//! asset row and current filesystem/connection facts (re-upserted every
//! sync — they are snapshots, not history). The local database IS the
//! buffer: nothing is deleted until the server acknowledges, retention
//! prunes old samples independently, and every server write is
//! idempotent, so a crashed sync retries cleanly on the next run.
//!
//! The HTTP call goes through the `curl` binary like every other Orbyn
//! API client. The enrollment token is streamed to curl via stdin
//! (`-H @-`) so it never appears in a process listing; the JSON body
//! travels through a temp file because stdin is taken.
//!
//! One attempt per run — cron/systemd timers are the retry policy. On
//! rejection (401/403) the agent keeps buffering and the operator
//! re-enrolls; on any other failure the next run resumes from the
//! cursor.

use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};

use crate::domain::asset_id;
use crate::process::{run_captured, MAX_STDERR_CAPTURE_BYTES};
use crate::server::IngestBatch;
use crate::store::traits::Store;

/// Agent-state key holding the last acknowledged sample instant.
const CURSOR_KEY: &str = "sync_cursor";
/// Samples per request; the server refuses more than double this.
const DEFAULT_BATCH: usize = 5_000;
/// Whole-request budget for one POST.
const SYNC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const SYNC_STDOUT_CAP: u64 = 1024 * 1024;

pub struct SyncConfig {
    /// Ingest endpoint, e.g. `http://127.0.0.1:7780/v1/ingest`.
    pub url: String,
    /// Enrollment token from `orbyn server enroll`.
    pub token: String,
    /// Asset IP the local agent records under.
    pub asset_ip: IpAddr,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncStats {
    pub batches: usize,
    pub samples: usize,
}

/// Ship everything since the cursor to the server. Returns when the
/// local buffer is drained (or the server refuses).
pub async fn sync(store: &dyn Store, cfg: &SyncConfig) -> Result<SyncStats> {
    let id = asset_id(cfg.asset_ip);
    crate::agent::ensure_asset(store, &id, cfg.asset_ip).await;
    let asset = store
        .get_asset(&id)
        .await?
        .ok_or_else(|| anyhow!("asset row missing for {id}"))?;
    let filesystems = store.list_filesystems(&id).await?;
    let connections = store.list_connections(&id).await?;

    let mut stats = SyncStats::default();
    loop {
        let since = read_cursor(store).await?;
        let samples = store
            .list_metric_samples_since(&id, since, DEFAULT_BATCH)
            .await?;
        if samples.is_empty() {
            break;
        }
        let last = samples.last().expect("non-empty").sampled_at;
        let count = samples.len();
        let batch = IngestBatch {
            asset: asset.clone(),
            samples,
            filesystems: filesystems.clone(),
            connections: connections.clone(),
        };
        let status = post_batch(cfg, &batch).await?;
        match status {
            200 => {
                store
                    .set_agent_state(CURSOR_KEY, &last.to_rfc3339())
                    .await?;
                stats.batches += 1;
                stats.samples += count;
                if count < DEFAULT_BATCH {
                    break;
                }
            }
            401 | 403 => {
                anyhow::bail!(
                    "server rejected the sync token (HTTP {status}); samples stay \
                     buffered locally — re-enroll with `orbyn server enroll`"
                );
            }
            status => {
                anyhow::bail!(
                    "ingest failed with HTTP {status}; samples stay buffered \
                     locally, the next run resumes from the cursor"
                );
            }
        }
    }
    Ok(stats)
}

async fn read_cursor(store: &dyn Store) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    match store.get_agent_state(CURSOR_KEY).await? {
        None => Ok(None),
        Some(raw) => Ok(Some(
            chrono::DateTime::parse_from_rfc3339(&raw)
                .with_context(|| format!("parsing sync cursor '{raw}'"))?
                .with_timezone(&chrono::Utc),
        )),
    }
}

/// POST one batch through curl; returns the HTTP status.
async fn post_batch(cfg: &SyncConfig, batch: &IngestBatch) -> Result<u16> {
    let body = serde_json::to_vec(batch).context("encoding sync batch")?;
    let path =
        std::env::temp_dir().join(format!("orbyn-sync-{}.json", uuid::Uuid::new_v4().simple()));
    std::fs::write(&path, &body).context("writing sync temp file")?;
    // The Authorization header travels through stdin (`-H @-`) so the
    // token never shows up in a process listing.
    let header = format!("Authorization: Bearer {}\n", cfg.token);

    let result = post_via_curl(cfg, &path, header.as_bytes()).await;
    let _ = std::fs::remove_file(&path);
    let captured = result?;
    crate::http::split_http_status(&captured.stdout)
        .map(|(_, status)| status)
        .ok_or_else(|| anyhow!("ingest server response was not HTTP"))
}

async fn post_via_curl(
    cfg: &SyncConfig,
    body_path: &std::path::Path,
    stdin: &[u8],
) -> Result<crate::process::CapturedProcess> {
    use std::process::Stdio;
    let curl = std::env::var("ORBYN_CURL_BIN").unwrap_or_else(|_| "curl".to_string());
    let child = tokio::process::Command::new(&curl)
        .arg("-sS")
        .arg("--max-time")
        .arg("30")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("@-")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("--data-binary")
        .arg(format!("@{}", body_path.display()))
        .arg("-w")
        .arg("%{http_code}")
        .arg(&cfg.url)
        .env_remove("ORBYN_SNMP_COMMUNITY")
        .env_remove("ORBYN_NETBOX_TOKEN")
        .env_remove("ORBYN_WINRM_PASSWORD")
        .env_remove("ORBYN_PROMETHEUS_TOKEN")
        .env_remove("ORBYN_DB")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting {curl}"))?;
    run_captured(
        child,
        Some(std::str::from_utf8(stdin).unwrap_or_default()),
        SYNC_STDOUT_CAP,
        MAX_STDERR_CAPTURE_BYTES,
        SYNC_TIMEOUT,
        "agent sync timed out".to_string(),
    )
    .await
}
