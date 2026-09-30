//! Cloud and platform adapters (Phase 5).
//!
//! A cloud adapter is a read-only client for a provider API. It fetches the
//! provider's inventory, normalizes it into Orbyn's domain model
//! ([`Observation`] types) and attaches provenance — provider, account,
//! region and observation time — so imported assets stay attributable to the
//! API they came from.
//!
//! The adapters share the same external-tool boundary as the rest of Orbyn:
//! every API call runs through the `curl` binary (never the standard library
//! without an external HTTP client), under a timeout and a response cap. The
//! secret never appears in process arguments: it is streamed to curl on stdin
//! through `-H @-`.
//!
//! ## The adapter contract
//!
//! Implement [`CloudAdapter`]. A provider adapter must:
//!
//! - be read-only (GET requests only);
//! - source credentials from the environment or a flag, never persist them;
//! - bound pagination, request count, response size and timeouts;
//! - return normalized observations plus [`CloudProvenance`];
//! - record provider provenance on every imported asset (as tags) so
//!   downstream assessment/export can tell where a row came from.
//!
//! Proxmox VE is the first adapter ([`proxmox`]); AWS follows.

pub mod aws;
pub mod proxmox;

use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::process::Command;

use crate::domain::{Asset, Capacity, Criticality, Filesystem, Interface, Service};
use crate::http::{
    is_retryable_curl_exit, is_retryable_status, split_http_status, with_retries, Attempt,
    CallFailure, RetryPolicy,
};
use crate::process::{is_timeout, run_captured, MAX_STDERR_CAPTURE_BYTES};

/// Per-request response cap. Far above any realistic provider page while
/// still bounding what a hostile endpoint can make Orbyn buffer.
pub const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Per-request lifecycle timeout.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum HTTP requests one adapter run may issue. Bounds fan-out over
/// per-resource detail calls so a provider with a huge inventory cannot turn
/// an import into an unbounded crawl.
pub const MAX_REQUESTS: usize = 20_000;

/// Environment variables holding secrets that must never leak into a child
/// `curl` process (a hijacked binary must not be able to read them).
const SCRUBBED_ENV: [&str; 9] = [
    "ORBYN_SNMP_COMMUNITY",
    "ORBYN_NETBOX_TOKEN",
    "ORBYN_WINRM_PASSWORD",
    "ORBYN_PROMETHEUS_TOKEN",
    "ORBYN_ZABBIX_TOKEN",
    "ORBYN_PROXMOX_TOKEN",
    "ORBYN_DB",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
];

/// Provider provenance attached to a cloud import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudProvenance {
    /// Provider identifier (`proxmox`, `aws`, ...).
    pub provider: String,
    /// Account / project / subscription / tenant the inventory was read from.
    pub account: Option<String>,
    /// Region, node or datacenter scope.
    pub region: Option<String>,
    /// When the provider was queried.
    pub observed_at: DateTime<Utc>,
}

impl CloudProvenance {
    /// A short, operator-facing label, e.g. `proxmox:acme@example.com:pve`.
    pub fn label(&self) -> String {
        let mut label = self.provider.clone();
        for part in [&self.account, &self.region].into_iter().flatten() {
            label.push(':');
            label.push_str(part);
        }
        label
    }

    /// The provenance tags attached to every imported asset, so a row
    /// remains attributable without a schema change.
    pub fn tags(&self) -> Vec<String> {
        let mut tags = vec![format!("cloud:{}", self.provider)];
        if let Some(account) = &self.account {
            tags.push(format!("cloud-account:{account}"));
        }
        if let Some(region) = &self.region {
            tags.push(format!("cloud-region:{region}"));
        }
        tags
    }
}

/// An asset plus the annotations Orbyn stores outside the asset row
/// (environment/owner/criticality/tags).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudAsset {
    pub asset: Asset,
    pub environment: Option<String>,
    pub owner: Option<String>,
    pub criticality: Option<Criticality>,
    pub tags: Vec<String>,
}

/// Normalized inventory from one cloud provider.
#[derive(Debug, Clone, PartialEq)]
pub struct CloudInventory {
    pub provenance: CloudProvenance,
    pub assets: Vec<CloudAsset>,
    pub interfaces: Vec<Interface>,
    pub services: Vec<Service>,
    pub capacities: Vec<Capacity>,
    pub filesystems: Vec<Filesystem>,
    /// Human-readable notes for resources the adapter could not represent
    /// (e.g. a VM without a reachable IP address). Surfaced as warnings.
    pub skipped: Vec<String>,
}

impl CloudInventory {
    /// An empty inventory for `provider`, used as a starting point.
    pub fn new(provider: &str, account: Option<String>, region: Option<String>) -> Self {
        Self {
            provenance: CloudProvenance {
                provider: provider.to_string(),
                account,
                region,
                observed_at: Utc::now(),
            },
            assets: Vec::new(),
            interfaces: Vec::new(),
            services: Vec::new(),
            capacities: Vec::new(),
            filesystems: Vec::new(),
            skipped: Vec::new(),
        }
    }

    /// Counts by observation kind, for the job outcome and the CLI summary.
    pub fn counts(&self) -> CloudCounts {
        CloudCounts {
            assets: self.assets.len(),
            interfaces: self.interfaces.len(),
            services: self.services.len(),
            capacities: self.capacities.len(),
            filesystems: self.filesystems.len(),
        }
    }
}

/// Observation counts for a cloud import.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CloudCounts {
    pub assets: usize,
    pub interfaces: usize,
    pub services: usize,
    pub capacities: usize,
    pub filesystems: usize,
}

/// A read-only provider adapter.
#[async_trait]
pub trait CloudAdapter: Send + Sync {
    /// Provider identifier (`proxmox`, `aws`, ...).
    fn provider(&self) -> &'static str;

    /// Fetch and normalize the provider inventory.
    async fn fetch(&self) -> Result<CloudInventory>;
}

/// A minimal HTTP client over the `curl` binary, shared by the cloud
/// adapters.
///
/// Every call appends the HTTP status to stdout (`-w %{http_code}`) so a
/// rate limit or a server error is distinguishable from a good response, and
/// replays only the transient failures a later attempt could fix. Request
/// headers (which may carry a credential) travel on stdin via `-H @-`, never
/// in argv.
pub struct CurlClient {
    binary: String,
    insecure: bool,
    retry: RetryPolicy,
    requests: AtomicUsize,
    max_requests: usize,
}

impl Default for CurlClient {
    fn default() -> Self {
        Self::new()
    }
}

impl CurlClient {
    pub fn new() -> Self {
        Self {
            binary: std::env::var("ORBYN_CURL_BIN").unwrap_or_else(|_| "curl".to_string()),
            insecure: false,
            retry: RetryPolicy::default(),
            requests: AtomicUsize::new(0),
            max_requests: MAX_REQUESTS,
        }
    }

    /// Skip TLS certificate verification (for a trusted self-signed
    /// provider endpoint).
    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }

    /// GET `url`, returning the response body. Transient failures (timeouts,
    /// dropped connections, 429, 5xx) are replayed per the default policy.
    pub async fn get(&self, url: &str, headers: &[String]) -> Result<String> {
        let count = self.requests.fetch_add(1, Ordering::Relaxed);
        if count >= self.max_requests {
            return Err(anyhow!(
                "cloud import exceeded the {} request limit",
                self.max_requests
            ));
        }
        with_retries(&self.retry, &format!("cloud request to {url}"), |_| {
            self.get_once(url, headers)
        })
        .await
    }

    /// GET `url` once, without retries, returning `None` on any failure.
    ///
    /// Used for optional probes (e.g. a guest agent that may not be running)
    /// where a missing answer is expected and must not abort the import or
    /// spend the retry budget.
    pub async fn try_get(&self, url: &str, headers: &[String]) -> Option<String> {
        let count = self.requests.fetch_add(1, Ordering::Relaxed);
        if count >= self.max_requests {
            return None;
        }
        self.get_once_no_retry(url, headers).await.ok()
    }

    /// One attempt that is not replayed: `get_once` with a single-attempt
    /// policy.
    async fn get_once_no_retry(&self, url: &str, headers: &[String]) -> Result<String> {
        let policy = RetryPolicy {
            max_attempts: 1,
            ..self.retry
        };
        with_retries(&policy, &format!("cloud request to {url}"), |_| {
            self.get_once(url, headers)
        })
        .await
    }

    /// One provider HTTP GET: the response body, or a failure classified for
    /// retry.
    async fn get_once(&self, url: &str, headers: &[String]) -> Attempt<String> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("-sS")
            // Append the HTTP status to stdout so a rate limit or a server
            // error is distinguishable from a good response without -f,
            // which would discard the error body an operator needs.
            .arg("-w")
            .arg("%{http_code}");
        if self.insecure {
            cmd.arg("--insecure");
        }
        if !headers.is_empty() {
            // Read the request headers from stdin (`-H @-`): a credential in
            // an Authorization header never reaches the process arguments.
            cmd.arg("-H").arg("@-");
        }
        cmd.arg(url);
        for name in SCRUBBED_ENV {
            cmd.env_remove(name);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                return Err(CallFailure::permanent(format!(
                    "failed to start curl; is it installed? {e}"
                )))
            }
        };

        let stdin_payload = if headers.is_empty() {
            None
        } else {
            Some(format!("{}\n", headers.join("\n")))
        };
        let captured = match run_captured(
            child,
            stdin_payload.as_deref(),
            MAX_RESPONSE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
            REQUEST_TIMEOUT,
            format!("curl timed out against {url}"),
        )
        .await
        {
            Ok(captured) => captured,
            Err(e) if is_timeout(&e) => return Err(CallFailure::transient(format!("{e:#}"))),
            Err(e) => return Err(e.into()),
        };

        if captured.stdout.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(CallFailure::permanent(format!(
                "provider response exceeds the {MAX_RESPONSE_BYTES} byte limit"
            )));
        }
        if !captured.status.success() {
            let message = format!(
                "curl exited with {} against {url}: {}",
                captured.status,
                captured.stderr.trim()
            );
            return Err(match captured.status.code() {
                Some(code) if is_retryable_curl_exit(code) => CallFailure::transient(message),
                _ => CallFailure::permanent(message),
            });
        }
        let Some((body, status)) = split_http_status(&captured.stdout) else {
            return Err(CallFailure::permanent(format!(
                "malformed curl response from {url}: no HTTP status trailer"
            )));
        };
        if !(200..300).contains(&status) {
            let message = format!("provider returned HTTP {status} for {url}");
            return Err(if is_retryable_status(status) {
                CallFailure::transient(message)
            } else {
                CallFailure::permanent(message)
            });
        }
        Ok(body.to_string())
    }
}

/// Build an [`Asset`] for a cloud resource observed now.
pub(crate) fn cloud_asset(
    ip: std::net::IpAddr,
    hostname: Option<String>,
    device_class: &str,
    observed_at: DateTime<Utc>,
) -> Asset {
    Asset {
        id: crate::domain::asset_id(ip),
        ip,
        hostname,
        device_class: Some(device_class.to_string()),
        os_name: None,
        os_version: None,
        sys_descr: None,
        environment: None,
        owner: None,
        criticality: None,
        tags: Vec::new(),
        first_seen: observed_at,
        last_seen: observed_at,
    }
}

/// Parse an IP address that may carry a CIDR suffix (`10.0.0.5/24`).
pub(crate) fn parse_ip_cidr(raw: &str) -> Option<std::net::IpAddr> {
    raw.split('/').next()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_label_joins_present_scope() {
        let mut p = CloudProvenance {
            provider: "proxmox".into(),
            account: None,
            region: None,
            observed_at: Utc::now(),
        };
        assert_eq!(p.label(), "proxmox");
        p.account = Some("root@pam".into());
        assert_eq!(p.label(), "proxmox:root@pam");
        p.region = Some("pve".into());
        assert_eq!(p.label(), "proxmox:root@pam:pve");
    }

    #[test]
    fn provenance_tags_include_provider_and_present_scope() {
        let p = CloudProvenance {
            provider: "aws".into(),
            account: Some("123456789012".into()),
            region: Some("eu-west-1".into()),
            observed_at: Utc::now(),
        };
        assert_eq!(
            p.tags(),
            vec![
                "cloud:aws".to_string(),
                "cloud-account:123456789012".to_string(),
                "cloud-region:eu-west-1".to_string()
            ]
        );
    }

    #[test]
    fn parse_ip_cidr_strips_prefix_and_rejects_junk() {
        assert_eq!(
            parse_ip_cidr("10.0.0.5/24"),
            Some("10.0.0.5".parse().unwrap())
        );
        assert_eq!(
            parse_ip_cidr("2001:db8::1/64"),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(parse_ip_cidr("10.0.0.5"), Some("10.0.0.5".parse().unwrap()));
        assert_eq!(parse_ip_cidr("not-an-ip"), None);
    }

    #[test]
    fn cloud_asset_derives_the_reconciled_id() {
        let asset = cloud_asset(
            "10.0.0.5".parse().unwrap(),
            Some("vm-100".into()),
            "virtual-machine",
            Utc::now(),
        );
        assert_eq!(asset.id, "10-0-0-5");
        assert_eq!(asset.device_class.as_deref(), Some("virtual-machine"));
    }
}
