//! NetBox source-of-truth importer (v1.1).
//!
//! Reads devices and virtual machines from the NetBox REST API and maps them
//! onto the normalized asset model. Read-only: Orbyn never writes back to
//! NetBox.
//!
//! The API is queried through the `curl` binary (consistent with the rest of
//! the collector surface). The API token is streamed to curl through stdin as
//! an `Authorization` header (`-H @-`), so it never appears in process
//! arguments, logs, disk, or CLI output.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::import::ImportedAsset;

/// Paginated NetBox envelope.
#[derive(Debug, Deserialize)]
struct NetBoxEnvelope<T> {
    results: Vec<T>,
    #[serde(default)]
    next: Option<String>,
}

const NETBOX_PAGE_SIZE: usize = 100;
const NETBOX_MAX_PAGES: usize = 10_000;
const NETBOX_MAX_RECORDS: usize = 1_000_000;
const NETBOX_MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
struct NamedRef {
    name: Option<String>,
    slug: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrimaryIp {
    address: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Tag {
    name: String,
}

#[derive(Debug, Deserialize)]
struct NetBoxDevice {
    name: Option<String>,
    role: Option<NamedRef>,
    tenant: Option<NamedRef>,
    primary_ip: Option<PrimaryIp>,
    #[serde(default)]
    tags: Vec<Tag>,
}

#[derive(Debug, Deserialize)]
struct NetBoxVm {
    name: String,
    role: Option<NamedRef>,
    tenant: Option<NamedRef>,
    primary_ip: Option<PrimaryIp>,
    #[serde(default)]
    tags: Vec<Tag>,
}

/// Parse the `/api/dcim/devices/` response into import rows.
pub fn parse_netbox_devices(json: &str) -> Result<Vec<ImportedAsset>> {
    let envelope: NetBoxEnvelope<NetBoxDevice> =
        serde_json::from_str(json).context("parsing NetBox devices response")?;
    Ok(envelope
        .results
        .into_iter()
        .filter_map(|d| {
            let ip = parse_ip(d.primary_ip.as_ref()?.address.as_deref()?)?;
            let tags: Vec<String> = d.tags.into_iter().map(|t| t.name).collect();
            Some(ImportedAsset {
                ip: ip.to_string(),
                hostname: d.name,
                device_class: Some(
                    d.role
                        .and_then(|r| r.slug.or(r.name))
                        .unwrap_or_else(|| "device".into()),
                ),
                os_name: None,
                os_version: None,
                environment: env_from_tags(&tags),
                owner: d.tenant.and_then(|t| t.name),
                criticality: None,
                tags,
            })
        })
        .collect())
}

/// Parse the `/api/virtualization/virtual-machines/` response into import rows.
pub fn parse_netbox_vms(json: &str) -> Result<Vec<ImportedAsset>> {
    let envelope: NetBoxEnvelope<NetBoxVm> =
        serde_json::from_str(json).context("parsing NetBox virtual machines response")?;
    Ok(envelope
        .results
        .into_iter()
        .filter_map(|vm| {
            let ip = parse_ip(vm.primary_ip.as_ref()?.address.as_deref()?)?;
            let tags: Vec<String> = vm.tags.into_iter().map(|t| t.name).collect();
            Some(ImportedAsset {
                ip: ip.to_string(),
                hostname: Some(vm.name),
                device_class: Some(
                    vm.role
                        .and_then(|r| r.slug.or(r.name))
                        .unwrap_or_else(|| "virtual-machine".into()),
                ),
                os_name: None,
                os_version: None,
                environment: env_from_tags(&tags),
                owner: vm.tenant.and_then(|t| t.name),
                criticality: None,
                tags,
            })
        })
        .collect())
}

/// Strip a CIDR suffix and validate the address.
fn parse_ip(address: &str) -> Option<std::net::IpAddr> {
    let host = address.split('/').next().unwrap_or(address);
    host.parse().ok()
}

/// Derive an environment from `env:<x>` or common environment tag names.
fn env_from_tags(tags: &[String]) -> Option<String> {
    for tag in tags {
        if let Some(rest) = tag.strip_prefix("env:") {
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    for tag in tags {
        if matches!(
            tag.as_str(),
            "prod"
                | "production"
                | "staging"
                | "dev"
                | "development"
                | "qa"
                | "test"
                | "dr"
                | "preprod"
                | "sandbox"
        ) {
            return Some(tag.clone());
        }
    }
    None
}

/// A read-only NetBox API client backed by the `curl` binary.
pub struct NetBoxClient {
    base_url: String,
    token: Option<String>,
    insecure: bool,
    binary: String,
}

impl NetBoxClient {
    pub fn new(base_url: &str, token: Option<String>, insecure: bool) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            insecure,
            binary: std::env::var("ORBYN_CURL_BIN").unwrap_or_else(|_| "curl".to_string()),
        }
    }

    /// Fetch and parse all devices.
    pub async fn fetch_devices(&self) -> Result<Vec<ImportedAsset>> {
        let devices: Vec<NetBoxDevice> = self.fetch_pages("/api/dcim/devices/").await?;
        Ok(devices.into_iter().filter_map(import_device).collect())
    }

    /// Fetch and parse all virtual machines.
    pub async fn fetch_vms(&self) -> Result<Vec<ImportedAsset>> {
        let vms: Vec<NetBoxVm> = self
            .fetch_pages("/api/virtualization/virtual-machines/")
            .await?;
        Ok(vms.into_iter().filter_map(import_vm).collect())
    }

    async fn fetch_pages<T: DeserializeOwned>(&self, path: &str) -> Result<Vec<T>> {
        let mut url = format!("{}{path}?limit={NETBOX_PAGE_SIZE}", self.base_url);
        let mut records = Vec::new();

        for page in 0..NETBOX_MAX_PAGES {
            let json = self.get_url(&url).await?;
            let envelope: NetBoxEnvelope<T> = serde_json::from_str(&json)
                .with_context(|| format!("parsing NetBox response page {}", page + 1))?;
            records.extend(envelope.results);
            if records.len() > NETBOX_MAX_RECORDS {
                return Err(anyhow!(
                    "NetBox response exceeds the {} record limit",
                    NETBOX_MAX_RECORDS
                ));
            }

            let Some(next) = envelope.next.filter(|next| !next.trim().is_empty()) else {
                return Ok(records);
            };
            if !next.starts_with(&self.base_url) {
                return Err(anyhow!("NetBox pagination returned an unexpected URL"));
            }
            url = next;
        }

        Err(anyhow!(
            "NetBox pagination exceeded the {} page limit",
            NETBOX_MAX_PAGES
        ))
    }

    async fn get_url(&self, url: &str) -> Result<String> {
        let has_token = self.token.is_some();

        let mut cmd = Command::new(&self.binary);
        cmd.arg("-sS");
        if self.insecure {
            cmd.arg("--insecure");
        }
        if has_token {
            // Read the Authorization header from stdin (`-H @-`) so the token
            // never hits the filesystem or the process argument list.
            cmd.arg("-H").arg("@-");
        }
        cmd.arg(url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .context("failed to start curl; is it installed?")?;

        match &self.token {
            Some(token) => {
                if let Some(mut stdin) = child.stdin.take() {
                    use tokio::io::AsyncWriteExt;
                    stdin
                        .write_all(token_header_line(token).as_bytes())
                        .await
                        .context("writing NetBox token header to curl stdin")?;
                    stdin.shutdown().await.ok();
                }
            }
            None => {
                // Close stdin so an unexpectedly header-reading curl still
                // reaches EOF instead of blocking.
                child.stdin.take();
            }
        }

        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(out) = child.stdout.take() {
            let mut limited = out.take(NETBOX_MAX_RESPONSE_BYTES + 1);
            limited
                .read_to_string(&mut stdout)
                .await
                .context("reading curl stdout")?;
            if stdout.len() as u64 > NETBOX_MAX_RESPONSE_BYTES {
                return Err(anyhow!(
                    "NetBox response exceeds the {} byte limit",
                    NETBOX_MAX_RESPONSE_BYTES
                ));
            }
        }
        if let Some(mut err) = child.stderr.take() {
            err.read_to_string(&mut stderr)
                .await
                .context("reading curl stderr")?;
        }
        let status = timeout(Duration::from_secs(60), child.wait())
            .await
            .map_err(|_| anyhow!("curl timed out against {url}"))?
            .context("waiting for curl")?;

        if !status.success() {
            return Err(anyhow!("curl exited with {status}: {}", stderr.trim()));
        }
        Ok(stdout)
    }
}

fn import_device(d: NetBoxDevice) -> Option<ImportedAsset> {
    let ip = parse_ip(d.primary_ip.as_ref()?.address.as_deref()?)?;
    let tags: Vec<String> = d.tags.into_iter().map(|t| t.name).collect();
    Some(ImportedAsset {
        ip: ip.to_string(),
        hostname: d.name,
        device_class: Some(
            d.role
                .and_then(|r| r.slug.or(r.name))
                .unwrap_or_else(|| "device".into()),
        ),
        os_name: None,
        os_version: None,
        environment: env_from_tags(&tags),
        owner: d.tenant.and_then(|t| t.name),
        criticality: None,
        tags,
    })
}

fn import_vm(vm: NetBoxVm) -> Option<ImportedAsset> {
    let ip = parse_ip(vm.primary_ip.as_ref()?.address.as_deref()?)?;
    let tags: Vec<String> = vm.tags.into_iter().map(|t| t.name).collect();
    Some(ImportedAsset {
        ip: ip.to_string(),
        hostname: Some(vm.name),
        device_class: Some(
            vm.role
                .and_then(|r| r.slug.or(r.name))
                .unwrap_or_else(|| "virtual-machine".into()),
        ),
        os_name: None,
        os_version: None,
        environment: env_from_tags(&tags),
        owner: vm.tenant.and_then(|t| t.name),
        criticality: None,
        tags,
    })
}

/// The Authorization header line curl reads from stdin via `-H @-`.
fn token_header_line(token: &str) -> String {
    format!("Authorization: Token {token}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICES: &str = r#"{"count":2,"next":null,"results":[
      {"name":"rtr-core-1","role":{"name":"Router","slug":"router"},"tenant":{"name":"neteng"},"primary_ip":{"address":"10.0.0.1/24"},"tags":[{"name":"core"},{"name":"env:prod"}]},
      {"name":"no-ip-device","role":{"name":"Switch","slug":"switch"},"primary_ip":null,"tags":[]}
    ]}"#;

    const VMS: &str = r#"{"count":1,"next":null,"results":[
      {"name":"vm-web-01","role":{"name":"VM","slug":"vm"},"tenant":{"name":"appteam"},"primary_ip":{"address":"10.0.0.5/24"},"tags":[{"name":"staging"}]}
    ]}"#;

    #[test]
    fn parses_devices_and_skips_missing_ip() {
        let rows = parse_netbox_devices(DEVICES).expect("parse devices");
        assert_eq!(rows.len(), 1, "device without primary_ip is skipped");
        let r = &rows[0];
        assert_eq!(r.ip, "10.0.0.1");
        assert_eq!(r.hostname.as_deref(), Some("rtr-core-1"));
        assert_eq!(r.device_class.as_deref(), Some("router"));
        assert_eq!(r.owner.as_deref(), Some("neteng"));
        assert_eq!(r.environment.as_deref(), Some("prod"));
        assert_eq!(r.tags, vec!["core".to_string(), "env:prod".to_string()]);
    }

    #[test]
    fn parses_vms_with_common_env_tag() {
        let rows = parse_netbox_vms(VMS).expect("parse vms");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_class.as_deref(), Some("vm"));
        assert_eq!(rows[0].environment.as_deref(), Some("staging"));
        assert_eq!(rows[0].owner.as_deref(), Some("appteam"));
    }

    #[test]
    fn env_tag_priority_and_fallback() {
        assert_eq!(env_from_tags(&["env:dr".into()]), Some("dr".into()));
        assert_eq!(
            env_from_tags(&["core".into(), "prod".into()]),
            Some("prod".into())
        );
        assert_eq!(env_from_tags(&["core".into()]), None);
        assert_eq!(env_from_tags(&["env:".into()]), None);
    }

    #[test]
    fn invalid_ip_is_skipped() {
        let json = r#"{"count":1,"next":null,"results":[
          {"name":"bad","primary_ip":{"address":"not-an-ip"},"tags":[]}
        ]}"#;
        assert!(parse_netbox_devices(json).unwrap().is_empty());
    }

    #[test]
    fn role_slug_preferred_over_name() {
        let json = r#"{"count":1,"next":null,"results":[
          {"name":"r1","role":{"name":"Router","slug":"router"},"primary_ip":{"address":"10.0.0.1/24"},"tags":[]}
        ]}"#;
        let rows = parse_netbox_devices(json).unwrap();
        assert_eq!(rows[0].device_class.as_deref(), Some("router"));
    }

    #[test]
    fn token_header_line_is_exact() {
        assert_eq!(
            token_header_line("supersecret"),
            "Authorization: Token supersecret\n"
        );
    }
}
