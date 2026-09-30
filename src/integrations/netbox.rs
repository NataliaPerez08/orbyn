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

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::process::Command;

use crate::http::{
    excerpt, is_retryable_curl_exit, is_retryable_status, split_http_status, with_retries, Attempt,
    CallFailure, RetryPolicy,
};
use crate::import::{ImportedAsset, ImportedInterface, ImportedInventory};
use crate::process::{is_timeout, run_captured, MAX_STDERR_CAPTURE_BYTES};

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
const NETBOX_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The origin of an absolute http(s) URL: scheme, host and effective port.
///
/// Hosts are lowercased reg-names or canonical IPv6 literals and ports are
/// normalized to the scheme default, so origins compare with `==`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UrlOrigin {
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: u16,
}

/// Parse the origin of an absolute http(s) URL under a strict grammar.
///
/// Accepted: `scheme://host[:port]/...` where the scheme is `http`/`https`
/// (case-insensitive), the host is a dotted reg-name of `[A-Za-z0-9.-]` or a
/// bracketed IPv6 literal, and the port is optional decimal digits. Anything
/// else — userinfo (`user:pass@host`), percent-encoding, empty ports, other
/// schemes, relative URLs — is rejected with `None`.
///
/// Pagination `next` URLs come from the server; a prefix check is not enough
/// (`https://netbox.example.com.evil/` and `https://netbox.example.com@evil/`
/// both pass one), so callers must compare parsed origins instead.
pub(crate) fn url_origin(url: &str) -> Option<UrlOrigin> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }

    // The authority runs to the first path/query/fragment separator.
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }
    // Userinfo is forbidden: under this grammar an '@' can only be a
    // userinfo separator (reg-names and IPv6 literals exclude it), and
    // `https://host@evil/` would otherwise send the token to `evil`.
    if authority.contains('@') {
        return None;
    }

    let (host, port_str, is_ipv6) = if let Some(bracketed) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal: `[::1]` or `[::1]:8443`. Canonicalized via
        // `Ipv6Addr` so equivalent literals compare equal.
        let (literal, after) = bracketed.split_once(']')?;
        let canonical = literal.parse::<Ipv6Addr>().ok()?.to_string();
        // Anything after `]` must be a port; bare junk is malformed.
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        (canonical, port, true)
    } else {
        match authority.rsplit_once(':') {
            // `host:port` — an unbracketed host never contains ':'.
            Some((host, port)) if !host.contains(':') => (host.to_string(), Some(port), false),
            _ => (authority.to_string(), None, false),
        }
    };

    let host = if is_ipv6 {
        host
    } else {
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return None;
        }
        host.to_ascii_lowercase()
    };

    let default_port = if scheme == "https" { 443 } else { 80 };
    let port = match port_str {
        Some(digits) => digits.parse::<u16>().ok()?,
        None => default_port,
    };

    Some(UrlOrigin { scheme, host, port })
}

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
    id: u64,
    name: Option<String>,
    role: Option<NamedRef>,
    tenant: Option<NamedRef>,
    primary_ip: Option<PrimaryIp>,
    #[serde(default)]
    tags: Vec<Tag>,
}

#[derive(Debug, Deserialize)]
struct NetBoxVm {
    id: u64,
    name: String,
    role: Option<NamedRef>,
    tenant: Option<NamedRef>,
    primary_ip: Option<PrimaryIp>,
    #[serde(default)]
    tags: Vec<Tag>,
}

/// The `device` / `virtual_machine` object embedded in interface rows.
#[derive(Debug, Deserialize)]
struct NetBoxInterfaceParent {
    id: u64,
}

/// An interface row from `dcim/interfaces` or `virtualization/interfaces`.
#[derive(Debug, Deserialize)]
struct NetBoxInterface {
    id: u64,
    name: Option<String>,
    mac_address: Option<String>,
    mtu: Option<u32>,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    device: Option<NetBoxInterfaceParent>,
    #[serde(default)]
    virtual_machine: Option<NetBoxInterfaceParent>,
}

/// An IP address row from `ipam/ip-addresses`.
#[derive(Debug, Deserialize)]
struct NetBoxIpAddress {
    address: String,
    #[serde(default)]
    dns_name: Option<String>,
    #[serde(default)]
    assigned_object_type: Option<String>,
    #[serde(default)]
    assigned_object_id: Option<u64>,
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

/// Assemble an import inventory from parsed NetBox endpoint payloads:
/// assets from devices + VMs, interfaces from `dcim/interfaces` +
/// `virtualization/interfaces`, and interface IPs (plus `dns_name` as a
/// hostname fallback) from `ipam/ip-addresses`.
///
/// Rows referencing parents Orbyn skipped (e.g. a device without a primary
/// IP) are dropped, mirroring the device-level skip.
pub fn parse_netbox_inventory(
    devices_json: &str,
    vms_json: &str,
    interfaces_json: &str,
    vm_interfaces_json: &str,
    ip_addresses_json: &str,
) -> Result<ImportedInventory> {
    let devices: NetBoxEnvelope<NetBoxDevice> =
        serde_json::from_str(devices_json).context("parsing NetBox devices response")?;
    let vms: NetBoxEnvelope<NetBoxVm> =
        serde_json::from_str(vms_json).context("parsing NetBox virtual machines response")?;
    let interfaces: NetBoxEnvelope<NetBoxInterface> =
        serde_json::from_str(interfaces_json).context("parsing NetBox interfaces response")?;
    let vm_interfaces: NetBoxEnvelope<NetBoxInterface> =
        serde_json::from_str(vm_interfaces_json)
            .context("parsing NetBox virtual machine interfaces response")?;
    let ip_addresses: NetBoxEnvelope<NetBoxIpAddress> =
        serde_json::from_str(ip_addresses_json).context("parsing NetBox IP addresses response")?;

    Ok(assemble_inventory(
        devices.results,
        vms.results,
        interfaces.results,
        vm_interfaces.results,
        ip_addresses.results,
    ))
}

fn assemble_inventory(
    devices: Vec<NetBoxDevice>,
    vms: Vec<NetBoxVm>,
    interfaces: Vec<NetBoxInterface>,
    vm_interfaces: Vec<NetBoxInterface>,
    ip_addresses: Vec<NetBoxIpAddress>,
) -> ImportedInventory {
    let mut assets: Vec<ImportedAsset> = Vec::new();
    let mut asset_by_device: HashMap<u64, usize> = HashMap::new();
    let mut asset_by_vm: HashMap<u64, usize> = HashMap::new();

    for device in devices {
        let netbox_id = device.id;
        if let Some(asset) = import_device(device) {
            asset_by_device.insert(netbox_id, assets.len());
            assets.push(asset);
        }
    }
    for vm in vms {
        let netbox_id = vm.id;
        if let Some(asset) = import_vm(vm) {
            asset_by_vm.insert(netbox_id, assets.len());
            assets.push(asset);
        }
    }

    // Interfaces carry no provider-independent id of their own; each row is
    // keyed by its NetBox id per endpoint (the two tables have independent
    // primary keys, so `assigned_object_type` disambiguates on lookup).
    struct InterfaceRow {
        interface: ImportedInterface,
        owner: usize,
    }

    let mut rows: Vec<InterfaceRow> = Vec::new();
    let mut row_by_interface: HashMap<(u64, u64), usize> = HashMap::new();

    let mut push_interface = |row: InterfaceRow, netbox_id: u64, vm: bool| {
        row_by_interface.insert((vm as u64, netbox_id), rows.len());
        rows.push(row);
    };

    for interface in interfaces {
        let Some(owner) = interface
            .device
            .as_ref()
            .and_then(|d| asset_by_device.get(&d.id))
        else {
            continue;
        };
        let netbox_id = interface.id;
        push_interface(
            InterfaceRow {
                interface: import_interface(interface, &assets[*owner]),
                owner: *owner,
            },
            netbox_id,
            false,
        );
    }
    for interface in vm_interfaces {
        let Some(owner) = interface
            .virtual_machine
            .as_ref()
            .and_then(|vm| asset_by_vm.get(&vm.id))
        else {
            continue;
        };
        let netbox_id = interface.id;
        push_interface(
            InterfaceRow {
                interface: import_interface(interface, &assets[*owner]),
                owner: *owner,
            },
            netbox_id,
            true,
        );
    }

    for ip in ip_addresses {
        let Some(interface_id) = ip.assigned_object_id else {
            continue;
        };
        let vm = ip
            .assigned_object_type
            .as_deref()
            .is_some_and(|t| t == "virtualization.vminterface");
        let Some(&row_index) = row_by_interface.get(&(vm as u64, interface_id)) else {
            continue;
        };
        let Some(address) = parse_ip(&ip.address) else {
            continue;
        };
        let row = &mut rows[row_index];
        if row.interface.ip.is_none() {
            row.interface.ip = Some(address);
        }
        // `dns_name` is the only hostname source for devices NetBox names
        // only by IP; an explicit device name always wins.
        if let Some(dns_name) = ip.dns_name.clone().filter(|d| !d.is_empty()) {
            if assets[row.owner].hostname.is_none() {
                assets[row.owner].hostname = Some(dns_name);
            }
        }
    }

    ImportedInventory {
        assets,
        interfaces: rows.into_iter().map(|r| r.interface).collect(),
        services: Vec::new(),
    }
}

fn import_interface(interface: NetBoxInterface, owner: &ImportedAsset) -> ImportedInterface {
    ImportedInterface {
        asset_id: owner.ip.clone(),
        name: interface.name,
        mac: interface.mac_address,
        ip: None,
        vendor: None,
        mtu: interface.mtu,
        if_index: None,
        is_up: Some(interface.enabled),
    }
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
    origin: UrlOrigin,
    token: Option<String>,
    insecure: bool,
    binary: String,
    retry: RetryPolicy,
}

impl NetBoxClient {
    /// Create a client for `base_url`, which must be an absolute http(s)
    /// URL without credentials; the token would otherwise be sent to a
    /// malformed destination.
    pub fn new(base_url: &str, token: Option<String>, insecure: bool) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        let origin = url_origin(&base_url).ok_or_else(|| {
            anyhow!(
                "invalid NetBox URL '{base_url}': expected an absolute http(s) \
                 URL without embedded credentials"
            )
        })?;
        Ok(Self {
            base_url,
            origin,
            token,
            insecure,
            binary: std::env::var("ORBYN_CURL_BIN").unwrap_or_else(|_| "curl".to_string()),
            retry: RetryPolicy::default(),
        })
    }

    /// Fetch devices, virtual machines, their interfaces and assigned IP
    /// addresses, and assemble a complete import inventory.
    pub async fn fetch_inventory(&self) -> Result<ImportedInventory> {
        let devices = self
            .fetch_pages::<NetBoxDevice>("/api/dcim/devices/")
            .await?;
        let vms = self
            .fetch_pages::<NetBoxVm>("/api/virtualization/virtual-machines/")
            .await?;
        let interfaces = self
            .fetch_pages::<NetBoxInterface>("/api/dcim/interfaces/")
            .await?;
        let vm_interfaces = self
            .fetch_pages::<NetBoxInterface>("/api/virtualization/interfaces/")
            .await?;
        let ip_addresses = self
            .fetch_pages::<NetBoxIpAddress>("/api/ipam/ip-addresses/")
            .await?;
        Ok(assemble_inventory(
            devices,
            vms,
            interfaces,
            vm_interfaces,
            ip_addresses,
        ))
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
            // The `next` URL is server-controlled: require an exact origin
            // match so the token is never sent to a redirected destination
            // (`https://netbox.example.com.evil/` and userinfo forms pass a
            // plain prefix check).
            if url_origin(&next).as_ref() != Some(&self.origin) {
                return Err(anyhow!("NetBox pagination returned an unexpected URL"));
            }
            url = next;
        }

        Err(anyhow!(
            "NetBox pagination exceeded the {} page limit",
            NETBOX_MAX_PAGES
        ))
    }

    /// GET one URL, replaying only the failures a later attempt could fix
    /// (timeouts, dropped connections, 429, 5xx).
    async fn get_url(&self, url: &str) -> Result<String> {
        with_retries(&self.retry, &format!("NetBox request to {url}"), |_| {
            self.get_once(url)
        })
        .await
    }

    /// One NetBox HTTP request: the response body, or a failure classified for
    /// retry.
    async fn get_once(&self, url: &str) -> Attempt<String> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("-sS")
            // The HTTP status is appended to stdout (3 digits) so a rate limit
            // or a server error is distinguishable from a good response
            // without -f, which would discard the body an operator needs.
            .arg("-w")
            .arg("%{http_code}");
        if self.insecure {
            cmd.arg("--insecure");
        }
        if self.token.is_some() {
            // Read the Authorization header from stdin (`-H @-`) so the token
            // never hits the filesystem or the process argument list.
            cmd.arg("-H").arg("@-");
        }
        cmd.arg(url)
            // Secret-bearing variables never reach the child environment
            // (audit OY-02): a hijacked curl must not be able to read the
            // community, the NetBox token, the WinRM password or the
            // database URL password.
            .env_remove("ORBYN_SNMP_COMMUNITY")
            .env_remove("ORBYN_NETBOX_TOKEN")
            .env_remove("ORBYN_WINRM_PASSWORD")
            .env_remove("ORBYN_PROMETHEUS_TOKEN")
            .env_remove("ORBYN_DB")
            .stdin(Stdio::piped())
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

        let stdin_payload = self.token.as_deref().map(token_header_line);
        let captured = match run_captured(
            child,
            stdin_payload.as_deref(),
            NETBOX_MAX_RESPONSE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
            NETBOX_REQUEST_TIMEOUT,
            format!("curl timed out against {url}"),
        )
        .await
        {
            Ok(captured) => captured,
            Err(e) if is_timeout(&e) => return Err(CallFailure::transient(format!("{e:#}"))),
            Err(e) => return Err(e.into()),
        };

        if captured.stdout.len() as u64 > NETBOX_MAX_RESPONSE_BYTES {
            return Err(CallFailure::permanent(format!(
                "NetBox response exceeds the {NETBOX_MAX_RESPONSE_BYTES} byte limit"
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
            let message = format!("NetBox returned HTTP {status} for {url}: {}", excerpt(body));
            return Err(if is_retryable_status(status) {
                CallFailure::transient(message)
            } else {
                CallFailure::permanent(message)
            });
        }
        Ok(body.to_string())
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
      {"id":101,"name":"rtr-core-1","role":{"name":"Router","slug":"router"},"tenant":{"name":"neteng"},"primary_ip":{"address":"10.0.0.1/24"},"tags":[{"name":"core"},{"name":"env:prod"}]},
      {"id":102,"name":"no-ip-device","role":{"name":"Switch","slug":"switch"},"primary_ip":null,"tags":[]}
    ]}"#;

    const VMS: &str = r#"{"count":1,"next":null,"results":[
      {"id":201,"name":"vm-web-01","role":{"name":"VM","slug":"vm"},"tenant":{"name":"appteam"},"primary_ip":{"address":"10.0.0.5/24"},"tags":[{"name":"staging"}]}
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
          {"id":1,"name":"bad","primary_ip":{"address":"not-an-ip"},"tags":[]}
        ]}"#;
        assert!(parse_netbox_devices(json).unwrap().is_empty());
    }

    #[test]
    fn role_slug_preferred_over_name() {
        let json = r#"{"count":1,"next":null,"results":[
          {"id":1,"name":"r1","role":{"name":"Router","slug":"router"},"primary_ip":{"address":"10.0.0.1/24"},"tags":[]}
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

    const EMPTY: &str = r#"{"count":0,"next":null,"results":[]}"#;

    fn inventory(
        devices: &str,
        vms: &str,
        interfaces: &str,
        vm_interfaces: &str,
        ip_addresses: &str,
    ) -> super::ImportedInventory {
        parse_netbox_inventory(devices, vms, interfaces, vm_interfaces, ip_addresses)
            .expect("assemble inventory")
    }

    #[test]
    fn inventory_maps_interfaces_and_assigned_ips() {
        let interfaces = r#"{"count":1,"next":null,"results":[
          {"id":301,"device":{"id":101},"name":"eth0","mac_address":"AA:BB:CC:DD:EE:01","mtu":1500,"enabled":true}
        ]}"#;
        let vm_interfaces = r#"{"count":1,"next":null,"results":[
          {"id":401,"virtual_machine":{"id":201},"name":"ens3","mac_address":null,"mtu":null,"enabled":false}
        ]}"#;
        let ips = r#"{"count":2,"next":null,"results":[
          {"address":"10.0.0.1/24","dns_name":"rtr-core-1.dns.example.com","assigned_object_type":"dcim.interface","assigned_object_id":301},
          {"address":"10.0.0.5/24","dns_name":"","assigned_object_type":"virtualization.vminterface","assigned_object_id":401}
        ]}"#;

        let inv = inventory(DEVICES, VMS, interfaces, vm_interfaces, ips);
        assert_eq!(inv.assets.len(), 2);
        assert_eq!(inv.interfaces.len(), 2);

        let eth = &inv.interfaces[0];
        assert_eq!(eth.asset_id, "10.0.0.1");
        assert_eq!(eth.name.as_deref(), Some("eth0"));
        assert_eq!(eth.mac.as_deref(), Some("AA:BB:CC:DD:EE:01"));
        assert_eq!(eth.mtu, Some(1500));
        assert_eq!(eth.is_up, Some(true));
        assert_eq!(eth.ip.map(|i| i.to_string()).as_deref(), Some("10.0.0.1"));

        let ens = &inv.interfaces[1];
        assert_eq!(ens.asset_id, "10.0.0.5");
        assert_eq!(ens.is_up, Some(false));
        assert_eq!(ens.ip.map(|i| i.to_string()).as_deref(), Some("10.0.0.5"));

        // The device already has a name, so dns_name must not override it.
        assert_eq!(
            inv.assets[0].hostname.as_deref(),
            Some("rtr-core-1"),
            "explicit device name wins over dns_name"
        );
    }

    #[test]
    fn inventory_skips_interfaces_of_skipped_parents() {
        // Interface 302 belongs to the device without a primary IP, which is
        // skipped at the asset level; its rows must not dangle.
        let interfaces = r#"{"count":2,"next":null,"results":[
          {"id":301,"device":{"id":101},"name":"eth0","enabled":true},
          {"id":302,"device":{"id":102},"name":"eth0","enabled":true}
        ]}"#;
        let ips = r#"{"count":1,"next":null,"results":[
          {"address":"10.0.0.9/24","dns_name":"orphan.dns.example.com","assigned_object_type":"dcim.interface","assigned_object_id":302}
        ]}"#;

        let inv = inventory(DEVICES, VMS, interfaces, EMPTY, ips);
        assert_eq!(inv.assets.len(), 2);
        assert_eq!(inv.interfaces.len(), 1, "orphan interface is skipped");
        assert_eq!(inv.interfaces[0].asset_id, "10.0.0.1");
        assert!(
            !inv.assets
                .iter()
                .any(|a| a.hostname.as_deref() == Some("orphan.dns.example.com")),
            "dns_name of an orphan IP must not leak into other assets"
        );
    }

    #[test]
    fn inventory_fills_missing_hostname_from_dns_name() {
        let devices = r#"{"count":1,"next":null,"results":[
          {"id":111,"name":null,"primary_ip":{"address":"10.0.0.7/24"},"tags":[]}
        ]}"#;
        let interfaces = r#"{"count":1,"next":null,"results":[
          {"id":311,"device":{"id":111},"name":"eth0","enabled":true}
        ]}"#;
        let ips = r#"{"count":1,"next":null,"results":[
          {"address":"10.0.0.7/24","dns_name":"sw-1.dns.example.com","assigned_object_type":"dcim.interface","assigned_object_id":311}
        ]}"#;

        let inv = inventory(devices, EMPTY, interfaces, EMPTY, ips);
        assert_eq!(
            inv.assets[0].hostname.as_deref(),
            Some("sw-1.dns.example.com")
        );
    }

    #[test]
    fn inventory_disambiguates_interface_ids_by_assigned_object_type() {
        // dcim interface 500 and vminterface 500 share an id; each IP must
        // land on its own interface.
        let interfaces = r#"{"count":1,"next":null,"results":[
          {"id":500,"device":{"id":101},"name":"eth0","enabled":true}
        ]}"#;
        let vm_interfaces = r#"{"count":1,"next":null,"results":[
          {"id":500,"virtual_machine":{"id":201},"name":"ens3","enabled":true}
        ]}"#;
        let ips = r#"{"count":2,"next":null,"results":[
          {"address":"10.0.0.1/24","dns_name":null,"assigned_object_type":"dcim.interface","assigned_object_id":500},
          {"address":"10.0.0.5/24","dns_name":null,"assigned_object_type":"virtualization.vminterface","assigned_object_id":500}
        ]}"#;

        let inv = inventory(DEVICES, VMS, interfaces, vm_interfaces, ips);
        assert_eq!(inv.interfaces.len(), 2);
        assert_eq!(inv.interfaces[0].asset_id, "10.0.0.1");
        assert_eq!(
            inv.interfaces[0].ip.map(|i| i.to_string()).as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(inv.interfaces[1].asset_id, "10.0.0.5");
        assert_eq!(
            inv.interfaces[1].ip.map(|i| i.to_string()).as_deref(),
            Some("10.0.0.5")
        );
    }

    #[test]
    fn inventory_without_interfaces_or_ips_still_imports_assets() {
        let inv = inventory(DEVICES, VMS, EMPTY, EMPTY, EMPTY);
        assert_eq!(inv.assets.len(), 2);
        assert!(inv.interfaces.is_empty());
        assert!(inv.services.is_empty());
    }

    #[test]
    fn url_origin_parses_scheme_host_and_port() {
        let o = url_origin("https://netbox.example.com:8443/api/dcim/devices/")
            .expect("absolute https URL with port");
        assert_eq!(o.scheme, "https");
        assert_eq!(o.host, "netbox.example.com");
        assert_eq!(o.port, 8443);
    }

    #[test]
    fn url_origin_normalizes_case_and_default_ports() {
        assert_eq!(
            url_origin("https://NetBox.Example.COM"),
            url_origin("https://netbox.example.com:443/api/dcim/devices/")
        );
        assert_eq!(url_origin("http://host:80/"), url_origin("http://host/"));
        assert_ne!(
            url_origin("http://host/"),
            url_origin("https://host/"),
            "scheme is part of the origin"
        );
    }

    #[test]
    fn url_origin_accepts_ipv6_literals() {
        let o = url_origin("https://[2001:db8::1]:8443/api").expect("bracketed IPv6");
        assert_eq!(o.host, "2001:db8::1");
        assert_eq!(o.port, 8443);
        assert_eq!(
            Some(o),
            url_origin("https://[2001:0DB8:0000:0000:0000:0000:0000:0001]:8443/x")
        );
        assert!(url_origin("https://[not-ipv6]/api").is_none());
        assert!(
            url_origin("https://[::1]garbage/api").is_none(),
            "trailing junk after the IPv6 literal is malformed"
        );
    }

    #[test]
    fn url_origin_rejects_userinfo_and_malformed_forms() {
        // userinfo in all shapes
        assert!(url_origin("https://netbox.example.com@evil.com/api").is_none());
        assert!(url_origin("https://user:pass@netbox.example.com/api").is_none());
        // non-http(s) schemes
        assert!(url_origin("file:///etc/passwd").is_none());
        assert!(url_origin("gopher://netbox.example.com/x").is_none());
        // relative or scheme-less
        assert!(url_origin("/api/dcim/devices/").is_none());
        assert!(url_origin("netbox.example.com/api").is_none());
        assert!(url_origin("").is_none());
        assert!(url_origin("https://").is_none());
        // empty port, percent-encoding, whitespace, unbracketed IPv6
        assert!(url_origin("https://netbox.example.com:/api").is_none());
        assert!(url_origin("https://net%62ox.example.com/api").is_none());
        assert!(url_origin("https://net box.example.com/api").is_none());
        assert!(url_origin("https://::1/api").is_none());
    }

    #[test]
    fn hostile_next_urls_fail_the_origin_check() {
        let base = url_origin("https://netbox.example.com").expect("valid base");
        // Prefix-passing but different host: the core #36 regression.
        assert_ne!(
            Some(base.clone()),
            url_origin("https://netbox.example.com.evil/api/dcim/devices/")
        );
        // Userinfo form: unparseable under the strict grammar.
        assert!(url_origin("https://netbox.example.com@evil.com/api").is_none());
        // Scheme or port mismatch.
        assert_ne!(
            Some(base.clone()),
            url_origin("http://netbox.example.com/api")
        );
        assert_ne!(
            Some(base.clone()),
            url_origin("https://netbox.example.com:8443/api")
        );
        // A completely different host.
        assert_ne!(Some(base.clone()), url_origin("https://evil.com/api"));
    }

    #[test]
    fn legitimate_next_urls_pass_the_origin_check() {
        let base = url_origin("https://netbox.example.com").expect("valid base");
        assert_eq!(
            Some(base.clone()),
            url_origin("https://netbox.example.com/api/dcim/devices/?limit=100&page=2&offset=100")
        );
        // Explicit default port is the same origin.
        assert_eq!(
            Some(base.clone()),
            url_origin("https://netbox.example.com:443/api/dcim/devices/?page=2")
        );
        // Same origin behind a subpath proxy.
        assert_eq!(
            Some(base),
            url_origin("https://netbox.example.com/netbox/api/dcim/devices/")
        );
    }

    #[test]
    fn netbox_client_validates_the_base_url() {
        assert!(NetBoxClient::new("https://netbox.example.com", None, false).is_ok());
        assert!(NetBoxClient::new("http://netbox.internal:8000/", None, false).is_ok());
        assert!(NetBoxClient::new("https://user@netbox.example.com", None, false).is_err());
        assert!(NetBoxClient::new("not-a-url", None, false).is_err());
        assert!(NetBoxClient::new("ftp://netbox.example.com", None, false).is_err());
    }
}
