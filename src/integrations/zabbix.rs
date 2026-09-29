//! Zabbix historical utilization importer.
//!
//! Pulls CPU/RAM/swap utilization from a Zabbix JSON-RPC API (`host.get`,
//! `item.get`, `history.get`) and turns them into [`MetricSample`] rows, so
//! an asset monitored by Zabbix carries the same kind of real observation
//! window the Prometheus importer produces. Read-only: Orbyn never writes to
//! Zabbix, and only ever calls methods that read.
//!
//! The API is called through the `curl` binary, consistent with the rest of
//! the integration surface. The JSON-RPC envelope — which carries the API
//! token in its `auth` field, since Zabbix has no header-based auth — is
//! piped to curl on stdin (`--data-binary @-`), so the token never appears in
//! process arguments, logs, disk, or CLI output.
//!
//! Only these item keys are read, and only for monitored hosts:
//!
//! | key                        | maps to            | unit |
//! |----------------------------|--------------------|------|
//! | `system.cpu.util`          | `cpu_usage_percent` | %    |
//! | `vm.memory.size`           | RAM total          | B    |
//! | `vm.memory.size[pavailable]`| `ram_used_mb` (total − available) | B |
//! | `vm.memory.size[pswapused]`| `swap_used_mb`     | B    |
//!
//! Memory items are only accepted when Zabbix reports their unit as bytes.
//! A setup that preprocesses to MiB would otherwise be recorded as 1/1024th
//! of the truth, and such items are skipped and reported instead.
//!
//! Hosts are mapped onto the inventory by interface IP first, then by host
//! name. A host matching nothing is reported, never guessed.

use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::process::Command;

use crate::domain::{Asset, MetricSample};
use crate::process::{run_captured, MAX_STDERR_CAPTURE_BYTES};

use super::netbox::url_origin;

const ZABBIX_MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const ZABBIX_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Hard cap on accepted history points per value type: a week of hourly
/// floats across dozens of hosts is already thousands of points, so 100k
/// bounds a hostile or misconfigured endpoint without blocking real estates.
const ZABBIX_MAX_POINTS: usize = 100_000;

/// Hard cap on hosts considered in one import.
const ZABBIX_MAX_HOSTS: usize = 5_000;

/// Zabbix `value_type` of a float item, whose history lives in table
/// `history` (as opposed to `history_uint`).
const VALUE_TYPE_FLOAT: u8 = 0;
/// Zabbix `value_type` of an unsigned item.
const VALUE_TYPE_UNSIGNED: u8 = 3;

/// Zabbix JSON-RPC history parameter for float history.
const HISTORY_FLOAT: u8 = 0;
/// Zabbix JSON-RPC history parameter for unsigned history.
const HISTORY_UNSIGNED: u8 = 3;

/// Item keys this importer understands, in request order.
const CPU_KEY: &str = "system.cpu.util";
const RAM_TOTAL_KEY: &str = "vm.memory.size";
const RAM_AVAILABLE_KEY: &str = "vm.memory.size[pavailable]";
const SWAP_USED_KEY: &str = "vm.memory.size[pswapused]";

const SUPPORTED_KEYS: [&str; 4] = [CPU_KEY, RAM_TOTAL_KEY, RAM_AVAILABLE_KEY, SWAP_USED_KEY];

/// A read-only Zabbix JSON-RPC client backed by the `curl` binary.
pub struct ZabbixClient {
    endpoint: String,
    token: Option<String>,
    insecure: bool,
    binary: String,
}

/// Parameters of one utilization import.
pub struct ImportOptions {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// One Zabbix host as returned by `host.get`, reduced to the fields the
/// importer needs to map it onto an asset.
#[derive(Debug, Clone, PartialEq)]
pub struct ZabbixHost {
    pub hostid: String,
    /// Technical name (`host`).
    pub host: String,
    /// Visible name (`name`).
    pub name: String,
    /// Interface addresses, IP first.
    pub addresses: Vec<String>,
}

/// One Zabbix item, reduced to the fields the importer needs.
#[derive(Debug, Clone, PartialEq)]
pub struct ZabbixItem {
    pub itemid: String,
    pub hostid: String,
    pub key: String,
    pub value_type: u8,
    /// Reported unit, e.g. `B` or `%`.
    pub units: String,
}

/// One history point: an item's value at a clock time.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryPoint {
    /// Kept as a string to match `item.get`'s ids without re-parsing.
    pub itemid: String,
    pub clock: i64,
    pub value: f64,
}

/// The raw result of the API calls, before inventory mapping.
#[derive(Debug, Default)]
pub struct FetchedUtilization {
    pub hosts: Vec<ZabbixHost>,
    pub items: Vec<ZabbixItem>,
    pub points: Vec<HistoryPoint>,
    /// Points dropped because their clock or value did not parse.
    pub skipped_points: usize,
    /// Items that were found but cannot be used: unknown key, or a memory
    /// item whose unit is not bytes.
    pub unsupported_items: usize,
    /// Hosts that had no usable utilization item at all.
    pub hosts_without_items: usize,
}

/// Metric samples assembled against the current inventory.
#[derive(Debug, Default)]
pub struct AssembledSamples {
    pub samples: Vec<MetricSample>,
    /// Hosts whose IP or name matched no known asset.
    pub unmatched_hosts: usize,
}

impl ZabbixClient {
    /// Create a client for a Zabbix JSON-RPC `endpoint`, which must be an
    /// absolute http(s) URL without credentials; a token would otherwise be
    /// sent to a malformed destination.
    pub fn new(endpoint: &str, token: Option<String>, insecure: bool) -> Result<Self> {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        if url_origin(&endpoint).is_none() {
            return Err(anyhow!(
                "invalid Zabbix URL '{endpoint}': expected an absolute http(s) \
                 URL without embedded credentials (the JSON-RPC endpoint, e.g. \
                 https://zabbix.example.com/zabbix/api_jsonrpc.php)"
            ));
        }
        Ok(Self {
            endpoint,
            token,
            insecure,
            binary: std::env::var("ORBYN_CURL_BIN").unwrap_or_else(|_| "curl".to_string()),
        })
    }

    /// Read hosts, their utilization items, and the history in the window.
    pub async fn fetch_utilization(&self, opts: &ImportOptions) -> Result<FetchedUtilization> {
        let hosts: Vec<HostDto> = self
            .call(
                "host.get",
                json!({
                    "output": ["hostid", "host", "name"],
                    "selectInterfaces": ["ip", "dns"],
                    "filter": { "status": 0 },
                    "sortfield": "hostid",
                    "limit": ZABBIX_MAX_HOSTS,
                }),
            )
            .await?;
        if hosts.len() >= ZABBIX_MAX_HOSTS {
            tracing::warn!(
                limit = ZABBIX_MAX_HOSTS,
                "Zabbix host list hit the import limit; hosts beyond it were not considered"
            );
        }

        let hostids: Vec<String> = hosts.iter().map(|h| h.hostid.clone()).collect();
        let items: Vec<ItemDto> = if hostids.is_empty() {
            Vec::new()
        } else {
            self.call(
                "item.get",
                json!({
                    "output": ["itemid", "hostid", "key_", "value_type", "units"],
                    "filter": { "hostid": hostids, "key_": SUPPORTED_KEYS },
                    "webitems": false,
                    "sortfield": "itemid",
                }),
            )
            .await?
        };

        let value_types: Vec<u8> = {
            let mut types: Vec<u8> = items.iter().map(|i| i.value_type).collect();
            types.sort_unstable();
            types.dedup();
            types
        };
        let mut points: Vec<HistoryPoint> = Vec::new();
        let mut skipped_points = 0usize;
        for value_type in value_types {
            let itemids: Vec<String> = items
                .iter()
                .filter(|i| i.value_type == value_type)
                .map(|i| i.itemid.clone())
                .collect();
            let (mut batch, skipped) = self.fetch_history(&itemids, value_type, opts).await?;
            skipped_points += skipped;
            if points.len() + batch.len() > ZABBIX_MAX_POINTS {
                batch.truncate(ZABBIX_MAX_POINTS - points.len());
                tracing::warn!(
                    limit = ZABBIX_MAX_POINTS,
                    "Zabbix history hit the import point limit; older points were dropped"
                );
            }
            points.append(&mut batch);
        }
        points.sort_by(|a, b| a.itemid.cmp(&b.itemid).then_with(|| a.clock.cmp(&b.clock)));

        let hosts: Vec<ZabbixHost> = hosts.into_iter().map(HostDto::into_host).collect();
        let items: Vec<ZabbixItem> = items.into_iter().map(ItemDto::into_item).collect();
        let mut hosts_without_items = 0usize;
        for host in &hosts {
            if !items.iter().any(|item| item.hostid == host.hostid) {
                hosts_without_items += 1;
            }
        }
        let unsupported_items = items.iter().filter(|i| usable_item(i).is_none()).count();

        Ok(FetchedUtilization {
            hosts,
            items,
            points,
            skipped_points,
            unsupported_items,
            hosts_without_items,
        })
    }

    /// One `history.get` call for every item of one value type.
    async fn fetch_history(
        &self,
        itemids: &[String],
        value_type: u8,
        opts: &ImportOptions,
    ) -> Result<(Vec<HistoryPoint>, usize)> {
        if itemids.is_empty() {
            return Ok((Vec::new(), 0));
        }
        let history = match value_type {
            VALUE_TYPE_FLOAT => HISTORY_FLOAT,
            VALUE_TYPE_UNSIGNED => HISTORY_UNSIGNED,
            other => {
                return Err(anyhow!(
                    "unsupported Zabbix value_type {other}; only float and unsigned \
                     items carry numeric utilization"
                ))
            }
        };
        let rows: Vec<HistoryRow> = self
            .call(
                "history.get",
                json!({
                    "output": "extend",
                    "history": history,
                    "itemids": itemids,
                    "time_from": opts.start.timestamp(),
                    "time_till": opts.end.timestamp(),
                    "sortfield": "clock",
                    "sortorder": "ASC",
                    "limit": ZABBIX_MAX_POINTS,
                }),
            )
            .await?;
        let mut points = Vec::with_capacity(rows.len());
        let mut skipped = 0usize;
        for row in rows {
            let itemid = row.itemid.as_ref().and_then(as_id);
            let clock = row.clock.as_ref().and_then(as_i64);
            let value = match &row.value {
                Some(Value::String(raw)) => raw.parse::<f64>().ok(),
                Some(Value::Number(n)) => n.as_f64(),
                _ => None,
            };
            match (itemid, clock, value) {
                (Some(itemid), Some(clock), Some(value)) if value.is_finite() => {
                    points.push(HistoryPoint {
                        itemid,
                        clock,
                        value,
                    })
                }
                _ => skipped += 1,
            }
        }
        Ok((points, skipped))
    }

    /// Issue one JSON-RPC call and return its `result`.
    async fn call<T: serde::de::DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let mut envelope = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        });
        if let (Some(token), Some(object)) = (self.token.as_deref(), envelope.as_object_mut()) {
            object.insert("auth".into(), json!(token));
        }
        let body = serde_json::to_string(&envelope).context("building Zabbix JSON-RPC envelope")?;
        let response = self.post(&body).await?;
        let parsed: RpcResponse = serde_json::from_str(&response)
            .with_context(|| format!("parsing Zabbix response to {method}"))?;
        if let Some(error) = parsed.error {
            return Err(anyhow!(
                "Zabbix {method} failed: {} (code {}, message {})",
                error.message,
                error.code,
                error.data.unwrap_or_else(|| "none".into())
            ));
        }
        let result = parsed
            .result
            .ok_or_else(|| anyhow!("Zabbix {method} returned neither result nor error"))?;
        serde_json::from_value(result).with_context(|| format!("decoding Zabbix {method} result"))
    }

    /// POST a JSON-RPC envelope through curl, with the envelope on stdin so
    /// the API token never reaches the process argument list.
    async fn post(&self, body: &str) -> Result<String> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("-sS")
            .arg("-X")
            .arg("POST")
            .arg("-H")
            .arg("Content-Type: application/json-rpc")
            .arg("--data-binary")
            .arg("@-");
        if self.insecure {
            cmd.arg("--insecure");
        }
        cmd.arg(&self.endpoint)
            // Secret-bearing variables never reach the child environment
            // (audit OY-02): a hijacked curl must not be able to read the
            // community, the NetBox token, the WinRM password, the
            // Prometheus or Zabbix token, or the database URL password.
            .env_remove("ORBYN_SNMP_COMMUNITY")
            .env_remove("ORBYN_NETBOX_TOKEN")
            .env_remove("ORBYN_WINRM_PASSWORD")
            .env_remove("ORBYN_PROMETHEUS_TOKEN")
            .env_remove("ORBYN_ZABBIX_TOKEN")
            .env_remove("ORBYN_DB")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let child = cmd
            .spawn()
            .context("failed to start curl; is it installed?")?;
        let captured = run_captured(
            child,
            Some(body),
            ZABBIX_MAX_RESPONSE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
            ZABBIX_REQUEST_TIMEOUT,
            format!("curl timed out talking to Zabbix at {}", self.endpoint),
        )
        .await?;

        if captured.stdout.len() as u64 > ZABBIX_MAX_RESPONSE_BYTES {
            return Err(anyhow!(
                "Zabbix response exceeds the {} byte limit",
                ZABBIX_MAX_RESPONSE_BYTES
            ));
        }
        if !captured.status.success() {
            return Err(anyhow!(
                "curl exited with {}: {}",
                captured.status,
                captured.stderr.trim()
            ));
        }
        Ok(captured.stdout)
    }
}

/// Map fetched hosts, items and history onto the inventory: each host
/// resolves by interface IP, then by name, and its CPU, RAM and swap points
/// merge into one sample per instant.
pub fn assemble_samples(fetched: &FetchedUtilization, assets: &[Asset]) -> AssembledSamples {
    let index = super::AssetIndex::new(assets);
    let items: BTreeMap<&str, &ZabbixItem> = fetched
        .items
        .iter()
        .map(|i| (i.itemid.as_str(), i))
        .collect();

    // hostid -> asset id, resolved once per host so a host is never attached
    // to the wrong asset by a second interface.
    let mut asset_of: BTreeMap<&str, &str> = BTreeMap::new();
    let mut unmatched_hosts = 0usize;
    for host in &fetched.hosts {
        let resolved = host
            .addresses
            .iter()
            .find_map(|address| index.resolve(address))
            .or_else(|| index.resolve(&host.host))
            .or_else(|| index.resolve(&host.name));
        match resolved {
            Some(asset) => {
                asset_of.insert(host.hostid.as_str(), asset.id.as_str());
            }
            None => unmatched_hosts += 1,
        }
    }

    // RAM used is total minus available, and the two arrive as separate
    // items, so values are collected per instant before a sample is built.
    let mut per_asset: BTreeMap<(&str, DateTime<Utc>), Partial> = BTreeMap::new();
    for history in &fetched.points {
        let Some(item) = items.get(history.itemid.as_str()) else {
            continue;
        };
        let Some(asset_id) = asset_of.get(item.hostid.as_str()) else {
            continue;
        };
        let Some(is_bytes) = usable_item(item) else {
            continue;
        };
        let Some(at) = DateTime::<Utc>::from_timestamp(history.clock, 0) else {
            continue;
        };
        let partial = per_asset.entry((asset_id, at)).or_default();
        match item.key.as_str() {
            CPU_KEY => partial.cpu_percent = Some(history.value.clamp(0.0, 100.0)),
            RAM_TOTAL_KEY if is_bytes => partial.ram_total_mb = Some(bytes_to_mb(history.value)),
            RAM_AVAILABLE_KEY if is_bytes => {
                partial.ram_available_mb = Some(bytes_to_mb(history.value))
            }
            SWAP_USED_KEY if is_bytes => partial.swap_used_mb = Some(bytes_to_mb(history.value)),
            _ => {}
        }
    }

    let samples = per_asset
        .into_iter()
        .map(|((asset_id, at), partial)| {
            let ram_used_mb = match (partial.ram_total_mb, partial.ram_available_mb) {
                // Both halves present: available is the used figure's basis.
                (Some(total), Some(available)) => Some(total.saturating_sub(available)),
                _ => None,
            };
            MetricSample {
                asset_id: asset_id.to_string(),
                sampled_at: at,
                cpu_usage_percent: partial.cpu_percent.map(|v| v as f32),
                ram_used_mb,
                ram_available_mb: partial.ram_available_mb,
                swap_used_mb: partial.swap_used_mb,
                load_1m: None,
                load_5m: None,
                load_15m: None,
            }
        })
        .collect();

    AssembledSamples {
        samples,
        unmatched_hosts,
    }
}

/// The per-instant values a host's items contribute, before they become a
/// [`MetricSample`].
#[derive(Debug, Default)]
struct Partial {
    cpu_percent: Option<f64>,
    ram_total_mb: Option<u64>,
    ram_available_mb: Option<u64>,
    swap_used_mb: Option<u64>,
}

fn bytes_to_mb(bytes: f64) -> u64 {
    (bytes / 1024.0 / 1024.0).round().max(0.0) as u64
}

/// Whether an item can be used, and whether its value is in bytes.
///
/// RAM and swap are computed from a total and a used/available part, so the
/// items must agree on a unit. Zabbix documents `vm.memory.size` in bytes; a
/// preprocessed item in MiB would be recorded 1024x too small, so it is
/// refused rather than silently rescaled.
fn usable_item(item: &ZabbixItem) -> Option<bool> {
    match item.key.as_str() {
        CPU_KEY => Some(false),
        RAM_TOTAL_KEY | RAM_AVAILABLE_KEY | SWAP_USED_KEY => {
            let unit = item.units.trim();
            if unit.eq_ignore_ascii_case("B") || unit.eq_ignore_ascii_case("byte") {
                Some(true)
            } else {
                tracing::warn!(
                    key = %item.key,
                    units = %item.units,
                    "skipping Zabbix memory item: expected bytes"
                );
                None
            }
        }
        _ => None,
    }
}

/// `host.get` row.
#[derive(Debug, Deserialize)]
struct HostDto {
    hostid: String,
    host: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    interfaces: Vec<InterfaceDto>,
}

#[derive(Debug, Deserialize)]
struct InterfaceDto {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    dns: String,
}

impl HostDto {
    fn into_host(self) -> ZabbixHost {
        let mut addresses: Vec<String> = self
            .interfaces
            .into_iter()
            .flat_map(|i| [i.ip, i.dns])
            .filter(|a| !a.is_empty())
            .collect();
        // Resolve IPv4 first: an inventory is usually keyed on IPv4, and an
        // IPv6 or DNS name is the weaker match.
        addresses.sort_by_key(|a| match a.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => 0,
            Ok(std::net::IpAddr::V6(_)) => 1,
            Err(_) => 2,
        });
        addresses.dedup();
        ZabbixHost {
            hostid: self.hostid,
            host: self.host,
            name: self.name,
            addresses,
        }
    }
}

/// `item.get` row.
#[derive(Debug, Deserialize)]
struct ItemDto {
    itemid: String,
    hostid: String,
    #[serde(rename = "key_")]
    key: String,
    #[serde(default)]
    value_type: u8,
    #[serde(default)]
    units: String,
}

impl ItemDto {
    fn into_item(self) -> ZabbixItem {
        ZabbixItem {
            itemid: self.itemid,
            hostid: self.hostid,
            key: self.key,
            value_type: self.value_type,
            units: self.units,
        }
    }
}

/// `history.get` row: Zabbix returns `itemid` and `clock` as numbers on some
/// versions and as strings on others, so both are accepted rather than
/// dropping a whole history batch over a type difference.
#[derive(Debug, Deserialize)]
struct HistoryRow {
    #[serde(default)]
    itemid: Option<Value>,
    #[serde(default)]
    clock: Option<Value>,
    #[serde(default)]
    value: Option<Value>,
}

/// A JSON number or numeric string as `i64`.
fn as_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(raw) => raw.parse().ok(),
        _ => None,
    }
}

/// A JSON number or numeric string as an id `String`.
fn as_id(value: &Value) -> Option<String> {
    match value {
        Value::Number(n) => Some(n.to_string()),
        Value::String(raw) => Some(raw.clone()),
        _ => None,
    }
}

/// JSON-RPC response envelope.
#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    message: String,
    code: i64,
    #[serde(default)]
    data: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::AssetIndex;

    fn asset(id: &str, ip: &str, hostname: Option<&str>) -> Asset {
        Asset {
            id: id.into(),
            ip: ip.parse().unwrap(),
            hostname: hostname.map(str::to_string),
            device_class: None,
            os_name: None,
            os_version: None,
            sys_descr: None,
            environment: None,
            owner: None,
            criticality: None,
            tags: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    fn host(hostid: &str, name: &str, addresses: &[&str]) -> ZabbixHost {
        ZabbixHost {
            hostid: hostid.into(),
            host: name.into(),
            name: name.into(),
            addresses: addresses.iter().map(|a| (*a).to_string()).collect(),
        }
    }

    fn item(itemid: &str, hostid: &str, key: &str, units: &str) -> ZabbixItem {
        ZabbixItem {
            itemid: itemid.into(),
            hostid: hostid.into(),
            key: key.into(),
            value_type: VALUE_TYPE_UNSIGNED,
            units: units.into(),
        }
    }

    fn point(itemid: &str, clock: i64, value: f64) -> HistoryPoint {
        HistoryPoint {
            itemid: itemid.into(),
            clock,
            value,
        }
    }

    const MIB: f64 = 1024.0 * 1024.0;

    #[test]
    fn client_rejects_malformed_urls() {
        assert!(ZabbixClient::new(
            "https://zabbix.example.com/zabbix/api_jsonrpc.php",
            None,
            false
        )
        .is_ok());
        assert!(
            ZabbixClient::new("http://zabbix:8080/zabbix/api_jsonrpc.php", None, false).is_ok()
        );
        assert!(ZabbixClient::new(
            "https://user:pass@zabbix.example.com/api_jsonrpc.php",
            None,
            false
        )
        .is_err());
        assert!(ZabbixClient::new("zabbix.example.com", None, false).is_err());
    }

    #[test]
    fn asset_index_prefers_ip_then_hostname() {
        let assets = vec![
            asset("a1", "10.0.0.5", Some("web-01")),
            asset("a2", "10.0.0.9", None),
        ];
        let index = AssetIndex::new(&assets);
        assert_eq!(index.len(), 2);
        assert_eq!(index.resolve("10.0.0.5").map(|a| a.id.as_str()), Some("a1"));
        assert_eq!(index.resolve("WEB-01").map(|a| a.id.as_str()), Some("a1"));
        assert_eq!(index.resolve("10.0.0.9").map(|a| a.id.as_str()), Some("a2"));
        // No guessing onto a close-but-different host.
        assert!(index.resolve("web-02").is_none());
        assert!(index.resolve("10.0.0.50").is_none());
    }

    #[test]
    fn memory_items_must_be_in_bytes() {
        assert_eq!(
            usable_item(&item("1", "h1", RAM_TOTAL_KEY, "B")),
            Some(true)
        );
        assert_eq!(
            usable_item(&item("2", "h1", SWAP_USED_KEY, "byte")),
            Some(true)
        );
        // A preprocessed item in MiB is refused rather than rescaled.
        assert!(usable_item(&item("3", "h1", RAM_TOTAL_KEY, "MB")).is_none());
        assert!(usable_item(&item("4", "h1", RAM_AVAILABLE_KEY, "MiB")).is_none());
        // CPU is a percentage, not a byte count.
        assert_eq!(usable_item(&item("5", "h1", CPU_KEY, "%")), Some(false));
        // Unknown keys are not ours.
        assert!(usable_item(&item("6", "h1", "net.if.in", "Bps")).is_none());
    }

    #[test]
    fn history_rows_accept_ids_and_clocks_as_numbers_or_strings() {
        let rows: Vec<HistoryRow> = serde_json::from_str(
            r#"[{"itemid":"28","clock":"1700000000","value":"12.5"},
                {"itemid":29,"clock":1700000300,"value":"30"},
                {"itemid":29,"clock":1700000600,"value":42.5},
                {"itemid":"29","clock":1700000900,"value":null},
                {"value":"1"}]"#,
        )
        .expect("parses history rows");
        assert_eq!(rows.len(), 5);
        assert_eq!(as_id(rows[0].itemid.as_ref().unwrap()), Some("28".into()));
        assert_eq!(as_i64(rows[0].clock.as_ref().unwrap()), Some(1700000000));
        assert_eq!(as_id(rows[1].itemid.as_ref().unwrap()), Some("29".into()));
        assert_eq!(as_i64(rows[1].clock.as_ref().unwrap()), Some(1700000300));
        assert!(rows[3].value.is_none());
        assert!(rows[4].itemid.is_none());
        assert!(as_id(rows[4].itemid.as_ref().unwrap_or(&Value::Null)).is_none());
    }

    #[test]
    fn rpc_error_envelope_is_surfaced() {
        let parsed: RpcResponse = serde_json::from_str(
            r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params.",
                "data":"unexpected parameter \"sortfield\""},"id":1}"#,
        )
        .expect("parses error envelope");
        assert!(parsed.result.is_none());
        let error = parsed.error.expect("error present");
        assert_eq!(error.code, -32602);
        assert_eq!(error.message, "Invalid params.");
        assert!(error.data.unwrap().contains("sortfield"));
    }

    #[test]
    fn host_interfaces_put_ipv4_first() {
        let dto: HostDto = serde_json::from_str(
            r#"{"hostid":"1","host":"web-01","name":"Web 01",
                "interfaces":[{"ip":"","dns":"web-01"},
                              {"ip":"2001:db8::1","dns":""},
                              {"ip":"10.0.0.5","dns":""}]}"#,
        )
        .expect("parses host");
        assert_eq!(
            dto.into_host().addresses,
            vec!["10.0.0.5", "2001:db8::1", "web-01"]
        );
    }

    #[test]
    fn assemble_merges_cpu_ram_and_swap_per_instant() {
        let assets = vec![asset("a1", "10.0.0.5", Some("web-01"))];
        let fetched = FetchedUtilization {
            hosts: vec![host("h1", "web-01", &["10.0.0.5"])],
            items: vec![
                item("100", "h1", CPU_KEY, "%"),
                item("101", "h1", RAM_TOTAL_KEY, "B"),
                item("102", "h1", RAM_AVAILABLE_KEY, "B"),
                item("103", "h1", SWAP_USED_KEY, "B"),
            ],
            points: vec![
                point("100", 1700000000, 12.5),
                point("101", 1700000000, 16384.0 * MIB),
                point("102", 1700000000, 14336.0 * MIB),
                point("103", 1700000000, 512.0 * MIB),
            ],
            ..Default::default()
        };
        let assembled = assemble_samples(&fetched, &assets);
        assert_eq!(assembled.unmatched_hosts, 0);
        assert_eq!(assembled.samples.len(), 1);
        let sample = &assembled.samples[0];
        assert_eq!(sample.asset_id, "a1");
        assert_eq!(sample.cpu_usage_percent, Some(12.5));
        assert_eq!(sample.ram_used_mb, Some(2048));
        assert_eq!(sample.swap_used_mb, Some(512));
    }

    #[test]
    fn unmatched_hosts_are_counted_not_guessed() {
        let assets = vec![asset("a1", "10.0.0.5", None)];
        let fetched = FetchedUtilization {
            hosts: vec![
                host("h1", "web-01", &["10.0.0.5"]),
                host("h2", "web-02", &["10.0.0.99"]),
            ],
            items: vec![item("100", "h2", CPU_KEY, "%")],
            points: vec![point("100", 1700000000, 12.5)],
            ..Default::default()
        };
        let assembled = assemble_samples(&fetched, &assets);
        assert_eq!(assembled.unmatched_hosts, 1);
        assert!(
            assembled.samples.is_empty(),
            "an unmatched host must not be attached to the nearest asset"
        );
    }

    #[test]
    fn samples_are_sorted_by_asset_and_instant() {
        let assets = vec![asset("a1", "10.0.0.5", None), asset("a2", "10.0.0.9", None)];
        let fetched = FetchedUtilization {
            hosts: vec![
                host("h1", "h1", &["10.0.0.9"]),
                host("h2", "h2", &["10.0.0.5"]),
            ],
            items: vec![item("1", "h1", CPU_KEY, "%"), item("2", "h2", CPU_KEY, "%")],
            points: vec![
                point("2", 1700000600, 3.0),
                point("1", 1700000000, 1.0),
                point("2", 1700000000, 2.0),
            ],
            ..Default::default()
        };
        let assembled = assemble_samples(&fetched, &assets);
        let order: Vec<(&str, i64)> = assembled
            .samples
            .iter()
            .map(|s| (s.asset_id.as_str(), s.sampled_at.timestamp()))
            .collect();
        assert_eq!(
            order,
            vec![("a1", 1700000000), ("a1", 1700000600), ("a2", 1700000000)]
        );
    }
}
