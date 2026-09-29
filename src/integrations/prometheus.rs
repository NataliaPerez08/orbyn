//! Prometheus historical utilization importer (v1.2).
//!
//! Pulls CPU/RAM/swap utilization time series from a Prometheus HTTP API
//! (`/api/v1/query_range`) and turns them into [`MetricSample`] rows, so an
//! asset can carry a real observation window (a week of history) instead of
//! only discovery snapshots. Read-only: Orbyn never writes to Prometheus.
//!
//! The API is queried through the `curl` binary (consistent with the rest of
//! the integration surface). A bearer token, when the endpoint needs one, is
//! streamed to curl through stdin as an `Authorization` header (`-H @-`), so
//! it never appears in process arguments, logs, disk, or CLI output.
//!
//! Series are mapped onto the inventory by the `instance` label: the host
//! part (IP or hostname, `:port` stripped) must match a known asset. Series
//! that match nothing are reported, not guessed.

use std::collections::{BTreeMap, HashMap};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tokio::process::Command;

use crate::domain::{Asset, MetricSample};
use crate::process::{run_captured, MAX_STDERR_CAPTURE_BYTES};

use super::netbox::url_origin;

const PROM_MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const PROM_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Hard cap on accepted points per query: a week at a 5-minute step is
/// ~2k points per series, so 50k accommodates dozens of hosts while
/// bounding a hostile endpoint.
const PROM_MAX_POINTS: usize = 50_000;

/// Default CPU utilization query (node_exporter): idle-rate complement,
/// aggregated per `instance`, in percent.
pub const DEFAULT_CPU_QUERY: &str =
    "100 - avg by (instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100";

/// Default RAM-used query (node_exporter): total minus available, in bytes.
pub const DEFAULT_RAM_QUERY: &str = "node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes";

/// Default swap-used query (node_exporter): total minus free, in bytes.
pub const DEFAULT_SWAP_QUERY: &str = "node_memory_SwapTotal_bytes - node_memory_SwapFree_bytes";

/// A read-only Prometheus HTTP API client backed by the `curl` binary.
pub struct PrometheusClient {
    base_url: String,
    token: Option<String>,
    insecure: bool,
    binary: String,
}

/// Parameters of one utilization import.
pub struct ImportOptions {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// Prometheus step expression, e.g. `5m`.
    pub step: String,
    /// Query returning CPU usage percent per `instance`.
    pub cpu_query: String,
    /// Query returning RAM used bytes per `instance`.
    pub ram_query: String,
    /// Query returning swap used bytes per `instance`.
    pub swap_query: String,
}

/// One resolved Prometheus series: its labels and (time, value) points.
#[derive(Debug, Clone, PartialEq)]
pub struct PromSeries {
    pub metric: HashMap<String, String>,
    pub values: Vec<(DateTime<Utc>, f64)>,
}

/// The raw result of the range queries, before inventory mapping.
#[derive(Debug, Default)]
pub struct FetchedUtilization {
    pub cpu_series: Vec<PromSeries>,
    pub ram_series: Vec<PromSeries>,
    pub swap_series: Vec<PromSeries>,
    /// Points dropped because their timestamp or value did not parse.
    pub skipped_points: usize,
}

/// Metric samples assembled against the current inventory.
#[derive(Debug, Default)]
pub struct AssembledSamples {
    pub samples: Vec<MetricSample>,
    /// Series whose `instance` label matched no known asset.
    pub unmatched_series: usize,
}

impl PrometheusClient {
    /// Create a client for `base_url`, which must be an absolute http(s)
    /// URL without credentials; a token would otherwise be sent to a
    /// malformed destination.
    pub fn new(base_url: &str, token: Option<String>, insecure: bool) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/').to_string();
        if url_origin(&base_url).is_none() {
            return Err(anyhow!(
                "invalid Prometheus URL '{base_url}': expected an absolute http(s) \
                 URL without embedded credentials"
            ));
        }
        Ok(Self {
            base_url,
            token,
            insecure,
            binary: std::env::var("ORBYN_CURL_BIN").unwrap_or_else(|_| "curl".to_string()),
        })
    }

    /// Run the CPU, RAM and swap range queries and return their series.
    ///
    /// A swap query the endpoint cannot answer is not fatal: swap is a
    /// pressure signal, and an instance without a node_exporter swap series
    /// still yields a usable CPU/RAM window.
    pub async fn fetch_utilization(&self, opts: &ImportOptions) -> Result<FetchedUtilization> {
        let (cpu_series, cpu_skipped) = self.query_range(&opts.cpu_query, opts).await?;
        let (ram_series, ram_skipped) = self.query_range(&opts.ram_query, opts).await?;
        let (swap_series, swap_skipped) = match self.query_range(&opts.swap_query, opts).await {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "swap query failed; importing CPU and RAM history only"
                );
                (Vec::new(), 0)
            }
        };
        Ok(FetchedUtilization {
            cpu_series,
            ram_series,
            swap_series,
            skipped_points: cpu_skipped + ram_skipped + swap_skipped,
        })
    }

    /// One `/api/v1/query_range` call: series plus the count of points that
    /// did not parse and were skipped.
    async fn query_range(
        &self,
        query: &str,
        opts: &ImportOptions,
    ) -> Result<(Vec<PromSeries>, usize)> {
        let url = format!(
            "{}/api/v1/query_range?query={}&start={}&end={}&step={}",
            self.base_url,
            encode_query_component(query),
            opts.start.timestamp(),
            opts.end.timestamp(),
            encode_query_component(&opts.step),
        );
        let json = self.get_url(&url).await?;
        let envelope: PromEnvelope =
            serde_json::from_str(&json).context("parsing Prometheus response")?;
        if envelope.status != "success" {
            return Err(anyhow!(
                "Prometheus query failed: {} [{}]",
                envelope.error.unwrap_or_else(|| "unknown error".into()),
                envelope.error_type.unwrap_or_else(|| "unknown".into()),
            ));
        }
        let data = envelope
            .data
            .ok_or_else(|| anyhow!("Prometheus response carries no data"))?;
        if data.result_type != "matrix" {
            return Err(anyhow!(
                "unexpected Prometheus result type '{}'; query_range must return a matrix",
                data.result_type
            ));
        }

        let mut series = Vec::with_capacity(data.result.len());
        let mut skipped = 0usize;
        let mut total_points = 0usize;
        for dto in data.result {
            let mut values = Vec::with_capacity(dto.values.len());
            for (ts, raw) in dto.values {
                match parse_point(ts, &raw) {
                    Some(point) => values.push(point),
                    None => skipped += 1,
                }
            }
            total_points += values.len();
            if total_points > PROM_MAX_POINTS {
                return Err(anyhow!(
                    "Prometheus response exceeds the {PROM_MAX_POINTS} point limit"
                ));
            }
            series.push(PromSeries {
                metric: dto.metric,
                values,
            });
        }
        Ok((series, skipped))
    }

    /// GET a URL through curl. The Authorization header, when a token is
    /// configured, is read by curl from stdin (`-H @-`) so the token never
    /// hits the filesystem or the process argument list.
    async fn get_url(&self, url: &str) -> Result<String> {
        let mut cmd = Command::new(&self.binary);
        cmd.arg("-sS");
        if self.insecure {
            cmd.arg("--insecure");
        }
        if self.token.is_some() {
            cmd.arg("-H").arg("@-");
        }
        cmd.arg(url)
            // Secret-bearing variables never reach the child environment
            // (audit OY-02): a hijacked curl must not be able to read the
            // community, the NetBox token, the WinRM password, the
            // Prometheus token or the database URL password.
            .env_remove("ORBYN_SNMP_COMMUNITY")
            .env_remove("ORBYN_NETBOX_TOKEN")
            .env_remove("ORBYN_WINRM_PASSWORD")
            .env_remove("ORBYN_PROMETHEUS_TOKEN")
            .env_remove("ORBYN_DB")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let child = cmd
            .spawn()
            .context("failed to start curl; is it installed?")?;

        let stdin_payload = self
            .token
            .as_deref()
            .map(|t| format!("Authorization: Bearer {t}\n"));
        let captured = run_captured(
            child,
            stdin_payload.as_deref(),
            PROM_MAX_RESPONSE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
            PROM_REQUEST_TIMEOUT,
            format!("curl timed out against {url}"),
        )
        .await?;

        if captured.stdout.len() as u64 > PROM_MAX_RESPONSE_BYTES {
            return Err(anyhow!(
                "Prometheus response exceeds the {} byte limit",
                PROM_MAX_RESPONSE_BYTES
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

/// Map fetched series onto the inventory: each series' `instance` label
/// (host part, `:port` stripped) must resolve to a known asset by IP or
/// hostname. CPU, RAM and swap points for the same asset and instant merge
/// into one sample.
pub fn assemble_samples(fetched: &FetchedUtilization, assets: &[Asset]) -> AssembledSamples {
    let index = super::AssetIndex::new(assets);
    let mut per_asset: HashMap<&str, BTreeMap<DateTime<Utc>, MetricSample>> = HashMap::new();
    let mut unmatched_series = 0usize;

    feed_series(
        &fetched.cpu_series,
        Field::Cpu,
        &index,
        &mut per_asset,
        &mut unmatched_series,
    );
    feed_series(
        &fetched.ram_series,
        Field::Ram,
        &index,
        &mut per_asset,
        &mut unmatched_series,
    );
    feed_series(
        &fetched.swap_series,
        Field::Swap,
        &index,
        &mut per_asset,
        &mut unmatched_series,
    );

    let mut samples = Vec::new();
    for (_asset_id, bucket) in per_asset {
        samples.extend(bucket.into_values());
    }
    // Deterministic order: (asset, instant), regardless of HashMap layout.
    samples.sort_by(|a, b| {
        a.asset_id
            .cmp(&b.asset_id)
            .then_with(|| a.sampled_at.cmp(&b.sampled_at))
    });
    AssembledSamples {
        samples,
        unmatched_series,
    }
}

/// Which column of a [`MetricSample`] a series fills.
#[derive(Clone, Copy)]
enum Field {
    Cpu,
    Ram,
    Swap,
}

/// Fold one batch of series into the per-asset sample buckets.
fn feed_series<'a>(
    series: &[PromSeries],
    field: Field,
    index: &super::AssetIndex<'a>,
    per_asset: &mut HashMap<&'a str, BTreeMap<DateTime<Utc>, MetricSample>>,
    unmatched: &mut usize,
) {
    for s in series {
        let Some(instance) = s.metric.get("instance") else {
            *unmatched += 1;
            continue;
        };
        let Some(asset) = index.resolve(instance_host(instance)) else {
            *unmatched += 1;
            continue;
        };
        let bucket = per_asset.entry(asset.id.as_str()).or_default();
        for (at, value) in &s.values {
            let sample = bucket.entry(*at).or_insert_with(|| MetricSample {
                asset_id: asset.id.clone(),
                sampled_at: *at,
                cpu_usage_percent: None,
                ram_used_mb: None,
                ram_available_mb: None,
                swap_used_mb: None,
                load_1m: None,
                load_5m: None,
                load_15m: None,
            });
            match field {
                Field::Cpu => sample.cpu_usage_percent = Some(*value as f32),
                Field::Ram => sample.ram_used_mb = Some(bytes_to_mb(*value)),
                Field::Swap => sample.swap_used_mb = Some(bytes_to_mb(*value)),
            }
        }
    }
}

/// Host part of a Prometheus `instance` label: strips a trailing `:port`
/// and IPv6 brackets, so `10.0.0.5:9100`, `web-01:9100`, `[::1]:9100` and
/// `10.0.0.5` all reduce to their host.
fn instance_host(instance: &str) -> &str {
    let host = match instance.rsplit_once(':') {
        Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => head,
        _ => instance,
    };
    host.trim_start_matches('[').trim_end_matches(']')
}

/// Percent-encode a URL query component (RFC 3986): PromQL is full of
/// spaces, braces and quotes that must never be interpreted as URL
/// structure.
fn encode_query_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Convert a Prometheus point (unix seconds, string value) into a typed
/// point; `None` when either half does not parse.
fn parse_point(ts: f64, raw: &str) -> Option<(DateTime<Utc>, f64)> {
    let at = DateTime::<Utc>::from_timestamp(ts.trunc() as i64, 0)?;
    let value: f64 = raw.parse().ok()?;
    if !value.is_finite() {
        return None;
    }
    Some((at, value))
}

fn bytes_to_mb(bytes: f64) -> u64 {
    (bytes / 1024.0 / 1024.0).round().max(0.0) as u64
}

/// `/api/v1/query_range` response envelope.
#[derive(Debug, Deserialize)]
struct PromEnvelope {
    status: String,
    #[serde(default)]
    data: Option<PromData>,
    #[serde(default)]
    error: Option<String>,
    #[serde(rename = "errorType", default)]
    error_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PromData {
    #[serde(rename = "resultType")]
    result_type: String,
    result: Vec<PromSeriesDto>,
}

#[derive(Debug, Deserialize)]
struct PromSeriesDto {
    metric: HashMap<String, String>,
    values: Vec<(f64, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Asset;
    use chrono::Timelike as _;

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

    fn series(instance: &str, values: Vec<(f64, f64)>) -> PromSeries {
        let mut metric = HashMap::new();
        metric.insert("instance".to_string(), instance.to_string());
        PromSeries {
            metric,
            values: values
                .into_iter()
                .map(|(ts, v)| (DateTime::<Utc>::from_timestamp(ts as i64, 0).unwrap(), v))
                .collect(),
        }
    }

    #[test]
    fn query_component_is_percent_encoded() {
        assert_eq!(
            encode_query_component(DEFAULT_CPU_QUERY),
            "100%20-%20avg%20by%20%28instance%29%20%28rate%28node_cpu_seconds_total%7Bmode%3D%22idle%22%7D%5B5m%5D%29%29%20%2A%20100"
        );
        assert_eq!(encode_query_component("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn instance_host_strips_ports_and_brackets() {
        assert_eq!(instance_host("10.0.0.5:9100"), "10.0.0.5");
        assert_eq!(instance_host("web-01:9100"), "web-01");
        assert_eq!(instance_host("[2001:db8::1]:9100"), "2001:db8::1");
        assert_eq!(instance_host("10.0.0.5"), "10.0.0.5");
    }

    #[test]
    fn client_rejects_malformed_urls() {
        assert!(PrometheusClient::new("https://prom.example.com", None, false).is_ok());
        assert!(PrometheusClient::new("http://prom:9090", None, false).is_ok());
        assert!(PrometheusClient::new("https://user:pass@prom.example.com", None, false).is_err());
        assert!(PrometheusClient::new("prom.example.com", None, false).is_err());
        assert!(PrometheusClient::new("ftp://prom.example.com", None, false).is_err());
    }

    #[test]
    fn points_parse_or_skip() {
        let (at, v) = parse_point(1700000000.0, "12.5").expect("parses");
        assert_eq!(at.timestamp(), 1700000000);
        assert_eq!(v, 12.5);
        assert!(parse_point(1.0e18, "1").is_none()); // out-of-range timestamp
        assert!(parse_point(1700000000.0, "NaN").is_none());
        assert!(parse_point(1700000000.0, "junk").is_none());
    }

    #[test]
    fn assemble_maps_by_ip_and_hostname_and_merges_cpu_ram() {
        let assets = vec![
            asset("a1", "10.0.0.5", Some("web-01")),
            asset("a2", "10.0.0.9", None),
        ];
        let fetched = FetchedUtilization {
            cpu_series: vec![
                series(
                    "10.0.0.5:9100",
                    vec![(1700000000.0, 12.5), (1700000300.0, 30.0)],
                ),
                series("web-02:9100", vec![(1700000000.0, 5.0)]), // hostname not in inventory
            ],
            ram_series: vec![
                series("web-01:9100", vec![(1700000000.0, 2147483648.0)]), // by hostname
                series("10.0.0.99:9100", vec![(1700000000.0, 1024.0)]),    // unknown IP
            ],
            swap_series: vec![
                // Merged into the same instant as the CPU and RAM points.
                series("10.0.0.5:9100", vec![(1700000000.0, 536870912.0)]),
            ],
            skipped_points: 0,
        };
        let assembled = assemble_samples(&fetched, &assets);
        // 2 of 5 series matched nothing.
        assert_eq!(assembled.unmatched_series, 2);
        assert_eq!(assembled.samples.len(), 2);
        let first = &assembled.samples[0];
        assert_eq!(first.asset_id, "a1");
        assert_eq!(first.sampled_at.timestamp(), 1700000000);
        assert_eq!(first.cpu_usage_percent, Some(12.5));
        assert_eq!(first.ram_used_mb, Some(2048)); // 2 GiB in MB
        assert_eq!(first.swap_used_mb, Some(512)); // 512 MiB in MB
        let second = &assembled.samples[1];
        assert_eq!(second.sampled_at.timestamp(), 1700000300);
        assert_eq!(second.cpu_usage_percent, Some(30.0));
        assert_eq!(second.ram_used_mb, None);
        assert_eq!(second.swap_used_mb, None);
    }

    #[test]
    fn swap_series_merge_into_existing_instants() {
        let assets = vec![asset("a1", "10.0.0.5", None)];
        let fetched = FetchedUtilization {
            cpu_series: vec![series("10.0.0.5:9100", vec![(1700000000.0, 12.5)])],
            ram_series: vec![],
            swap_series: vec![series(
                "10.0.0.5:9100",
                vec![(1700000000.0, 1048576.0), (1700000300.0, 2097152.0)],
            )],
            skipped_points: 0,
        };
        let assembled = assemble_samples(&fetched, &assets);
        assert_eq!(assembled.samples.len(), 2);
        let first = &assembled.samples[0];
        assert_eq!(first.cpu_usage_percent, Some(12.5));
        assert_eq!(first.swap_used_mb, Some(1));
        let second = &assembled.samples[1];
        assert_eq!(second.cpu_usage_percent, None);
        assert_eq!(second.swap_used_mb, Some(2));
    }

    #[test]
    fn samples_are_sorted_by_asset_and_instant() {
        let assets = vec![asset("a1", "10.0.0.5", None), asset("a2", "10.0.0.9", None)];
        let fetched = FetchedUtilization {
            cpu_series: vec![
                series("10.0.0.9:9100", vec![(1700000000.0, 1.0)]),
                series(
                    "10.0.0.5:9100",
                    vec![(1700000600.0, 2.0), (1700000000.0, 3.0)],
                ),
            ],
            ram_series: vec![],
            swap_series: vec![],
            skipped_points: 0,
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

    #[test]
    fn envelope_parses_success_and_error_shapes() {
        let ok: PromEnvelope = serde_json::from_str(
            r#"{"status":"success","data":{"resultType":"matrix","result":[
                {"metric":{"instance":"10.0.0.5:9100","job":"node"},
                 "values":[[1700000000,"12.5"],[1700000300,"30"]]}]}}"#,
        )
        .expect("parses success envelope");
        assert_eq!(ok.status, "success");
        let data = ok.data.expect("data present");
        assert_eq!(data.result_type, "matrix");
        assert_eq!(data.result.len(), 1);
        assert_eq!(data.result[0].values.len(), 2);
        assert_eq!(data.result[0].values[0].1, "12.5");

        let err: PromEnvelope = serde_json::from_str(
            r#"{"status":"error","errorType":"bad_data","error":"invalid parameter"}"#,
        )
        .expect("parses error envelope");
        assert_eq!(err.status, "error");
        assert_eq!(err.error.as_deref(), Some("invalid parameter"));
        assert_eq!(err.error_type.as_deref(), Some("bad_data"));
        assert!(err.data.is_none());
    }

    #[test]
    fn timestamps_keep_second_precision() {
        let (at, _) = parse_point(1700000000.9, "1.0").expect("parses");
        assert_eq!(at.timestamp(), 1700000000);
        assert_eq!(at.nanosecond(), 0);
    }
}
