//! Normalized domain model.
//!
//! Every collector normalizes its observations into these types. Assessment,
//! graph, metrics and presentation layers operate on the domain model and must
//! not care where an observation came from.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An asset discovered in the infrastructure: a host, VM, network device, etc.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Asset {
    pub id: String,
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub device_class: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    /// Free-form environment label (e.g. `prod`, `staging`, `dr`).
    pub environment: Option<String>,
    /// Owning team or operator responsible for the asset.
    pub owner: Option<String>,
    /// Business criticality assigned to the asset.
    pub criticality: Option<Criticality>,
    /// Custom tags attached to the asset.
    pub tags: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// A network interface observed on an asset.
///
/// Collectors report whatever they can see: SNMP walks the full `ifTable`,
/// while Nmap only observes the responding MAC address and its vendor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Interface {
    pub id: String,
    pub asset_id: String,
    pub name: Option<String>,
    /// Normalized MAC address (lowercase `xx:xx:xx:xx:xx:xx`).
    pub mac: Option<String>,
    pub ip: Option<IpAddr>,
    /// MAC vendor/OUI string when known.
    pub vendor: Option<String>,
    pub mtu: Option<u32>,
    pub if_index: Option<u32>,
    pub is_up: Option<bool>,
}

impl Interface {
    /// Build an interface with a deterministic id derived from its identifying
    /// attributes so re-observed interfaces reconcile to the same row.
    pub fn new(asset_id: &str, name: Option<&str>, mac: Option<&str>, ip: Option<IpAddr>) -> Self {
        Self {
            id: interface_id(asset_id, name, mac, ip),
            asset_id: asset_id.to_string(),
            name: name.map(str::to_string),
            mac: mac.and_then(normalize_mac),
            ip,
            vendor: None,
            mtu: None,
            if_index: None,
            is_up: None,
        }
    }
}

/// Deterministic storage id for an interface.
pub fn interface_id(
    asset_id: &str,
    name: Option<&str>,
    mac: Option<&str>,
    ip: Option<IpAddr>,
) -> String {
    let name = name.unwrap_or_default().to_lowercase();
    let mac = normalize_mac(mac.unwrap_or_default()).unwrap_or_default();
    let ip = ip.map(|a| a.to_string()).unwrap_or_default();
    format!("{asset_id}--{name}--{mac}--{ip}")
}

/// Normalize a MAC address representation to lowercase `xx:xx:xx:xx:xx:xx`.
///
/// Accepts plain hex, dotted, and colon/dash separated forms (as returned by
/// Nmap, SNMP `ifPhysAddress`, and ARP tables). Returns `None` when the input
/// does not contain exactly 12 hexadecimal digits, so non-MAC values never
/// persist in a non-canonical form.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if cleaned.len() != 12 {
        return None;
    }
    Some(
        cleaned
            .as_bytes()
            .chunks(2)
            .map(|b| std::str::from_utf8(b).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Business criticality used for inventory annotation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Criticality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Criticality::Low => write!(f, "low"),
            Criticality::Medium => write!(f, "medium"),
            Criticality::High => write!(f, "high"),
            Criticality::Critical => write!(f, "critical"),
        }
    }
}

impl FromStr for Criticality {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "low" => Ok(Criticality::Low),
            "medium" | "med" => Ok(Criticality::Medium),
            "high" => Ok(Criticality::High),
            "critical" | "crit" => Ok(Criticality::Critical),
            other => Err(format!(
                "unknown criticality '{other}' (expected low|medium|high|critical)"
            )),
        }
    }
}

/// A network service observed on an asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Service {
    pub asset_id: String,
    pub proto: String,
    pub port: u16,
    pub name: Option<String>,
    pub state: String,
    pub banner: Option<String>,
}

/// A directional dependency between two assets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Dependency {
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub proto: String,
    pub port: u16,
    pub evidence_source: String,
    pub confidence: f32,
    pub confirmed: bool,
}

/// An active network connection observed on a host (v0.4 dependency
/// evidence). The store reconciles the remote endpoint into a
/// [`Dependency`] edge whenever the remote IP matches a known asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Connection {
    pub asset_id: String,
    pub proto: String,
    pub local_ip: Option<IpAddr>,
    pub local_port: Option<u16>,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    /// Owning process name when visible (Linux `ss -p` only).
    pub process: Option<String>,
}

/// Hardware/virtual machine allocation for a single asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capacity {
    pub asset_id: String,
    pub cpu_model: Option<String>,
    pub cpu_sockets: Option<u32>,
    pub cpu_cores: Option<u32>,
    pub cpu_threads: Option<u32>,
    pub ram_total_mb: Option<u64>,
    pub collected_at: DateTime<Utc>,
}

/// A mounted filesystem observed on an asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Filesystem {
    pub asset_id: String,
    pub device: Option<String>,
    /// Mount point (Linux) or drive letter (Windows, e.g. `C:`).
    pub mount: String,
    pub fs_type: Option<String>,
    pub size_kb: u64,
    pub used_kb: Option<u64>,
    pub available_kb: Option<u64>,
    pub used_pct: Option<u32>,
}

/// A host-level running service observed on an asset (systemd unit on Linux,
/// service on Windows). Distinct from network [`Service`] port observations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunningService {
    pub asset_id: String,
    pub name: String,
    pub state: Option<String>,
    pub description: Option<String>,
}

/// A single observation of resource utilization. Always a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricSample {
    pub asset_id: String,
    pub sampled_at: DateTime<Utc>,
    pub cpu_usage_percent: Option<f32>,
    pub ram_used_mb: Option<u64>,
    pub ram_available_mb: Option<u64>,
    pub swap_used_mb: Option<u64>,
    pub load_1m: Option<f32>,
    pub load_5m: Option<f32>,
    pub load_15m: Option<f32>,
}

/// Lifecycle of a discovery job.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
}

/// Aggregate outcome recorded on a finished discovery job.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct JobOutcome {
    pub assets_found: u32,
    pub services_found: u32,
}

/// Metadata about a discovery run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryJob {
    pub id: String,
    pub collector: String,
    pub targets: Vec<String>,
    pub status: JobStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    /// Assets persisted by this job (None until the job finishes).
    pub assets_found: Option<u32>,
    /// Services persisted by this job (None until the job finishes).
    pub services_found: Option<u32>,
}

/// A typed observation produced by a collector before normalization.
#[derive(Debug, Clone, PartialEq)]
pub enum Observation {
    Asset(Asset),
    Service(Service),
    Interface(Interface),
    Capacity(Capacity),
    Filesystem(Filesystem),
    RunningService(RunningService),
    Connection(Connection),
    MetricSample(MetricSample),
    Dependency(Dependency),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mac_formats() {
        assert_eq!(
            normalize_mac("0011:2233:4455"),
            Some("00:11:22:33:44:55".into())
        );
        assert_eq!(
            normalize_mac("00-11-22-33-44-55"),
            Some("00:11:22:33:44:55".into())
        );
        assert_eq!(
            normalize_mac("00:11:22:33:44:55"),
            Some("00:11:22:33:44:55".into())
        );
        assert_eq!(
            normalize_mac("112233445566"),
            Some("11:22:33:44:55:66".into())
        );
    }

    #[test]
    fn normalize_mac_rejects_non_mac_values() {
        assert_eq!(normalize_mac(""), None);
        assert_eq!(normalize_mac("not a mac"), None);
        assert_eq!(normalize_mac("00:11:22:33:44"), None, "too few octets");
        assert_eq!(
            normalize_mac("00:11:22:33:44:55:66:77"),
            None,
            "too many octets"
        );
    }

    #[test]
    fn criticality_round_trips() {
        assert_eq!("high".parse::<Criticality>().unwrap(), Criticality::High);
        assert_eq!(Criticality::Critical.to_string(), "critical");
        assert!("nonsense".parse::<Criticality>().is_err());
    }

    #[test]
    fn interface_id_is_deterministic_and_stable() {
        let a = Interface::new("10-0-0-10", Some("eth0"), Some("00:11:22:33:44:55"), None);
        let b = Interface::new("10-0-0-10", Some("eth0"), Some("00:11:22:33:44:55"), None);
        assert_eq!(a.id, b.id);
    }
}
