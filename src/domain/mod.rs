//! Normalized domain model.
//!
//! Every collector normalizes its observations into these types. Assessment,
//! graph, metrics and presentation layers operate on the domain model and must
//! not care where an observation came from.

use std::net::IpAddr;

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
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
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
}

/// A typed observation produced by a collector before normalization.
#[derive(Debug, Clone, PartialEq)]
pub enum Observation {
    Asset(Asset),
    Service(Service),
    Capacity(Capacity),
    MetricSample(MetricSample),
    Dependency(Dependency),
}
