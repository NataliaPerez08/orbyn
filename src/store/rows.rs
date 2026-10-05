//! Shared row mappings for the SQL stores.
//!
//! The same `FromRow` structs decode rows from both SQLite and PostgreSQL:
//! column types are chosen (TEXT, BIGINT, DOUBLE PRECISION, BOOLEAN) so the
//! shared conversions produce identical domain values on either backend.

use sqlx::FromRow;

use crate::domain::{
    AppSource, Application, ApplicationEvidence, ApplicationMember, Asset, AuditEvent, Capacity,
    Connection, Criticality, Dependency, DependencyEvidence, DiscoveryJob, Filesystem, Interface,
    JobStatus, MetricSample, RunningService, Service,
};

#[derive(Debug, FromRow)]
pub(crate) struct AssetRow {
    pub id: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub device_class: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub sys_descr: Option<String>,
    pub environment: Option<String>,
    pub owner: Option<String>,
    pub criticality: Option<String>,
    pub tags: String,
    pub first_seen: String,
    pub last_seen: String,
}

impl AssetRow {
    pub fn into_asset(self) -> Asset {
        Asset {
            id: self.id,
            ip: self
                .ip
                .parse()
                .unwrap_or_else(|_| "0.0.0.0".parse().unwrap()),
            hostname: self.hostname,
            device_class: self.device_class,
            os_name: self.os_name,
            os_version: self.os_version,
            sys_descr: self.sys_descr,
            environment: self.environment,
            owner: self.owner,
            criticality: self.criticality.and_then(|c| c.parse::<Criticality>().ok()),
            tags: serde_json::from_str(&self.tags).unwrap_or_default(),
            first_seen: parse_ts(&self.first_seen),
            last_seen: parse_ts(&self.last_seen),
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct ServiceRow {
    pub asset_id: String,
    pub proto: String,
    pub port: i64,
    pub name: Option<String>,
    pub state: String,
    pub banner: Option<String>,
}

impl ServiceRow {
    pub fn into_service(self) -> Service {
        Service {
            asset_id: self.asset_id,
            proto: self.proto,
            port: self.port as u16,
            name: self.name,
            state: self.state,
            banner: self.banner,
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct InterfaceRow {
    pub id: String,
    pub asset_id: String,
    pub name: Option<String>,
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub vendor: Option<String>,
    pub mtu: Option<i64>,
    pub if_index: Option<i64>,
    pub is_up: Option<bool>,
}

impl InterfaceRow {
    pub fn into_interface(self) -> Interface {
        Interface {
            id: self.id,
            asset_id: self.asset_id,
            name: self.name,
            mac: self.mac,
            ip: self.ip.and_then(|ip| ip.parse().ok()),
            vendor: self.vendor,
            mtu: self.mtu.map(|m| m as u32),
            if_index: self.if_index.map(|i| i as u32),
            is_up: self.is_up,
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct CapacityRow {
    pub asset_id: String,
    pub cpu_model: Option<String>,
    pub cpu_sockets: Option<i64>,
    pub cpu_cores: Option<i64>,
    pub cpu_threads: Option<i64>,
    pub ram_total_mb: Option<i64>,
    pub hypervisor: Option<String>,
    pub collected_at: String,
}

impl CapacityRow {
    pub fn into_capacity(self) -> Capacity {
        Capacity {
            asset_id: self.asset_id,
            cpu_model: self.cpu_model,
            cpu_sockets: self.cpu_sockets.map(|v| v as u32),
            cpu_cores: self.cpu_cores.map(|v| v as u32),
            cpu_threads: self.cpu_threads.map(|v| v as u32),
            ram_total_mb: self.ram_total_mb.map(|v| v as u64),
            hypervisor: self.hypervisor,
            collected_at: parse_ts(&self.collected_at),
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct MetricSampleRow {
    pub asset_id: String,
    pub sampled_at: String,
    pub cpu_usage_percent: Option<f64>,
    pub ram_used_mb: Option<i64>,
    pub ram_available_mb: Option<i64>,
    pub swap_used_mb: Option<i64>,
    pub load_1m: Option<f64>,
    pub load_5m: Option<f64>,
    pub load_15m: Option<f64>,
}

impl MetricSampleRow {
    pub fn into_sample(self) -> MetricSample {
        MetricSample {
            asset_id: self.asset_id,
            sampled_at: parse_ts(&self.sampled_at),
            cpu_usage_percent: self.cpu_usage_percent.map(|v| v as f32),
            ram_used_mb: self.ram_used_mb.map(|v| v as u64),
            ram_available_mb: self.ram_available_mb.map(|v| v as u64),
            swap_used_mb: self.swap_used_mb.map(|v| v as u64),
            load_1m: self.load_1m.map(|v| v as f32),
            load_5m: self.load_5m.map(|v| v as f32),
            load_15m: self.load_15m.map(|v| v as f32),
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct FilesystemRow {
    pub asset_id: String,
    pub device: Option<String>,
    pub mount: String,
    pub fs_type: Option<String>,
    pub size_kb: i64,
    pub used_kb: Option<i64>,
    pub available_kb: Option<i64>,
    pub used_pct: Option<i64>,
}

impl FilesystemRow {
    pub fn into_filesystem(self) -> Filesystem {
        Filesystem {
            asset_id: self.asset_id,
            device: self.device,
            mount: self.mount,
            fs_type: self.fs_type,
            size_kb: self.size_kb as u64,
            used_kb: self.used_kb.map(|v| v as u64),
            available_kb: self.available_kb.map(|v| v as u64),
            used_pct: self.used_pct.map(|v| v as u32),
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct RunningServiceRow {
    pub asset_id: String,
    pub name: String,
    pub state: Option<String>,
    pub description: Option<String>,
}

impl RunningServiceRow {
    pub fn into_running_service(self) -> RunningService {
        RunningService {
            asset_id: self.asset_id,
            name: self.name,
            state: self.state,
            description: self.description,
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct ConnectionRow {
    pub asset_id: String,
    pub proto: String,
    pub local_ip: Option<String>,
    pub local_port: Option<i64>,
    pub remote_ip: String,
    pub remote_port: i64,
    pub process: Option<String>,
}

impl ConnectionRow {
    pub fn into_connection(self) -> Connection {
        Connection {
            asset_id: self.asset_id,
            proto: self.proto,
            local_ip: self.local_ip.and_then(|ip| ip.parse().ok()),
            local_port: self.local_port.map(|p| p as u16),
            remote_ip: self
                .remote_ip
                .parse()
                .unwrap_or_else(|_| "0.0.0.0".parse().unwrap()),
            remote_port: self.remote_port as u16,
            process: self.process,
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct DependencyRow {
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub proto: String,
    pub port: i64,
    pub evidence_source: String,
    pub confidence: f64,
    pub confirmed: bool,
}

impl DependencyRow {
    pub fn into_dependency(self) -> Dependency {
        Dependency {
            source_asset_id: self.source_asset_id,
            target_asset_id: self.target_asset_id,
            proto: self.proto,
            port: self.port as u16,
            evidence_source: self.evidence_source,
            confidence: self.confidence as f32,
            confirmed: self.confirmed,
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct DependencyEvidenceRow {
    pub source_asset_id: String,
    pub target_asset_id: String,
    pub proto: String,
    pub port: i64,
    pub observations: i64,
}

impl DependencyEvidenceRow {
    pub fn into_evidence(self) -> DependencyEvidence {
        DependencyEvidence {
            source_asset_id: self.source_asset_id,
            target_asset_id: self.target_asset_id,
            proto: self.proto,
            port: self.port as u16,
            observations: self.observations.max(0) as u32,
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct ApplicationRow {
    pub id: String,
    pub name: String,
    pub source: String,
    pub confidence: f64,
    pub created_at: String,
    pub updated_at: String,
}

impl ApplicationRow {
    pub fn into_application(self) -> Application {
        Application {
            id: self.id,
            name: self.name,
            source: AppSource::parse(&self.source),
            confidence: self.confidence as f32,
            created_at: parse_ts(&self.created_at),
            updated_at: parse_ts(&self.updated_at),
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct ApplicationMemberRow {
    pub application_id: String,
    pub asset_id: String,
    pub source: String,
    pub confidence: f64,
    pub evidence: String,
    pub is_excluded: bool,
}

impl ApplicationMemberRow {
    pub fn into_member(self) -> ApplicationMember {
        ApplicationMember {
            application_id: self.application_id,
            asset_id: self.asset_id,
            source: AppSource::parse(&self.source),
            confidence: self.confidence as f32,
            evidence: serde_json::from_str::<Vec<ApplicationEvidence>>(&self.evidence)
                .unwrap_or_default(),
            is_excluded: self.is_excluded,
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct JobRow {
    pub id: String,
    pub collector: String,
    pub targets: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub error: Option<String>,
    pub assets_found: Option<i64>,
    pub services_found: Option<i64>,
    pub filesystems_found: Option<i64>,
    pub running_services_found: Option<i64>,
    pub connections_found: Option<i64>,
}

impl JobRow {
    pub fn into_job(self) -> DiscoveryJob {
        DiscoveryJob {
            id: self.id,
            collector: self.collector,
            targets: serde_json::from_str(&self.targets).unwrap_or_default(),
            status: parse_status(&self.status),
            started_at: parse_ts(&self.started_at),
            finished_at: self.finished_at.as_deref().map(parse_ts),
            error: self.error,
            assets_found: self.assets_found.map(|v| v as u32),
            services_found: self.services_found.map(|v| v as u32),
            filesystems_found: self.filesystems_found.map(|v| v as u32),
            running_services_found: self.running_services_found.map(|v| v as u32),
            connections_found: self.connections_found.map(|v| v as u32),
        }
    }
}

#[derive(Debug, FromRow)]
pub(crate) struct AuditEventRow {
    pub id: String,
    pub action: String,
    pub target: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub details: Option<String>,
    pub error: Option<String>,
}

impl AuditEventRow {
    pub fn into_event(self) -> AuditEvent {
        AuditEvent {
            id: self.id,
            action: self.action,
            target: self.target,
            status: parse_status(&self.status),
            started_at: parse_ts(&self.started_at),
            finished_at: self.finished_at.as_deref().map(parse_ts),
            details: self.details,
            error: self.error,
        }
    }
}

pub(crate) fn parse_ts(ts: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
}

pub(crate) fn status_as_str(status: JobStatus) -> &'static str {
    match status {
        JobStatus::Pending => "pending",
        JobStatus::Running => "running",
        JobStatus::Succeeded => "succeeded",
        JobStatus::Failed => "failed",
    }
}

pub(crate) fn parse_status(status: &str) -> JobStatus {
    match status {
        "running" => JobStatus::Running,
        "succeeded" => JobStatus::Succeeded,
        "failed" => JobStatus::Failed,
        _ => JobStatus::Pending,
    }
}
