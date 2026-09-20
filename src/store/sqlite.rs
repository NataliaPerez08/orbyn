//! SQLite store implemented with `sqlx`.
//!
//! Database schema lives in the top-level `migrations/` directory and is
//! applied at startup through `sqlx::migrate!`.

use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, Row, SqlitePool};

use crate::domain::{
    Asset, Capacity, Connection, Criticality, Dependency, DiscoveryJob, Filesystem, Interface,
    JobOutcome, JobStatus, MetricSample, Observation, RunningService, Service,
};
use crate::store::traits::AssetAnnotations;

#[derive(Debug, Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

#[derive(Debug, FromRow)]
struct AssetRow {
    id: String,
    ip: String,
    hostname: Option<String>,
    device_class: Option<String>,
    os_name: Option<String>,
    os_version: Option<String>,
    environment: Option<String>,
    owner: Option<String>,
    criticality: Option<String>,
    tags: String,
    first_seen: String,
    last_seen: String,
}

impl AssetRow {
    fn into_asset(self) -> Asset {
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
struct ServiceRow {
    asset_id: String,
    proto: String,
    port: i64,
    name: Option<String>,
    state: String,
    banner: Option<String>,
}

impl ServiceRow {
    fn into_service(self) -> Service {
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
struct InterfaceRow {
    id: String,
    asset_id: String,
    name: Option<String>,
    mac: Option<String>,
    ip: Option<String>,
    vendor: Option<String>,
    mtu: Option<i64>,
    if_index: Option<i64>,
    is_up: Option<bool>,
}

impl InterfaceRow {
    fn into_interface(self) -> Interface {
        Interface {
            id: self.id,
            asset_id: self.asset_id,
            name: self.name,
            mac: self.mac,
            ip: self.ip.and_then(|ip| ip.parse::<IpAddr>().ok()),
            vendor: self.vendor,
            mtu: self.mtu.map(|m| m as u32),
            if_index: self.if_index.map(|i| i as u32),
            is_up: self.is_up,
        }
    }
}

#[derive(Debug, FromRow)]
struct CapacityRow {
    asset_id: String,
    cpu_model: Option<String>,
    cpu_sockets: Option<i64>,
    cpu_cores: Option<i64>,
    cpu_threads: Option<i64>,
    ram_total_mb: Option<i64>,
    collected_at: String,
}

impl CapacityRow {
    fn into_capacity(self) -> Capacity {
        Capacity {
            asset_id: self.asset_id,
            cpu_model: self.cpu_model,
            cpu_sockets: self.cpu_sockets.map(|v| v as u32),
            cpu_cores: self.cpu_cores.map(|v| v as u32),
            cpu_threads: self.cpu_threads.map(|v| v as u32),
            ram_total_mb: self.ram_total_mb.map(|v| v as u64),
            collected_at: parse_ts(&self.collected_at),
        }
    }
}

#[derive(Debug, FromRow)]
struct MetricSampleRow {
    asset_id: String,
    sampled_at: String,
    cpu_usage_percent: Option<f64>,
    ram_used_mb: Option<i64>,
    ram_available_mb: Option<i64>,
    swap_used_mb: Option<i64>,
    load_1m: Option<f64>,
    load_5m: Option<f64>,
    load_15m: Option<f64>,
}

impl MetricSampleRow {
    fn into_sample(self) -> MetricSample {
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
struct FilesystemRow {
    asset_id: String,
    device: Option<String>,
    mount: String,
    fs_type: Option<String>,
    size_kb: i64,
    used_kb: Option<i64>,
    available_kb: Option<i64>,
    used_pct: Option<i64>,
}

impl FilesystemRow {
    fn into_filesystem(self) -> Filesystem {
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
struct RunningServiceRow {
    asset_id: String,
    name: String,
    state: Option<String>,
    description: Option<String>,
}

#[derive(Debug, FromRow)]
struct ConnectionRow {
    asset_id: String,
    proto: String,
    local_ip: Option<String>,
    local_port: Option<i64>,
    remote_ip: String,
    remote_port: i64,
    process: Option<String>,
}

impl ConnectionRow {
    fn into_connection(self) -> Connection {
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
struct DependencyRow {
    source_asset_id: String,
    target_asset_id: String,
    proto: String,
    port: i64,
    evidence_source: String,
    confidence: f64,
    confirmed: bool,
}

impl DependencyRow {
    fn into_dependency(self) -> Dependency {
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
struct JobRow {
    id: String,
    collector: String,
    targets: String,
    status: String,
    started_at: String,
    finished_at: Option<String>,
    error: Option<String>,
    assets_found: Option<i64>,
    services_found: Option<i64>,
}

impl JobRow {
    fn into_job(self) -> DiscoveryJob {
        DiscoveryJob {
            id: self.id,
            collector: self.collector,
            targets: serde_json::from_str(&self.targets).unwrap_or_default(),
            status: match self.status.as_str() {
                "running" => JobStatus::Running,
                "succeeded" => JobStatus::Succeeded,
                "failed" => JobStatus::Failed,
                _ => JobStatus::Pending,
            },
            started_at: parse_ts(&self.started_at),
            finished_at: self.finished_at.as_deref().map(parse_ts),
            error: self.error,
            assets_found: self.assets_found.map(|v| v as u32),
            services_found: self.services_found.map(|v| v as u32),
        }
    }
}

fn parse_ts(ts: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
}

impl SqliteStore {
    /// Open (creating if necessary) the database at `path` and run migrations.
    pub async fn open(path: &std::path::Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating database directory {}", parent.display()))?;
            }
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .context("connecting to sqlite database")?;

        sqlx::migrate!()
            .run(&pool)
            .await
            .context("running database migrations")?;

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

/// Re-create dependency edges from every recorded connection against the
/// current asset inventory. Run after each persisted observation batch and
/// exposed for re-scanning so no edge is missing because of collection order.
const RECONCILE_DEPENDENCIES_SQL: &str = "
    INSERT OR IGNORE INTO dependencies \
       (source_asset_id, target_asset_id, proto, port, evidence_source, confidence, confirmed) \
     SELECT c.asset_id, a.id, c.proto, c.remote_port, 'active-connections', 0.9, 0 \
     FROM asset_connections c \
     JOIN assets a ON a.ip = c.remote_ip \
     WHERE c.asset_id != a.id";

#[async_trait::async_trait]
impl crate::store::traits::Store for SqliteStore {
    fn database_type(&self) -> &'static str {
        "sqlite"
    }

    async fn store_observations(&self, observations: Vec<Observation>) -> Result<()> {
        let mut tx = self.pool.begin().await.context("beginning transaction")?;

        for obs in observations {
            match obs {
                Observation::Asset(asset) => {
                    let ip = asset.ip.to_string();
                    sqlx::query(
                        "INSERT INTO assets (id, ip, hostname, device_class, os_name, os_version, first_seen, last_seen) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7) \
                         ON CONFLICT(ip) DO UPDATE SET \
                           hostname = COALESCE(excluded.hostname, assets.hostname), \
                           device_class = COALESCE(excluded.device_class, assets.device_class), \
                           os_name = COALESCE(excluded.os_name, assets.os_name), \
                           os_version = COALESCE(excluded.os_version, assets.os_version), \
                           last_seen = excluded.last_seen",
                    )
                    .bind(&asset.id)
                    .bind(&ip)
                    .bind(&asset.hostname)
                    .bind(&asset.device_class)
                    .bind(&asset.os_name)
                    .bind(&asset.os_version)
                    .bind(asset.first_seen.to_rfc3339())
                    .execute(&mut *tx)
                    .await
                    .context("inserting asset")?;
                }
                Observation::Service(service) => {
                    sqlx::query(
                        "INSERT OR IGNORE INTO services \
                           (asset_id, proto, port, name, state, banner) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    )
                    .bind(&service.asset_id)
                    .bind(&service.proto)
                    .bind(service.port as i64)
                    .bind(&service.name)
                    .bind(&service.state)
                    .bind(&service.banner)
                    .execute(&mut *tx)
                    .await
                    .context("inserting service")?;
                }
                Observation::Interface(interface) => {
                    sqlx::query(
                        "INSERT INTO asset_interfaces (id, asset_id, name, mac, ip, vendor, mtu, if_index, is_up) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
                         ON CONFLICT(id) DO UPDATE SET \
                           name = COALESCE(excluded.name, asset_interfaces.name), \
                           vendor = COALESCE(excluded.vendor, asset_interfaces.vendor), \
                           mtu = COALESCE(excluded.mtu, asset_interfaces.mtu), \
                           is_up = COALESCE(excluded.is_up, asset_interfaces.is_up)",
                    )
                    .bind(&interface.id)
                    .bind(&interface.asset_id)
                    .bind(&interface.name)
                    .bind(&interface.mac)
                    .bind(interface.ip.map(|ip| ip.to_string()))
                    .bind(&interface.vendor)
                    .bind(interface.mtu.map(|m| m as i64))
                    .bind(interface.if_index.map(|i| i as i64))
                    .bind(interface.is_up)
                    .execute(&mut *tx)
                    .await
                    .context("inserting interface")?;
                }
                Observation::Dependency(dep) => {
                    sqlx::query(
                        "INSERT OR IGNORE INTO dependencies \
                           (source_asset_id, target_asset_id, proto, port, evidence_source, confidence, confirmed) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    )
                    .bind(&dep.source_asset_id)
                    .bind(&dep.target_asset_id)
                    .bind(&dep.proto)
                    .bind(dep.port as i64)
                    .bind(&dep.evidence_source)
                    .bind(dep.confidence)
                    .bind(dep.confirmed)
                    .execute(&mut *tx)
                    .await
                    .context("inserting dependency")?;
                }
                Observation::Capacity(capacity) => {
                    // #8: overwrite every measured field with the latest
                    // observation instead of COALESCE-ing against the previous
                    // row. A later scan that no longer detects a field (e.g.
                    // CPU model) records NULL here, so "unknown now" is never
                    // conflated with "value unchanged".
                    sqlx::query(
                        "INSERT INTO asset_capacity \
                           (asset_id, cpu_model, cpu_sockets, cpu_cores, cpu_threads, ram_total_mb, collected_at) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                         ON CONFLICT(asset_id) DO UPDATE SET \
                           cpu_model = excluded.cpu_model, \
                           cpu_sockets = excluded.cpu_sockets, \
                           cpu_cores = excluded.cpu_cores, \
                           cpu_threads = excluded.cpu_threads, \
                           ram_total_mb = excluded.ram_total_mb, \
                           collected_at = excluded.collected_at",
                    )
                    .bind(&capacity.asset_id)
                    .bind(&capacity.cpu_model)
                    .bind(capacity.cpu_sockets.map(|v| v as i64))
                    .bind(capacity.cpu_cores.map(|v| v as i64))
                    .bind(capacity.cpu_threads.map(|v| v as i64))
                    .bind(capacity.ram_total_mb.map(|v| v as i64))
                    .bind(capacity.collected_at.to_rfc3339())
                    .execute(&mut *tx)
                    .await
                    .context("inserting capacity")?;
                }
                Observation::Filesystem(fs) => {
                    sqlx::query(
                        "INSERT INTO asset_filesystems \
                           (asset_id, device, mount, fs_type, size_kb, used_kb, available_kb, used_pct) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                         ON CONFLICT(asset_id, mount) DO UPDATE SET \
                           device = COALESCE(excluded.device, asset_filesystems.device), \
                           fs_type = COALESCE(excluded.fs_type, asset_filesystems.fs_type), \
                           size_kb = excluded.size_kb, \
                           used_kb = excluded.used_kb, \
                           available_kb = excluded.available_kb, \
                           used_pct = excluded.used_pct",
                    )
                    .bind(&fs.asset_id)
                    .bind(&fs.device)
                    .bind(&fs.mount)
                    .bind(&fs.fs_type)
                    .bind(fs.size_kb as i64)
                    .bind(fs.used_kb.map(|v| v as i64))
                    .bind(fs.available_kb.map(|v| v as i64))
                    .bind(fs.used_pct.map(|v| v as i64))
                    .execute(&mut *tx)
                    .await
                    .context("inserting filesystem")?;
                }
                Observation::RunningService(svc) => {
                    sqlx::query(
                        "INSERT INTO asset_running_services (asset_id, name, state, description) \
                         VALUES (?1, ?2, ?3, ?4) \
                         ON CONFLICT(asset_id, name) DO UPDATE SET \
                           state = excluded.state, \
                           description = COALESCE(excluded.description, asset_running_services.description)",
                    )
                    .bind(&svc.asset_id)
                    .bind(&svc.name)
                    .bind(&svc.state)
                    .bind(&svc.description)
                    .execute(&mut *tx)
                    .await
                    .context("inserting running service")?;
                }
                Observation::Connection(conn) => {
                    let remote_ip = conn.remote_ip.to_string();
                    let now = chrono::Utc::now().to_rfc3339();
                    sqlx::query(
                        "INSERT INTO asset_connections \
                           (asset_id, proto, local_ip, local_port, remote_ip, remote_port, process, first_seen, last_seen) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8) \
                         ON CONFLICT(asset_id, proto, remote_ip, remote_port) DO UPDATE SET \
                           local_ip = COALESCE(excluded.local_ip, asset_connections.local_ip), \
                           local_port = COALESCE(excluded.local_port, asset_connections.local_port), \
                           process = COALESCE(excluded.process, asset_connections.process), \
                           last_seen = excluded.last_seen",
                    )
                    .bind(&conn.asset_id)
                    .bind(&conn.proto)
                    .bind(conn.local_ip.map(|ip| ip.to_string()))
                    .bind(conn.local_port.map(|p| p as i64))
                    .bind(&remote_ip)
                    .bind(conn.remote_port as i64)
                    .bind(&conn.process)
                    .bind(&now)
                    .execute(&mut *tx)
                    .await
                    .context("inserting connection")?;
                }
                Observation::MetricSample(sample) => {
                    sqlx::query(
                        "INSERT INTO metric_samples \
                           (id, asset_id, sampled_at, cpu_usage_percent, ram_used_mb, \
                            ram_available_mb, swap_used_mb, load_1m, load_5m, load_15m) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    )
                    .bind(uuid::Uuid::new_v4().to_string())
                    .bind(&sample.asset_id)
                    .bind(sample.sampled_at.to_rfc3339())
                    .bind(sample.cpu_usage_percent.map(f64::from))
                    .bind(sample.ram_used_mb.map(|v| v as i64))
                    .bind(sample.ram_available_mb.map(|v| v as i64))
                    .bind(sample.swap_used_mb.map(|v| v as i64))
                    .bind(sample.load_1m.map(f64::from))
                    .bind(sample.load_5m.map(f64::from))
                    .bind(sample.load_15m.map(f64::from))
                    .execute(&mut *tx)
                    .await
                    .context("inserting metric sample")?;
                }
            }
        }

        // #6: re-resolve every recorded connection into a dependency edge
        // against the current asset inventory. Reconciliation runs once for the
        // whole batch (not per connection), so an edge is created even when the
        // target asset only lands in the inventory later in the same run.
        sqlx::query(RECONCILE_DEPENDENCIES_SQL)
            .execute(&mut *tx)
            .await
            .context("reconciling dependency edges")?;

        tx.commit().await.context("committing transaction")?;
        Ok(())
    }

    async fn list_assets(&self) -> Result<Vec<Asset>> {
        let rows = sqlx::query_as::<_, AssetRow>(
            "SELECT id, ip, hostname, device_class, os_name, os_version, \
                    environment, owner, criticality, tags, first_seen, last_seen \
             FROM assets ORDER BY ip",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing assets")?;
        Ok(rows.into_iter().map(AssetRow::into_asset).collect())
    }

    async fn get_asset(&self, id: &str) -> Result<Option<Asset>> {
        let row = sqlx::query_as::<_, AssetRow>(
            "SELECT id, ip, hostname, device_class, os_name, os_version, \
                    environment, owner, criticality, tags, first_seen, last_seen \
             FROM assets WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("fetching asset")?;
        Ok(row.map(AssetRow::into_asset))
    }

    async fn get_asset_by_ip(&self, ip: &str) -> Result<Option<Asset>> {
        let row = sqlx::query_as::<_, AssetRow>(
            "SELECT id, ip, hostname, device_class, os_name, os_version, \
                    environment, owner, criticality, tags, first_seen, last_seen \
             FROM assets WHERE ip = ?1",
        )
        .bind(ip)
        .fetch_optional(&self.pool)
        .await
        .context("fetching asset by ip")?;
        Ok(row.map(AssetRow::into_asset))
    }

    async fn get_asset_by_hostname(&self, hostname: &str) -> Result<Option<Asset>> {
        let row = sqlx::query_as::<_, AssetRow>(
            "SELECT id, ip, hostname, device_class, os_name, os_version, \
                    environment, owner, criticality, tags, first_seen, last_seen \
             FROM assets WHERE hostname = ?1 COLLATE NOCASE",
        )
        .bind(hostname)
        .fetch_optional(&self.pool)
        .await
        .context("fetching asset by hostname")?;
        Ok(row.map(AssetRow::into_asset))
    }

    async fn list_dependencies(&self) -> Result<Vec<Dependency>> {
        let rows = sqlx::query_as::<_, DependencyRow>(
            "SELECT source_asset_id, target_asset_id, proto, port, evidence_source, confidence, confirmed \
             FROM dependencies ORDER BY source_asset_id, port",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing dependencies")?;
        Ok(rows
            .into_iter()
            .map(DependencyRow::into_dependency)
            .collect())
    }

    async fn reconcile_dependencies(&self) -> Result<()> {
        sqlx::query(RECONCILE_DEPENDENCIES_SQL)
            .execute(&self.pool)
            .await
            .context("reconciling dependency edges")?;
        Ok(())
    }

    async fn list_services(&self, asset_id: &str) -> Result<Vec<Service>> {
        let rows = sqlx::query_as::<_, ServiceRow>(
            "SELECT asset_id, proto, port, name, state, banner \
             FROM services WHERE asset_id = ?1 ORDER BY port",
        )
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await
        .context("listing services")?;
        Ok(rows.into_iter().map(ServiceRow::into_service).collect())
    }

    async fn list_interfaces(&self, asset_id: &str) -> Result<Vec<Interface>> {
        let rows = sqlx::query_as::<_, InterfaceRow>(
            "SELECT id, asset_id, name, mac, ip, vendor, mtu, if_index, is_up \
             FROM asset_interfaces WHERE asset_id = ?1 ORDER BY if_index, name",
        )
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await
        .context("listing interfaces")?;
        Ok(rows.into_iter().map(InterfaceRow::into_interface).collect())
    }

    async fn get_capacity(&self, asset_id: &str) -> Result<Option<Capacity>> {
        let row = sqlx::query_as::<_, CapacityRow>(
            "SELECT asset_id, cpu_model, cpu_sockets, cpu_cores, cpu_threads, ram_total_mb, collected_at \
             FROM asset_capacity WHERE asset_id = ?1",
        )
        .bind(asset_id)
        .fetch_optional(&self.pool)
        .await
        .context("fetching capacity")?;
        Ok(row.map(CapacityRow::into_capacity))
    }

    async fn list_filesystems(&self, asset_id: &str) -> Result<Vec<Filesystem>> {
        let rows = sqlx::query_as::<_, FilesystemRow>(
            "SELECT asset_id, device, mount, fs_type, size_kb, used_kb, available_kb, used_pct \
             FROM asset_filesystems WHERE asset_id = ?1 ORDER BY mount",
        )
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await
        .context("listing filesystems")?;
        Ok(rows
            .into_iter()
            .map(FilesystemRow::into_filesystem)
            .collect())
    }

    async fn list_connections(&self, asset_id: &str) -> Result<Vec<Connection>> {
        let rows = sqlx::query_as::<_, ConnectionRow>(
            "SELECT asset_id, proto, local_ip, local_port, remote_ip, remote_port, process \
             FROM asset_connections WHERE asset_id = ?1 ORDER BY remote_ip, remote_port",
        )
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await
        .context("listing connections")?;
        Ok(rows
            .into_iter()
            .map(ConnectionRow::into_connection)
            .collect())
    }

    async fn list_metric_samples(
        &self,
        asset_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<MetricSample>> {
        const SELECT_METRICS: &str =
            "SELECT asset_id, sampled_at, cpu_usage_percent, ram_used_mb, \
                        ram_available_mb, swap_used_mb, load_1m, load_5m, load_15m \
                 FROM metric_samples WHERE asset_id = ?1 ORDER BY sampled_at DESC";
        let sql = match limit {
            Some(n) => format!("{SELECT_METRICS} LIMIT {n}"),
            None => SELECT_METRICS.to_string(),
        };
        let mut rows = sqlx::query_as::<_, MetricSampleRow>(&sql)
            .bind(asset_id)
            .fetch_all(&self.pool)
            .await
            .context("listing metric samples")?;
        rows.reverse(); // oldest first for windowed aggregation
        Ok(rows.into_iter().map(MetricSampleRow::into_sample).collect())
    }

    async fn confirm_dependency(
        &self,
        source: &str,
        target: &str,
        proto: Option<&str>,
        port: Option<u16>,
    ) -> Result<usize> {
        let result = sqlx::query(
            "UPDATE dependencies SET confirmed = 1, confidence = 1.0 \
             WHERE source_asset_id = ?1 AND target_asset_id = ?2 \
               AND (?3 IS NULL OR proto = ?3) \
               AND (?4 IS NULL OR port = ?4)",
        )
        .bind(source)
        .bind(target)
        .bind(proto)
        .bind(port.map(|p| p as i64))
        .execute(&self.pool)
        .await
        .context("confirming dependency")?;
        Ok(result.rows_affected() as usize)
    }

    async fn remove_dependency(
        &self,
        source: &str,
        target: &str,
        proto: Option<&str>,
        port: Option<u16>,
    ) -> Result<usize> {
        let result = sqlx::query(
            "DELETE FROM dependencies \
             WHERE source_asset_id = ?1 AND target_asset_id = ?2 \
               AND (?3 IS NULL OR proto = ?3) \
               AND (?4 IS NULL OR port = ?4)",
        )
        .bind(source)
        .bind(target)
        .bind(proto)
        .bind(port.map(|p| p as i64))
        .execute(&self.pool)
        .await
        .context("removing dependency")?;
        Ok(result.rows_affected() as usize)
    }

    async fn list_running_services(&self, asset_id: &str) -> Result<Vec<RunningService>> {
        let rows = sqlx::query_as::<_, RunningServiceRow>(
            "SELECT asset_id, name, state, description \
             FROM asset_running_services WHERE asset_id = ?1 ORDER BY name",
        )
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await
        .context("listing running services")?;
        Ok(rows
            .into_iter()
            .map(|row| RunningService {
                asset_id: row.asset_id,
                name: row.name,
                state: row.state,
                description: row.description,
            })
            .collect())
    }

    async fn annotate_asset(&self, id: &str, annotations: AssetAnnotations) -> Result<()> {
        let row =
            sqlx::query("SELECT environment, owner, criticality, tags FROM assets WHERE id = ?1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .context("fetching asset for annotation")?
                .ok_or_else(|| anyhow!("no asset matches '{id}'"))?;

        let current_tags: Vec<String> = row
            .try_get::<String, _>("tags")
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();

        let mut tags = current_tags;
        tags.retain(|t| !annotations.remove_tags.iter().any(|r| r == t));
        for tag in &annotations.add_tags {
            if !tags.contains(tag) {
                tags.push(tag.clone());
            }
        }

        let environment = match annotations.environment {
            Some(v) => Some(v),
            None => row.try_get("environment")?,
        };
        let owner = match annotations.owner {
            Some(v) => Some(v),
            None => row.try_get("owner")?,
        };
        let criticality: Option<String> = match annotations.criticality {
            Some(c) => Some(c.to_string()),
            None => row.try_get("criticality")?,
        };

        sqlx::query(
            "UPDATE assets SET environment = ?2, owner = ?3, criticality = ?4, tags = ?5 \
             WHERE id = ?1",
        )
        .bind(id)
        .bind(&environment)
        .bind(&owner)
        .bind(&criticality)
        .bind(serde_json::to_string(&tags)?)
        .execute(&self.pool)
        .await
        .context("annotating asset")?;
        Ok(())
    }

    async fn create_job(&self, job: DiscoveryJob) -> Result<()> {
        sqlx::query(
            "INSERT INTO discovery_jobs \
               (id, collector, targets, status, started_at, finished_at, error, assets_found, services_found) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&job.id)
        .bind(&job.collector)
        .bind(serde_json::to_string(&job.targets)?)
        .bind(status_as_str(job.status))
        .bind(job.started_at.to_rfc3339())
        .bind(job.finished_at.map(|ts| ts.to_rfc3339()))
        .bind(&job.error)
        .bind(job.assets_found.map(|n| n as i64))
        .bind(job.services_found.map(|n| n as i64))
        .execute(&self.pool)
        .await
        .context("creating discovery job")?;
        Ok(())
    }

    async fn get_job(&self, id: &str) -> Result<Option<DiscoveryJob>> {
        let row = sqlx::query_as::<_, JobRow>(
            "SELECT id, collector, targets, status, started_at, finished_at, error, \
                    assets_found, services_found \
             FROM discovery_jobs WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("fetching discovery job")?;
        Ok(row.map(JobRow::into_job))
    }

    async fn list_jobs(&self, limit: Option<usize>) -> Result<Vec<DiscoveryJob>> {
        let mut sql = String::from(
            "SELECT id, collector, targets, status, started_at, finished_at, error, \
                    assets_found, services_found \
             FROM discovery_jobs ORDER BY started_at DESC",
        );
        if let Some(limit) = limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }
        let rows = sqlx::query_as::<_, JobRow>(&sql)
            .fetch_all(&self.pool)
            .await
            .context("listing discovery jobs")?;
        Ok(rows.into_iter().map(JobRow::into_job).collect())
    }

    async fn finish_job(
        &self,
        id: &str,
        status: JobStatus,
        error: Option<String>,
        outcome: Option<JobOutcome>,
    ) -> Result<()> {
        let assets_found = outcome.map(|o| o.assets_found as i64);
        let services_found = outcome.map(|o| o.services_found as i64);
        sqlx::query(
            "UPDATE discovery_jobs \
             SET status = ?2, finished_at = ?3, error = ?4, \
                 assets_found = COALESCE(?5, assets_found), \
                 services_found = COALESCE(?6, services_found) \
             WHERE id = ?1",
        )
        .bind(id)
        .bind(status_as_str(status))
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(&error)
        .bind(assets_found)
        .bind(services_found)
        .execute(&self.pool)
        .await
        .context("finishing discovery job")?;
        Ok(())
    }
}

fn status_as_str(status: JobStatus) -> &'static str {
    match status {
        JobStatus::Pending => "pending",
        JobStatus::Running => "running",
        JobStatus::Succeeded => "succeeded",
        JobStatus::Failed => "failed",
    }
}
