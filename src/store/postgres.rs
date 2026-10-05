//! PostgreSQL store implemented with `sqlx`.
//!
//! Mirrors [`crate::store::sqlite::SqliteStore`] over the same
//! [`crate::store::traits::Store`] contract. The schema lives in
//! `migrations/postgres/` and is applied at startup through
//! `sqlx::migrate!`; row decoding is shared with SQLite through
//! [`crate::store::rows`].
//!
//! Dialect differences against the SQLite store:
//! - `$N` placeholders instead of `?N`;
//! - `INSERT ... ON CONFLICT DO NOTHING` instead of `INSERT OR IGNORE`;
//! - `LOWER(hostname) = LOWER($1)` instead of `COLLATE NOCASE`;
//! - explicit parameter casts where a bare `$N` is ambiguous.

use anyhow::{anyhow, Context, Result};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};

use crate::domain::Observation;
use crate::store::rows::{
    status_as_str, ApplicationMemberRow, ApplicationRow, AssetRow, AuditEventRow, CapacityRow,
    ConnectionRow, DependencyEvidenceRow, DependencyRow, FilesystemRow, InterfaceRow, JobRow,
    MetricSampleRow, RunningServiceRow, ServiceRow,
};
use crate::store::traits::{AnnotationField, AssetAnnotations};

#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Connect to the database at `url` (`postgres://` or `postgresql://`)
    /// and run migrations. TLS is negotiated when the server offers it
    /// (`sslmode=prefer` by default); require it with `?sslmode=require`.
    ///
    /// When the URL carries no password, `ORBYN_PG_PASSWORD` (or the
    /// standard `PGPASSWORD`) supplies one so the credential never has to
    /// appear in the process arguments (audit OY-06).
    pub async fn open(url: &str) -> Result<Self> {
        let mut options: PgConnectOptions = url.parse().context("parsing database URL")?;
        if crate::config::postgres_password_value(url).is_none() {
            if let Some(password) = crate::config::postgres_env_password() {
                options = options.password(&password);
            }
        }

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .context("connecting to postgres database")?;

        sqlx::migrate!("migrations/postgres")
            .run(&pool)
            .await
            .context("running database migrations")?;

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// The annotation values an edit resolves to: requested fields replaced,
/// unset fields cleared, tags merged with the stored ones.
struct MergedAnnotation {
    environment: Option<String>,
    owner: Option<String>,
    criticality: Option<String>,
    tags: Vec<String>,
}

/// Resolve `annotations` against the asset's current row.
///
/// Shared by the single-asset and bulk paths; the executor is generic so the
/// same resolution runs inside a transaction or on the pool directly.
async fn merged_annotation<'e, E>(
    id: &str,
    annotations: &AssetAnnotations,
    executor: E,
) -> Result<MergedAnnotation>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row = sqlx::query("SELECT environment, owner, criticality, tags FROM assets WHERE id = $1")
        .bind(id)
        .fetch_optional(executor)
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

    let environment = if annotations.unset.contains(&AnnotationField::Environment) {
        None
    } else {
        match annotations.environment.clone() {
            Some(v) => Some(v),
            None => row.try_get("environment")?,
        }
    };
    let owner = if annotations.unset.contains(&AnnotationField::Owner) {
        None
    } else {
        match annotations.owner.clone() {
            Some(v) => Some(v),
            None => row.try_get("owner")?,
        }
    };
    let criticality = if annotations.unset.contains(&AnnotationField::Criticality) {
        None
    } else {
        match &annotations.criticality {
            Some(c) => Some(c.to_string()),
            None => row.try_get("criticality")?,
        }
    };

    Ok(MergedAnnotation {
        environment,
        owner,
        criticality,
        tags,
    })
}

/// Re-create dependency edges from every recorded connection against the
/// current asset inventory. Run after each persisted observation batch and
/// exposed for re-scanning so no edge is missing because of collection order.
///
/// The evidence literal must stay in sync with
/// [`crate::domain::EvidenceKind::ActiveConnections`]; a test pins it.
const RECONCILE_DEPENDENCIES_SQL: &str = "
    INSERT INTO dependencies \
       (source_asset_id, target_asset_id, proto, port, evidence_source, confidence, confirmed) \
      SELECT c.asset_id, a.id, c.proto, c.remote_port, 'active-connections', 0.9, FALSE \
      FROM asset_connections c \
      JOIN assets a ON a.ip = c.remote_ip \
      WHERE c.asset_id != a.id \
      ON CONFLICT DO NOTHING";

#[async_trait::async_trait]
impl crate::store::traits::Store for PostgresStore {
    async fn store_observations(&self, observations: Vec<Observation>) -> Result<()> {
        let mut tx = self.pool.begin().await.context("beginning transaction")?;

        for obs in observations {
            match obs {
                Observation::Asset(asset) => {
                    let ip = asset.ip.to_string();
                    sqlx::query(
                        "INSERT INTO assets (id, ip, hostname, device_class, os_name, os_version, sys_descr, first_seen, last_seen) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8) \
                         ON CONFLICT(ip) DO UPDATE SET \
                           hostname = COALESCE(EXCLUDED.hostname, assets.hostname), \
                           device_class = COALESCE(EXCLUDED.device_class, assets.device_class), \
                           os_name = COALESCE(EXCLUDED.os_name, assets.os_name), \
                           os_version = COALESCE(EXCLUDED.os_version, assets.os_version), \
                           sys_descr = COALESCE(EXCLUDED.sys_descr, assets.sys_descr), \
                           last_seen = EXCLUDED.last_seen",
                    )
                    .bind(&asset.id)
                    .bind(&ip)
                    .bind(&asset.hostname)
                    .bind(&asset.device_class)
                    .bind(&asset.os_name)
                    .bind(&asset.os_version)
                    .bind(&asset.sys_descr)
                    .bind(asset.first_seen.to_rfc3339())
                    .execute(&mut *tx)
                    .await
                    .context("inserting asset")?;
                }
                Observation::Service(service) => {
                    sqlx::query(
                        "INSERT INTO services \
                           (asset_id, proto, port, name, state, banner) \
                         VALUES ($1, $2, $3, $4, $5, $6) \
                         ON CONFLICT DO NOTHING",
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
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
                         ON CONFLICT(id) DO UPDATE SET \
                           name = COALESCE(EXCLUDED.name, asset_interfaces.name), \
                           vendor = COALESCE(EXCLUDED.vendor, asset_interfaces.vendor), \
                           mtu = COALESCE(EXCLUDED.mtu, asset_interfaces.mtu), \
                           is_up = COALESCE(EXCLUDED.is_up, asset_interfaces.is_up)",
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
                        "INSERT INTO dependencies \
                           (source_asset_id, target_asset_id, proto, port, evidence_source, confidence, confirmed) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7) \
                         ON CONFLICT DO NOTHING",
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
                           (asset_id, cpu_model, cpu_sockets, cpu_cores, cpu_threads, ram_total_mb, hypervisor, collected_at) \
                          VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                          ON CONFLICT(asset_id) DO UPDATE SET \
                            cpu_model = EXCLUDED.cpu_model, \
                            cpu_sockets = EXCLUDED.cpu_sockets, \
                            cpu_cores = EXCLUDED.cpu_cores, \
                            cpu_threads = EXCLUDED.cpu_threads, \
                            ram_total_mb = EXCLUDED.ram_total_mb, \
                            hypervisor = EXCLUDED.hypervisor, \
                            collected_at = EXCLUDED.collected_at",
                    )
                    .bind(&capacity.asset_id)
                    .bind(&capacity.cpu_model)
                    .bind(capacity.cpu_sockets.map(|v| v as i64))
                    .bind(capacity.cpu_cores.map(|v| v as i64))
                    .bind(capacity.cpu_threads.map(|v| v as i64))
                    .bind(capacity.ram_total_mb.map(|v| v as i64))
                    .bind(&capacity.hypervisor)
                    .bind(capacity.collected_at.to_rfc3339())
                    .execute(&mut *tx)
                    .await
                    .context("inserting capacity")?;
                }
                Observation::Filesystem(fs) => {
                    sqlx::query(
                        "INSERT INTO asset_filesystems \
                           (asset_id, device, mount, fs_type, size_kb, used_kb, available_kb, used_pct) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                         ON CONFLICT(asset_id, mount) DO UPDATE SET \
                           device = COALESCE(EXCLUDED.device, asset_filesystems.device), \
                           fs_type = COALESCE(EXCLUDED.fs_type, asset_filesystems.fs_type), \
                           size_kb = EXCLUDED.size_kb, \
                           used_kb = EXCLUDED.used_kb, \
                           available_kb = EXCLUDED.available_kb, \
                           used_pct = EXCLUDED.used_pct",
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
                         VALUES ($1, $2, $3, $4) \
                         ON CONFLICT(asset_id, name) DO UPDATE SET \
                           state = EXCLUDED.state, \
                           description = COALESCE(EXCLUDED.description, asset_running_services.description)",
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
                    // Re-observing an endpoint increments its counter: the
                    // number of observations is application inference
                    // evidence (repeated communication).
                    sqlx::query(
                        "INSERT INTO asset_connections \
                           (asset_id, proto, local_ip, local_port, remote_ip, remote_port, process, first_seen, last_seen) \
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8) \
                         ON CONFLICT(asset_id, proto, remote_ip, remote_port) DO UPDATE SET \
                           local_ip = COALESCE(EXCLUDED.local_ip, asset_connections.local_ip), \
                           local_port = COALESCE(EXCLUDED.local_port, asset_connections.local_port), \
                           process = COALESCE(EXCLUDED.process, asset_connections.process), \
                           last_seen = EXCLUDED.last_seen, \
                           observation_count = asset_connections.observation_count + 1",
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
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                         ON CONFLICT (asset_id, sampled_at) DO NOTHING",
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

    async fn list_assets(&self) -> Result<Vec<crate::domain::Asset>> {
        let rows = sqlx::query_as::<_, AssetRow>(
            "SELECT id, ip, hostname, device_class, os_name, os_version, sys_descr, \
                    environment, owner, criticality, tags, first_seen, last_seen \
             FROM assets ORDER BY ip",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing assets")?;
        Ok(rows.into_iter().map(AssetRow::into_asset).collect())
    }

    async fn get_asset(&self, id: &str) -> Result<Option<crate::domain::Asset>> {
        let row = sqlx::query_as::<_, AssetRow>(
            "SELECT id, ip, hostname, device_class, os_name, os_version, sys_descr, \
                    environment, owner, criticality, tags, first_seen, last_seen \
             FROM assets WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("fetching asset")?;
        Ok(row.map(AssetRow::into_asset))
    }

    async fn get_asset_by_ip(&self, ip: &str) -> Result<Option<crate::domain::Asset>> {
        let row = sqlx::query_as::<_, AssetRow>(
            "SELECT id, ip, hostname, device_class, os_name, os_version, sys_descr, \
                    environment, owner, criticality, tags, first_seen, last_seen \
             FROM assets WHERE ip = $1",
        )
        .bind(ip)
        .fetch_optional(&self.pool)
        .await
        .context("fetching asset by ip")?;
        Ok(row.map(AssetRow::into_asset))
    }

    async fn get_asset_by_hostname(&self, hostname: &str) -> Result<Option<crate::domain::Asset>> {
        let row = sqlx::query_as::<_, AssetRow>(
            "SELECT id, ip, hostname, device_class, os_name, os_version, sys_descr, \
                    environment, owner, criticality, tags, first_seen, last_seen \
             FROM assets WHERE LOWER(hostname) = LOWER($1) ORDER BY id ASC LIMIT 1",
        )
        .bind(hostname)
        .fetch_optional(&self.pool)
        .await
        .context("fetching asset by hostname")?;
        Ok(row.map(AssetRow::into_asset))
    }

    async fn list_dependencies(&self) -> Result<Vec<crate::domain::Dependency>> {
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

    async fn list_services(&self, asset_id: &str) -> Result<Vec<crate::domain::Service>> {
        let rows = sqlx::query_as::<_, ServiceRow>(
            "SELECT asset_id, proto, port, name, state, banner \
             FROM services WHERE asset_id = $1 ORDER BY port",
        )
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await
        .context("listing services")?;
        Ok(rows.into_iter().map(ServiceRow::into_service).collect())
    }

    async fn list_interfaces(&self, asset_id: &str) -> Result<Vec<crate::domain::Interface>> {
        let rows = sqlx::query_as::<_, InterfaceRow>(
            "SELECT id, asset_id, name, mac, ip, vendor, mtu, if_index, is_up \
             FROM asset_interfaces WHERE asset_id = $1 ORDER BY if_index, name",
        )
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await
        .context("listing interfaces")?;
        Ok(rows.into_iter().map(InterfaceRow::into_interface).collect())
    }

    async fn get_capacity(&self, asset_id: &str) -> Result<Option<crate::domain::Capacity>> {
        let row = sqlx::query_as::<_, CapacityRow>(
            "SELECT asset_id, cpu_model, cpu_sockets, cpu_cores, cpu_threads, ram_total_mb, hypervisor, collected_at \
             FROM asset_capacity WHERE asset_id = $1",
        )
        .bind(asset_id)
        .fetch_optional(&self.pool)
        .await
        .context("fetching capacity")?;
        Ok(row.map(CapacityRow::into_capacity))
    }

    async fn list_filesystems(&self, asset_id: &str) -> Result<Vec<crate::domain::Filesystem>> {
        let rows = sqlx::query_as::<_, FilesystemRow>(
            "SELECT asset_id, device, mount, fs_type, size_kb, used_kb, available_kb, used_pct \
             FROM asset_filesystems WHERE asset_id = $1 ORDER BY mount",
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

    async fn list_connections(&self, asset_id: &str) -> Result<Vec<crate::domain::Connection>> {
        let rows = sqlx::query_as::<_, ConnectionRow>(
            "SELECT asset_id, proto, local_ip, local_port, remote_ip, remote_port, process \
             FROM asset_connections WHERE asset_id = $1 ORDER BY remote_ip, remote_port",
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

    async fn list_all_services(&self) -> Result<Vec<crate::domain::Service>> {
        let rows = sqlx::query_as::<_, ServiceRow>(
            "SELECT asset_id, proto, port, name, state, banner \
             FROM services ORDER BY asset_id, port",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing all services")?;
        Ok(rows.into_iter().map(ServiceRow::into_service).collect())
    }

    async fn list_all_interfaces(&self) -> Result<Vec<crate::domain::Interface>> {
        let rows = sqlx::query_as::<_, InterfaceRow>(
            "SELECT id, asset_id, name, mac, ip, vendor, mtu, if_index, is_up \
             FROM asset_interfaces ORDER BY asset_id, if_index, name",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing all interfaces")?;
        Ok(rows.into_iter().map(InterfaceRow::into_interface).collect())
    }

    async fn list_all_filesystems(&self) -> Result<Vec<crate::domain::Filesystem>> {
        let rows = sqlx::query_as::<_, FilesystemRow>(
            "SELECT asset_id, device, mount, fs_type, size_kb, used_kb, available_kb, used_pct \
             FROM asset_filesystems ORDER BY asset_id, mount",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing all filesystems")?;
        Ok(rows
            .into_iter()
            .map(FilesystemRow::into_filesystem)
            .collect())
    }

    async fn list_all_capacities(&self) -> Result<Vec<crate::domain::Capacity>> {
        let rows = sqlx::query_as::<_, CapacityRow>(
            "SELECT asset_id, cpu_model, cpu_sockets, cpu_cores, cpu_threads, ram_total_mb, hypervisor, collected_at \
             FROM asset_capacity ORDER BY asset_id",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing all capacities")?;
        Ok(rows.into_iter().map(CapacityRow::into_capacity).collect())
    }

    async fn list_all_connections(&self) -> Result<Vec<crate::domain::Connection>> {
        let rows = sqlx::query_as::<_, ConnectionRow>(
            "SELECT asset_id, proto, local_ip, local_port, remote_ip, remote_port, process \
             FROM asset_connections ORDER BY asset_id, remote_ip, remote_port",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing all connections")?;
        Ok(rows
            .into_iter()
            .map(ConnectionRow::into_connection)
            .collect())
    }

    async fn list_metric_samples(
        &self,
        asset_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<crate::domain::MetricSample>> {
        const SELECT_METRICS: &str =
            "SELECT asset_id, sampled_at, cpu_usage_percent, ram_used_mb, \
                        ram_available_mb, swap_used_mb, load_1m, load_5m, load_15m \
                 FROM metric_samples WHERE asset_id = $1 ORDER BY sampled_at DESC";
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

    async fn list_all_metric_samples(&self) -> Result<Vec<crate::domain::MetricSample>> {
        let rows = sqlx::query_as::<_, MetricSampleRow>(
            "SELECT asset_id, sampled_at, cpu_usage_percent, ram_used_mb, \
                    ram_available_mb, swap_used_mb, load_1m, load_5m, load_15m \
             FROM metric_samples ORDER BY asset_id, sampled_at",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing all metric samples")?;
        Ok(rows.into_iter().map(MetricSampleRow::into_sample).collect())
    }

    async fn insert_metric_samples(
        &self,
        samples: &[crate::domain::MetricSample],
    ) -> Result<usize> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("beginning metric import transaction")?;
        let mut inserted = 0usize;
        for sample in samples {
            let result = sqlx::query(
                "INSERT INTO metric_samples \
                   (id, asset_id, sampled_at, cpu_usage_percent, ram_used_mb, \
                    ram_available_mb, swap_used_mb, load_1m, load_5m, load_15m) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                 ON CONFLICT (asset_id, sampled_at) DO NOTHING",
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
            inserted += result.rows_affected() as usize;
        }
        tx.commit().await.context("committing transaction")?;
        Ok(inserted)
    }

    async fn confirm_dependency(
        &self,
        source: &str,
        target: &str,
        proto: Option<&str>,
        port: Option<u16>,
    ) -> Result<usize> {
        let result = sqlx::query(
            "UPDATE dependencies SET confirmed = TRUE, confidence = 1.0 \
             WHERE source_asset_id = $1 AND target_asset_id = $2 \
               AND ($3::text IS NULL OR proto = $3) \
               AND ($4::bigint IS NULL OR port = $4)",
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
             WHERE source_asset_id = $1 AND target_asset_id = $2 \
               AND ($3::text IS NULL OR proto = $3) \
               AND ($4::bigint IS NULL OR port = $4)",
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

    async fn create_application(&self, application: crate::domain::Application) -> Result<()> {
        let result = sqlx::query(
            "INSERT INTO applications (id, name, source, confidence, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&application.id)
        .bind(&application.name)
        .bind(application.source.as_str())
        .bind(application.confidence)
        .bind(application.created_at.to_rfc3339())
        .bind(application.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await;
        if let Err(e) = result {
            // A name collision is the only expected violation; surface it
            // as a clean error instead of a raw constraint failure.
            if self.get_application(&application.name).await?.is_some() {
                anyhow::bail!("application '{}' already exists", application.name);
            }
            return Err(e).context("creating application");
        }
        Ok(())
    }

    async fn update_application_confidence(&self, id: &str, confidence: f32) -> Result<()> {
        // Manual precedence: only inferred applications are refreshed by
        // discovery; the literal is built from the canonical value.
        let sql = format!(
            "UPDATE applications SET confidence = $2, updated_at = $3 \
             WHERE id = $1 AND source = '{}'",
            crate::domain::AppSource::Inferred.as_str()
        );
        sqlx::query(&sql)
            .bind(id)
            .bind(confidence)
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(&self.pool)
            .await
            .context("updating application confidence")?;
        Ok(())
    }

    async fn delete_application(&self, id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await.context("beginning transaction")?;
        sqlx::query("DELETE FROM application_members WHERE application_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("deleting application members")?;
        sqlx::query("DELETE FROM applications WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("deleting application")?;
        tx.commit().await.context("committing transaction")
    }

    async fn list_applications(&self) -> Result<Vec<crate::domain::Application>> {
        let rows = sqlx::query_as::<_, ApplicationRow>(
            "SELECT id, name, source, confidence, created_at, updated_at \
             FROM applications ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing applications")?;
        Ok(rows
            .into_iter()
            .map(ApplicationRow::into_application)
            .collect())
    }

    async fn get_application(
        &self,
        id_or_name: &str,
    ) -> Result<Option<crate::domain::Application>> {
        let by_id = sqlx::query_as::<_, ApplicationRow>(
            "SELECT id, name, source, confidence, created_at, updated_at \
             FROM applications WHERE id = $1",
        )
        .bind(id_or_name)
        .fetch_optional(&self.pool)
        .await
        .context("fetching application")?;
        if let Some(row) = by_id {
            return Ok(Some(row.into_application()));
        }
        let by_name = sqlx::query_as::<_, ApplicationRow>(
            "SELECT id, name, source, confidence, created_at, updated_at \
             FROM applications WHERE LOWER(name) = LOWER($1) LIMIT 1",
        )
        .bind(id_or_name)
        .fetch_optional(&self.pool)
        .await
        .context("fetching application by name")?;
        Ok(by_name.map(ApplicationRow::into_application))
    }

    async fn list_application_members(
        &self,
        application_id: &str,
    ) -> Result<Vec<crate::domain::ApplicationMember>> {
        let rows = sqlx::query_as::<_, ApplicationMemberRow>(
            "SELECT application_id, asset_id, source, confidence, evidence, is_excluded \
             FROM application_members WHERE application_id = $1 ORDER BY asset_id",
        )
        .bind(application_id)
        .fetch_all(&self.pool)
        .await
        .context("listing application members")?;
        Ok(rows
            .into_iter()
            .map(ApplicationMemberRow::into_member)
            .collect())
    }

    async fn add_application_member(&self, member: crate::domain::ApplicationMember) -> Result<()> {
        // Manual precedence: an existing manual row is never overwritten;
        // an inferred or tombstone row is upgraded to the new values.
        let sql = format!(
            "INSERT INTO application_members \
               (application_id, asset_id, source, confidence, evidence, is_excluded) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT(application_id, asset_id) DO UPDATE SET \
               source = EXCLUDED.source, \
               confidence = EXCLUDED.confidence, \
               evidence = EXCLUDED.evidence, \
               is_excluded = EXCLUDED.is_excluded \
             WHERE application_members.source != '{}'",
            crate::domain::AppSource::Manual.as_str()
        );
        sqlx::query(&sql)
            .bind(&member.application_id)
            .bind(&member.asset_id)
            .bind(member.source.as_str())
            .bind(member.confidence)
            .bind(serde_json::to_string(&member.evidence)?)
            .bind(member.is_excluded)
            .execute(&self.pool)
            .await
            .context("adding application member")?;
        Ok(())
    }

    async fn remove_application_member(
        &self,
        application_id: &str,
        asset_id: &str,
    ) -> Result<bool> {
        let row = sqlx::query(
            "SELECT source FROM application_members \
             WHERE application_id = $1 AND asset_id = $2",
        )
        .bind(application_id)
        .bind(asset_id)
        .fetch_optional(&self.pool)
        .await
        .context("fetching application member")?;
        let Some(row) = row else {
            return Ok(false);
        };
        let source: String = row.try_get("source").context("reading member source")?;
        if source == crate::domain::AppSource::Manual.as_str() {
            sqlx::query(
                "DELETE FROM application_members \
                 WHERE application_id = $1 AND asset_id = $2",
            )
            .bind(application_id)
            .bind(asset_id)
            .execute(&self.pool)
            .await
            .context("removing application member")?;
        } else {
            // Inferred member: keep a tombstone so re-discovery cannot
            // re-add the asset the user explicitly removed.
            sqlx::query(
                "UPDATE application_members SET is_excluded = TRUE \
                 WHERE application_id = $1 AND asset_id = $2",
            )
            .bind(application_id)
            .bind(asset_id)
            .execute(&self.pool)
            .await
            .context("excluding application member")?;
        }
        Ok(true)
    }

    async fn replace_inferred_members(
        &self,
        application_id: &str,
        members: Vec<crate::domain::ApplicationMember>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.context("beginning transaction")?;
        // Only the inferred, non-excluded slice is refreshed: manual rows
        // and exclusion tombstones survive re-discovery.
        let delete_sql = format!(
            "DELETE FROM application_members \
             WHERE application_id = $1 AND source = '{}' AND is_excluded = FALSE",
            crate::domain::AppSource::Inferred.as_str()
        );
        sqlx::query(&delete_sql)
            .bind(application_id)
            .execute(&mut *tx)
            .await
            .context("replacing inferred application members")?;
        for member in members {
            // DO NOTHING keeps manual rows and tombstones that the caller
            // could not have filtered (e.g. created concurrently).
            sqlx::query(
                "INSERT INTO application_members \
                   (application_id, asset_id, source, confidence, evidence, is_excluded) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (application_id, asset_id) DO NOTHING",
            )
            .bind(application_id)
            .bind(&member.asset_id)
            .bind(crate::domain::AppSource::Inferred.as_str())
            .bind(member.confidence)
            .bind(serde_json::to_string(&member.evidence)?)
            .bind(false)
            .execute(&mut *tx)
            .await
            .context("inserting inferred application member")?;
        }
        tx.commit().await.context("committing transaction")
    }

    async fn list_dependency_evidence(&self) -> Result<Vec<crate::domain::DependencyEvidence>> {
        let rows = sqlx::query_as::<_, DependencyEvidenceRow>(
            "SELECT c.asset_id AS source_asset_id, a.id AS target_asset_id, \
                    c.proto, c.remote_port AS port, SUM(c.observation_count) AS observations \
             FROM asset_connections c \
             JOIN assets a ON a.ip = c.remote_ip \
             WHERE c.asset_id != a.id \
             GROUP BY c.asset_id, a.id, c.proto, c.remote_port \
             ORDER BY c.asset_id, a.id, c.proto, c.remote_port",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing dependency evidence")?;
        Ok(rows
            .into_iter()
            .map(DependencyEvidenceRow::into_evidence)
            .collect())
    }

    async fn list_running_services(
        &self,
        asset_id: &str,
    ) -> Result<Vec<crate::domain::RunningService>> {
        let rows = sqlx::query_as::<_, RunningServiceRow>(
            "SELECT asset_id, name, state, description \
             FROM asset_running_services WHERE asset_id = $1 ORDER BY name",
        )
        .bind(asset_id)
        .fetch_all(&self.pool)
        .await
        .context("listing running services")?;
        Ok(rows
            .into_iter()
            .map(RunningServiceRow::into_running_service)
            .collect())
    }

    async fn annotate_asset(&self, id: &str, annotations: AssetAnnotations) -> Result<()> {
        let merged = merged_annotation(id, &annotations, &self.pool).await?;
        sqlx::query(
            "UPDATE assets SET environment = $2, owner = $3, criticality = $4, tags = $5 \
             WHERE id = $1",
        )
        .bind(id)
        .bind(&merged.environment)
        .bind(&merged.owner)
        .bind(&merged.criticality)
        .bind(serde_json::to_string(&merged.tags)?)
        .execute(&self.pool)
        .await
        .context("annotating asset")?;
        Ok(())
    }

    /// Apply every edit in one transaction: a bulk import commits once
    /// instead of once per asset.
    async fn annotate_assets(&self, edits: Vec<(String, AssetAnnotations)>) -> Result<()> {
        let mut tx = self.pool.begin().await.context("beginning transaction")?;
        for (id, annotations) in edits {
            let merged = merged_annotation(&id, &annotations, &mut *tx).await?;
            sqlx::query(
                "UPDATE assets SET environment = $2, owner = $3, criticality = $4, tags = $5 \
                 WHERE id = $1",
            )
            .bind(&id)
            .bind(&merged.environment)
            .bind(&merged.owner)
            .bind(&merged.criticality)
            .bind(serde_json::to_string(&merged.tags)?)
            .execute(&mut *tx)
            .await
            .context("annotating asset")?;
        }
        tx.commit().await.context("committing annotations")
    }

    async fn create_job(&self, job: crate::domain::DiscoveryJob) -> Result<()> {
        sqlx::query(
            "INSERT INTO discovery_jobs \
               (id, collector, targets, status, started_at, finished_at, error, \
                assets_found, services_found, filesystems_found, running_services_found, connections_found) \
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
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
        .bind(job.filesystems_found.map(|n| n as i64))
        .bind(job.running_services_found.map(|n| n as i64))
        .bind(job.connections_found.map(|n| n as i64))
        .execute(&self.pool)
        .await
        .context("creating discovery job")?;
        Ok(())
    }

    async fn get_job(&self, id: &str) -> Result<Option<crate::domain::DiscoveryJob>> {
        let row = sqlx::query_as::<_, JobRow>(
            "SELECT id, collector, targets, status, started_at, finished_at, error, \
                    assets_found, services_found, filesystems_found, \
                    running_services_found, connections_found \
             FROM discovery_jobs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("fetching discovery job")?;
        Ok(row.map(JobRow::into_job))
    }

    async fn list_jobs(&self, limit: Option<usize>) -> Result<Vec<crate::domain::DiscoveryJob>> {
        let mut sql = String::from(
            "SELECT id, collector, targets, status, started_at, finished_at, error, \
                    assets_found, services_found, filesystems_found, \
                    running_services_found, connections_found \
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
        status: crate::domain::JobStatus,
        error: Option<String>,
        outcome: Option<crate::domain::JobOutcome>,
    ) -> Result<()> {
        let assets_found = outcome.map(|o| o.assets_found as i64);
        let services_found = outcome.map(|o| o.services_found as i64);
        let filesystems_found = outcome.map(|o| o.filesystems_found as i64);
        let running_services_found = outcome.map(|o| o.running_services_found as i64);
        let connections_found = outcome.map(|o| o.connections_found as i64);
        sqlx::query(
            "UPDATE discovery_jobs \
             SET status = $2, finished_at = $3, error = $4, \
                 assets_found = COALESCE($5::bigint, assets_found), \
                 services_found = COALESCE($6::bigint, services_found), \
                 filesystems_found = COALESCE($7::bigint, filesystems_found), \
                 running_services_found = COALESCE($8::bigint, running_services_found), \
                 connections_found = COALESCE($9::bigint, connections_found) \
             WHERE id = $1",
        )
        .bind(id)
        .bind(status_as_str(status))
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(&error)
        .bind(assets_found)
        .bind(services_found)
        .bind(filesystems_found)
        .bind(running_services_found)
        .bind(connections_found)
        .execute(&self.pool)
        .await
        .context("finishing discovery job")?;
        Ok(())
    }

    async fn create_audit_event(&self, event: crate::domain::AuditEvent) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_events \
               (id, action, target, status, started_at, finished_at, details, error) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&event.id)
        .bind(&event.action)
        .bind(&event.target)
        .bind(status_as_str(event.status))
        .bind(event.started_at.to_rfc3339())
        .bind(event.finished_at.map(|ts| ts.to_rfc3339()))
        .bind(&event.details)
        .bind(&event.error)
        .execute(&self.pool)
        .await
        .context("creating audit event")?;
        Ok(())
    }

    async fn list_audit_events(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<crate::domain::AuditEvent>> {
        let mut sql = String::from(
            "SELECT id, action, target, status, started_at, finished_at, details, error \
             FROM audit_events ORDER BY started_at DESC",
        );
        if let Some(limit) = limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }
        let rows = sqlx::query_as::<_, AuditEventRow>(&sql)
            .fetch_all(&self.pool)
            .await
            .context("listing audit events")?;
        Ok(rows.into_iter().map(AuditEventRow::into_event).collect())
    }

    async fn finish_audit_event(
        &self,
        id: &str,
        status: crate::domain::JobStatus,
        error: Option<String>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE audit_events SET status = $2, finished_at = $3, error = $4 WHERE id = $1",
        )
        .bind(id)
        .bind(status_as_str(status))
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(error)
        .execute(&self.pool)
        .await
        .context("finishing audit event")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::EvidenceKind;

    /// The reconcile SQL hardcodes the evidence literal; it must stay in
    /// sync with the canonical `EvidenceKind` value.
    #[test]
    fn reconcile_sql_uses_canonical_evidence_kind() {
        assert!(RECONCILE_DEPENDENCIES_SQL
            .contains(format!("'{}'", EvidenceKind::ActiveConnections.as_str()).as_str()));
    }
}
