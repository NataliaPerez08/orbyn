//! SQLite store implemented with `sqlx`.
//!
//! Database schema lives in the top-level `migrations/` directory and is
//! applied at startup through `sqlx::migrate!`.

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, SqlitePool};

use crate::domain::{Asset, DiscoveryJob, JobStatus, Observation, Service};

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
            first_seen: chrono::DateTime::parse_from_rfc3339(&self.first_seen)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            last_seen: chrono::DateTime::parse_from_rfc3339(&self.last_seen)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
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
struct JobRow {
    id: String,
    collector: String,
    targets: String,
    status: String,
    started_at: String,
    finished_at: Option<String>,
    error: Option<String>,
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
            started_at: chrono::DateTime::parse_from_rfc3339(&self.started_at)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            finished_at: self.finished_at.and_then(|ts| {
                chrono::DateTime::parse_from_rfc3339(&ts)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .ok()
            }),
            error: self.error,
        }
    }
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
                        "INSERT INTO assets (id, ip, hostname, first_seen, last_seen) \
                         VALUES (?1, ?2, ?3, ?4, ?4) \
                         ON CONFLICT(ip) DO UPDATE SET \
                           hostname = COALESCE(excluded.hostname, assets.hostname), \
                           last_seen = excluded.last_seen",
                    )
                    .bind(&asset.id)
                    .bind(&ip)
                    .bind(&asset.hostname)
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
                Observation::Dependency(_)
                | Observation::Capacity(_)
                | Observation::MetricSample(_) => {
                    tracing::warn!("observation type not yet persisted");
                }
            }
        }

        tx.commit().await.context("committing transaction")?;
        Ok(())
    }

    async fn list_assets(&self) -> Result<Vec<Asset>> {
        let rows = sqlx::query_as::<_, AssetRow>(
            "SELECT id, ip, hostname, device_class, os_name, os_version, first_seen, last_seen \
             FROM assets ORDER BY ip",
        )
        .fetch_all(&self.pool)
        .await
        .context("listing assets")?;
        Ok(rows.into_iter().map(AssetRow::into_asset).collect())
    }

    async fn get_asset(&self, id: &str) -> Result<Option<Asset>> {
        let row = sqlx::query_as::<_, AssetRow>(
            "SELECT id, ip, hostname, device_class, os_name, os_version, first_seen, last_seen \
             FROM assets WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("fetching asset")?;
        Ok(row.map(AssetRow::into_asset))
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

    async fn create_job(&self, job: DiscoveryJob) -> Result<()> {
        sqlx::query(
            "INSERT INTO discovery_jobs \
               (id, collector, targets, status, started_at, finished_at, error) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(&job.id)
        .bind(&job.collector)
        .bind(serde_json::to_string(&job.targets)?)
        .bind(status_as_str(job.status))
        .bind(job.started_at.to_rfc3339())
        .bind(job.finished_at.map(|ts| ts.to_rfc3339()))
        .bind(&job.error)
        .execute(&self.pool)
        .await
        .context("creating discovery job")?;
        Ok(())
    }

    async fn get_job(&self, id: &str) -> Result<Option<DiscoveryJob>> {
        let row = sqlx::query_as::<_, JobRow>(
            "SELECT id, collector, targets, status, started_at, finished_at, error \
             FROM discovery_jobs WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .context("fetching discovery job")?;
        Ok(row.map(JobRow::into_job))
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
