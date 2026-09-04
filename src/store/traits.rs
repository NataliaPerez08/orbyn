use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{Asset, Dependency, DiscoveryJob, JobStatus, Observation, Service};

/// Storage contracts used across Orbyn.
///
/// Domain/assessment code depends on this trait rather than on a concrete
/// driver. New backends (e.g. PostgreSQL) implement it without touching
/// collectors.
#[async_trait]
pub trait Store: Send + Sync {
    /// Fully-qualified database backend name, useful for diagnostics.
    fn database_type(&self) -> &'static str {
        "unknown"
    }

    /// Persist a batch of normalized observations, reconciling assets.
    async fn store_observations(&self, observations: Vec<Observation>) -> Result<()>;

    /// Persist a single observation.
    async fn store_observation(&self, observation: Observation) -> Result<()> {
        self.store_observations(vec![observation]).await
    }

    async fn list_assets(&self) -> Result<Vec<Asset>>;
    async fn get_asset(&self, id: &str) -> Result<Option<Asset>>;
    async fn get_asset_by_ip(&self, ip: &str) -> Result<Option<Asset>>;
    async fn list_services(&self, asset_id: &str) -> Result<Vec<Service>>;
    async fn list_dependencies(&self) -> Result<Vec<Dependency>>;
    async fn create_job(&self, job: DiscoveryJob) -> Result<()>;
    async fn get_job(&self, id: &str) -> Result<Option<DiscoveryJob>>;
    async fn finish_job(&self, id: &str, status: JobStatus, error: Option<String>) -> Result<()>;
}
