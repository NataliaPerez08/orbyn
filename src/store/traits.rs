use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    Asset, Capacity, Criticality, Dependency, DiscoveryJob, Filesystem, Interface, JobOutcome,
    JobStatus, Observation, RunningService, Service,
};

/// Inventory annotation edits applied to an asset.
#[derive(Debug, Clone, Default)]
pub struct AssetAnnotations {
    pub environment: Option<String>,
    pub owner: Option<String>,
    pub criticality: Option<Criticality>,
    /// Tags to add (deduplicated).
    pub add_tags: Vec<String>,
    /// Tags to remove.
    pub remove_tags: Vec<String>,
}

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
    async fn list_interfaces(&self, asset_id: &str) -> Result<Vec<Interface>>;
    async fn list_filesystems(&self, asset_id: &str) -> Result<Vec<Filesystem>>;
    async fn list_running_services(&self, asset_id: &str) -> Result<Vec<RunningService>>;
    /// Latest recorded CPU/RAM capacity for an asset.
    async fn get_capacity(&self, asset_id: &str) -> Result<Option<Capacity>>;
    async fn list_dependencies(&self) -> Result<Vec<Dependency>>;

    /// Apply inventory annotation edits (environment/owner/criticality/tags).
    async fn annotate_asset(&self, id: &str, annotations: AssetAnnotations) -> Result<()>;

    async fn create_job(&self, job: DiscoveryJob) -> Result<()>;
    async fn get_job(&self, id: &str) -> Result<Option<DiscoveryJob>>;
    async fn list_jobs(&self, limit: Option<usize>) -> Result<Vec<DiscoveryJob>>;
    async fn finish_job(
        &self,
        id: &str,
        status: JobStatus,
        error: Option<String>,
        outcome: Option<JobOutcome>,
    ) -> Result<()>;
}
