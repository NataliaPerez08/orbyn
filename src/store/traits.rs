use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    Asset, AuditEvent, Capacity, Connection, Criticality, Dependency, DiscoveryJob, Filesystem,
    Interface, JobOutcome, JobStatus, MetricSample, Observation, RunningService, Service,
};

/// An annotation field that can be cleared with `orbyn annotate --unset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnotationField {
    Environment,
    Owner,
    Criticality,
}

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
    /// Fields to clear. Applied after the setters, so unsetting a field
    /// that is also being set clears it.
    pub unset: Vec<AnnotationField>,
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
    async fn get_asset_by_hostname(&self, hostname: &str) -> Result<Option<Asset>>;
    async fn list_services(&self, asset_id: &str) -> Result<Vec<Service>>;
    async fn list_interfaces(&self, asset_id: &str) -> Result<Vec<Interface>>;
    async fn list_filesystems(&self, asset_id: &str) -> Result<Vec<Filesystem>>;
    async fn list_running_services(&self, asset_id: &str) -> Result<Vec<RunningService>>;
    /// Latest recorded CPU/RAM capacity for an asset.
    async fn get_capacity(&self, asset_id: &str) -> Result<Option<Capacity>>;
    /// Resource utilization samples recorded for an asset (oldest first,
    /// newest by default). A window can be limited to the most recent `limit`.
    async fn list_metric_samples(
        &self,
        asset_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<MetricSample>>;
    /// Every recorded utilization sample, ordered by asset then time. Used
    /// by `assess` to build per-asset windows without N+1 queries.
    async fn list_all_metric_samples(&self) -> Result<Vec<MetricSample>>;
    /// Persist a batch of historical utilization samples (e.g. imported
    /// from Prometheus). A sample colliding on (asset, instant) with an
    /// existing row is skipped, so re-importing the same window is
    /// idempotent. Returns the number of samples actually inserted.
    async fn insert_metric_samples(&self, samples: &[MetricSample]) -> Result<usize>;
    /// Active connections observed on an asset (dependency evidence).
    async fn list_connections(&self, asset_id: &str) -> Result<Vec<Connection>>;
    async fn list_dependencies(&self) -> Result<Vec<Dependency>>;

    // Bulk variants: whole-table reads in one query each, used by `assess`
    // and `export` so large inventories do not degrade into N+1 query loops.

    /// Every recorded service, ordered by asset then port.
    async fn list_all_services(&self) -> Result<Vec<Service>>;
    /// Every recorded interface, ordered by asset then interface index/name.
    async fn list_all_interfaces(&self) -> Result<Vec<Interface>>;
    /// Every recorded filesystem, ordered by asset then mount point.
    async fn list_all_filesystems(&self) -> Result<Vec<Filesystem>>;
    /// Every recorded capacity row (one per asset).
    async fn list_all_capacities(&self) -> Result<Vec<Capacity>>;
    /// Every recorded connection, ordered by asset then remote endpoint.
    async fn list_all_connections(&self) -> Result<Vec<Connection>>;

    /// Re-derive dependency edges from every recorded connection against the
    /// current asset inventory, so an edge does not depend on the collection
    /// order (a connection observed before its target asset landed still maps).
    async fn reconcile_dependencies(&self) -> Result<()>;

    /// Mark observed edges between two assets as confirmed (confidence 1.0).
    /// `proto`/`port` narrow the update; `None` means every edge between the
    /// pair. Returns the number of edges confirmed.
    async fn confirm_dependency(
        &self,
        source: &str,
        target: &str,
        proto: Option<&str>,
        port: Option<u16>,
    ) -> Result<usize>;

    /// Delete edges between two assets. Returns the number removed.
    async fn remove_dependency(
        &self,
        source: &str,
        target: &str,
        proto: Option<&str>,
        port: Option<u16>,
    ) -> Result<usize>;

    /// Apply inventory annotation edits (environment/owner/criticality/tags).
    async fn annotate_asset(&self, id: &str, annotations: AssetAnnotations) -> Result<()>;

    /// Apply annotation edits to several assets.
    ///
    /// Bulk imports use this instead of looping [`Store::annotate_asset`]: one
    /// commit per asset turns a large import into thousands of disk syncs.
    /// The default implementation loops so a backend only has to override it
    /// to get the batching; the built-in backends do, in a single
    /// transaction.
    async fn annotate_assets(&self, edits: Vec<(String, AssetAnnotations)>) -> Result<()> {
        for (id, annotations) in edits {
            self.annotate_asset(&id, annotations).await?;
        }
        Ok(())
    }

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

    async fn create_audit_event(&self, event: AuditEvent) -> Result<()>;
    async fn list_audit_events(&self, limit: Option<usize>) -> Result<Vec<AuditEvent>>;
    async fn finish_audit_event(
        &self,
        id: &str,
        status: JobStatus,
        error: Option<String>,
    ) -> Result<()>;
}
