use anyhow::Result;
use async_trait::async_trait;

use crate::domain::{
    Application, ApplicationMember, Asset, AuditEvent, Capacity, Connection, Criticality,
    Dependency, DependencyEvidence, DiscoveryJob, Filesystem, Interface, JobOutcome, JobStatus,
    MetricSample, MigrationPlan, Observation, RunningService, Service,
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

    // Applications (v1.1): persisted logical applications with per-member
    // confidence and evidence. Manual rows always win over inference.

    /// Insert a new application. Fails when the name is already taken.
    async fn create_application(&self, application: Application) -> Result<()>;

    /// Refresh an inferred application's confidence. Manual/imported
    /// applications are never touched (manual precedence).
    async fn update_application_confidence(&self, id: &str, confidence: f32) -> Result<()>;

    /// Delete an application and its member rows.
    async fn delete_application(&self, id: &str) -> Result<()>;

    async fn list_applications(&self) -> Result<Vec<Application>>;

    /// Look up an application by id or (case-insensitive) name.
    async fn get_application(&self, id_or_name: &str) -> Result<Option<Application>>;

    /// All member rows of an application, including manual exclusion
    /// tombstones (`is_excluded`); callers filter what they show.
    async fn list_application_members(
        &self,
        application_id: &str,
    ) -> Result<Vec<ApplicationMember>>;

    /// Add or upgrade a member. A manual add on an existing inferred
    /// member upgrades it to manual and clears any exclusion tombstone.
    async fn add_application_member(&self, member: ApplicationMember) -> Result<()>;

    /// Remove a member. An inferred member becomes an exclusion tombstone
    /// so a later re-discover cannot re-add it; a manual member row is
    /// deleted. Returns true when a row existed.
    async fn remove_application_member(&self, application_id: &str, asset_id: &str)
        -> Result<bool>;

    /// Refresh the inferred members of an application in one transaction:
    /// inferred, non-excluded rows are replaced; manual and tombstone
    /// rows are preserved.
    async fn replace_inferred_members(
        &self,
        application_id: &str,
        members: Vec<ApplicationMember>,
    ) -> Result<()>;

    /// Aggregated per-edge connection observation counts, joined against
    /// the inventory (only connections whose remote IP matches a known
    /// asset). Feeds the application inference engine.
    async fn list_dependency_evidence(&self) -> Result<Vec<DependencyEvidence>>;

    // Migration plans (v1.2): append-only, reproducible artifacts. The
    // scalar summary lives in columns, the detail in JSON.

    /// Persist a migration plan (insert; re-planning appends a new row).
    async fn save_plan(&self, plan: MigrationPlan) -> Result<()>;

    /// Saved plans, newest first; filtered by application when given.
    async fn list_plans(&self, application_id: Option<&str>) -> Result<Vec<MigrationPlan>>;

    /// One saved plan by id.
    async fn get_plan(&self, id: &str) -> Result<Option<MigrationPlan>>;

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
