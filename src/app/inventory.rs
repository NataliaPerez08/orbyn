//! Inventory workflows: asset resolution, composite detail assembly, and
//! the persistence of imported (file, NetBox) and cloud inventories.

use anyhow::{anyhow, Context, Result};
use chrono::Utc;

use orbyn::domain::{
    asset_id, Asset, Criticality, DiscoveryJob, Interface, JobOutcome, JobStatus, Observation,
    Service,
};
use orbyn::import::{resolve_asset_id, ImportedInventory, ImportedStats};
use orbyn::integrations::cloud::{CloudCounts, CloudInventory};
use orbyn::output::Format;
use orbyn::store::traits::AssetAnnotations;
use orbyn::store::Store;

/// Asset rows written per transaction during an import.
///
/// Large enough that a bulk import pays a handful of commits instead of one
/// per asset, small enough that a single transaction never holds the database
/// write lock for a very long time.
pub(crate) const IMPORT_WRITE_CHUNK: usize = 500;

/// Resolve an asset reference that may be an id, an IP address, or a
/// hostname (exact, case-insensitive).
pub(crate) async fn resolve_asset(store: &dyn Store, key: &str) -> Result<Asset> {
    if let Some(asset) = store.get_asset(key).await? {
        return Ok(asset);
    }
    if let Some(asset) = store.get_asset_by_ip(key).await? {
        return Ok(asset);
    }
    if let Some(asset) = store.get_asset_by_hostname(key).await? {
        return Ok(asset);
    }
    Err(anyhow!("no asset matches '{key}'"))
}

/// Fetch every asset facet from the store and render the composite detail.
pub(crate) async fn render_asset_detail(
    store: &dyn Store,
    asset: &Asset,
    format: Format,
) -> Result<String> {
    let services = store.list_services(&asset.id).await?;
    let ifaces = store.list_interfaces(&asset.id).await?;
    let capacity = store.get_capacity(&asset.id).await?;
    let filesystems = store.list_filesystems(&asset.id).await?;
    let running = store.list_running_services(&asset.id).await?;
    Ok(orbyn::output::asset_detail(
        asset,
        &services,
        &ifaces,
        capacity.as_ref(),
        &filesystems,
        &running,
        format,
    ))
}

/// Persist an imported inventory — assets plus the interfaces and services
/// emitted by `orbyn export` — recording an audit job under the given
/// collector name. Shared by `import` and `netbox`.
///
/// Interface and service rows whose `asset_id` matches neither an asset in
/// this import nor an existing inventory row are skipped with a warning
/// instead of failing the whole import.
pub(crate) async fn persist_imported_inventory(
    store: &dyn Store,
    inv: &ImportedInventory,
    collector: &str,
) -> Result<ImportedStats> {
    let (rows, duplicates) = orbyn::import::deduplicate(inv.assets.clone());
    if duplicates > 0 {
        tracing::warn!(
            duplicates,
            "skipped duplicate import rows that share an IP address"
        );
    }

    // Validate every asset row before writing anything, so a malformed input
    // never leaves a half-applied import behind.
    let mut assets = Vec::with_capacity(rows.len());
    for row in &rows {
        let ip: std::net::IpAddr = row
            .ip
            .parse()
            .with_context(|| format!("invalid IP '{}' in import", row.ip))?;
        let criticality = row
            .criticality
            .as_deref()
            .map(str::parse::<Criticality>)
            .transpose()
            .map_err(anyhow::Error::msg)?;
        assets.push((row, ip, criticality));
    }

    // Asset ids that interface/service rows may reference: the ids this
    // import creates, plus everything already in the inventory.
    let mut known_ids: std::collections::HashSet<String> =
        assets.iter().map(|&(_, ip, _)| asset_id(ip)).collect();
    for existing in store.list_assets().await? {
        known_ids.insert(existing.id);
    }

    let mut observations = Vec::new();
    let mut interfaces_persisted = 0usize;
    let mut services_persisted = 0usize;
    let mut skipped_refs = 0usize;
    for iface in &inv.interfaces {
        let asset_id = resolve_asset_id(&iface.asset_id);
        if !known_ids.contains(&asset_id) {
            skipped_refs += 1;
            tracing::warn!(
                asset = %iface.asset_id,
                "skipped interface row referencing an unknown asset"
            );
            continue;
        }
        let mut interface = Interface::new(
            &asset_id,
            iface.name.as_deref(),
            iface.mac.as_deref(),
            iface.ip,
        );
        interface.vendor = iface.vendor.clone();
        interface.mtu = iface.mtu;
        interface.if_index = iface.if_index;
        interface.is_up = iface.is_up;
        interfaces_persisted += 1;
        observations.push(Observation::Interface(interface));
    }
    for svc in &inv.services {
        let asset_id = resolve_asset_id(&svc.asset_id);
        if !known_ids.contains(&asset_id) {
            skipped_refs += 1;
            tracing::warn!(
                asset = %svc.asset_id,
                "skipped service row referencing an unknown asset"
            );
            continue;
        }
        services_persisted += 1;
        observations.push(Observation::Service(Service {
            asset_id,
            proto: svc.proto.clone(),
            port: svc.port,
            name: svc.name.clone(),
            state: svc.state.clone(),
            banner: svc.banner.clone(),
        }));
    }
    if skipped_refs > 0 {
        tracing::warn!(
            skipped_refs,
            "skipped import rows referencing unknown assets"
        );
    }

    if assets.is_empty() && observations.is_empty() {
        return Ok(ImportedStats::default());
    }

    let job = DiscoveryJob {
        id: uuid::Uuid::new_v4().to_string(),
        collector: collector.into(),
        targets: rows.iter().map(|r| r.ip.clone()).collect(),
        status: JobStatus::Running,
        started_at: Utc::now(),
        finished_at: None,
        error: None,
        assets_found: None,
        services_found: None,
        filesystems_found: None,
        running_services_found: None,
        connections_found: None,
    };
    store.create_job(job.clone()).await?;

    // Assets are written in batches and annotations in a single transaction:
    // a commit per asset turns a large import into thousands of disk syncs.
    let mut persisted = 0u32;
    let mut asset_observations = Vec::with_capacity(assets.len());
    let mut annotation_edits = Vec::with_capacity(assets.len());
    for (row, ip, criticality) in assets {
        let id = asset_id(ip);

        let now = Utc::now();
        asset_observations.push(Observation::Asset(Asset {
            id: id.clone(),
            ip,
            hostname: row.hostname.clone(),
            device_class: row.device_class.clone(),
            os_name: row.os_name.clone(),
            os_version: row.os_version.clone(),
            sys_descr: None,
            environment: None,
            owner: None,
            criticality: None,
            tags: Vec::new(),
            first_seen: now,
            last_seen: now,
        }));
        annotation_edits.push((
            id,
            AssetAnnotations {
                environment: row.environment.clone(),
                owner: row.owner.clone(),
                criticality,
                unset: Vec::new(),
                add_tags: row.tags.clone(),
                remove_tags: Vec::new(),
            },
        ));
        persisted += 1;
    }

    for chunk in asset_observations.chunks(IMPORT_WRITE_CHUNK) {
        store.store_observations(chunk.to_vec()).await?;
    }
    store.annotate_assets(annotation_edits).await?;

    if !observations.is_empty() {
        store.store_observations(observations).await?;
    }

    store
        .finish_job(
            &job.id,
            JobStatus::Succeeded,
            None,
            Some(JobOutcome {
                assets_found: persisted,
                services_found: services_persisted as u32,
                filesystems_found: 0,
                running_services_found: 0,
                connections_found: 0,
            }),
        )
        .await?;

    Ok(ImportedStats {
        assets: persisted as usize,
        interfaces: interfaces_persisted,
        services: services_persisted,
    })
}

/// Persist a normalized cloud inventory — assets, interfaces, services,
/// capacity and filesystems — recording a discovery job named after the
/// provider and attaching its provenance tags to every asset.
///
/// Unlike a flat file import, a cloud adapter has already validated and
/// normalized its rows, so this writes them directly. Assets are written
/// first so interface/service/capacity references satisfy their foreign keys.
pub(crate) async fn persist_cloud_inventory(
    store: &dyn Store,
    inv: &CloudInventory,
) -> Result<CloudCounts> {
    let counts = inv.counts();

    let job = DiscoveryJob {
        id: uuid::Uuid::new_v4().to_string(),
        collector: inv.provenance.provider.clone(),
        targets: vec![inv.provenance.label()],
        status: JobStatus::Running,
        started_at: Utc::now(),
        finished_at: None,
        error: None,
        assets_found: None,
        services_found: None,
        filesystems_found: None,
        running_services_found: None,
        connections_found: None,
    };
    store.create_job(job.clone()).await?;

    // Assets first, in bounded chunks, then their annotations in one
    // transaction (one commit per asset would be thousands of disk syncs).
    let mut asset_observations = Vec::with_capacity(inv.assets.len());
    let mut annotation_edits = Vec::with_capacity(inv.assets.len());
    for cloud_asset in &inv.assets {
        asset_observations.push(Observation::Asset(cloud_asset.asset.clone()));
        let mut tags = cloud_asset.tags.clone();
        tags.extend(inv.provenance.tags());
        annotation_edits.push((
            cloud_asset.asset.id.clone(),
            AssetAnnotations {
                environment: cloud_asset.environment.clone(),
                owner: cloud_asset.owner.clone(),
                criticality: cloud_asset.criticality,
                unset: Vec::new(),
                add_tags: tags,
                remove_tags: Vec::new(),
            },
        ));
    }
    for chunk in asset_observations.chunks(IMPORT_WRITE_CHUNK) {
        store.store_observations(chunk.to_vec()).await?;
    }
    if !annotation_edits.is_empty() {
        store.annotate_assets(annotation_edits).await?;
    }

    let mut observations: Vec<Observation> = Vec::new();
    observations.extend(inv.interfaces.iter().cloned().map(Observation::Interface));
    observations.extend(inv.services.iter().cloned().map(Observation::Service));
    observations.extend(inv.capacities.iter().cloned().map(Observation::Capacity));
    observations.extend(inv.filesystems.iter().cloned().map(Observation::Filesystem));
    if !observations.is_empty() {
        store.store_observations(observations).await?;
    }

    store
        .finish_job(
            &job.id,
            JobStatus::Succeeded,
            None,
            Some(JobOutcome {
                assets_found: counts.assets as u32,
                services_found: counts.services as u32,
                filesystems_found: counts.filesystems as u32,
                running_services_found: 0,
                connections_found: 0,
            }),
        )
        .await?;

    Ok(counts)
}
