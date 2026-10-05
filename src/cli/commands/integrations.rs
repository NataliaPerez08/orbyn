//! Handlers for inventory imports and the metrics/CMDB integrations:
//! `import`, `netbox`, `prometheus`, and `zabbix`.

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;

use orbyn::config::Config;
use orbyn::domain::{
    asset_id, Asset, Criticality, DiscoveryJob, Interface, JobOutcome, JobStatus, Observation,
    Service,
};
use orbyn::import::{parse_import_csv, resolve_asset_id, ImportedInventory, ImportedStats};
use orbyn::integrations::netbox::NetBoxClient;
use orbyn::integrations::prometheus::{
    assemble_samples, ImportOptions, PrometheusClient, DEFAULT_CPU_QUERY, DEFAULT_RAM_QUERY,
    DEFAULT_SWAP_QUERY,
};
use orbyn::integrations::zabbix::{
    assemble_samples as zabbix_assemble_samples, ImportOptions as ZabbixImportOptions, ZabbixClient,
};
use orbyn::output::Format;
use orbyn::store::traits::AssetAnnotations;
use orbyn::store::Store;

use crate::cli::args::{ImportFormat, NetboxAction, PrometheusAction, ZabbixAction};
use crate::cli::{
    begin_audit, finish_audit_result, is_plain_http, open_store, resolve_secret, IMPORT_WRITE_CHUNK,
};

/// Handle `orbyn import`.
pub(crate) async fn import(
    config: &Config,
    format: ImportFormat,
    file: Option<PathBuf>,
) -> Result<()> {
    let store = open_store(config).await?;
    let input = read_input(file.as_ref())?;
    let stats = import_inventory(store.as_ref(), &input, format).await?;
    let mut parts = vec![format!("{} assets", stats.assets)];
    if stats.interfaces > 0 {
        parts.push(format!("{} interfaces", stats.interfaces));
    }
    if stats.services > 0 {
        parts.push(format!("{} services", stats.services));
    }
    eprintln!("Imported {}.", parts.join(", "));
    let jobs = store.list_jobs(Some(1)).await?;
    print!("{}", orbyn::output::jobs(&jobs, Format::Table));
    Ok(())
}

/// Handle `orbyn netbox <action>`.
pub(crate) async fn netbox(config: &Config, action: NetboxAction) -> Result<()> {
    let NetboxAction::Import {
        url,
        token,
        no_verify,
    } = action;
    let token = resolve_secret(token, "--token", "ORBYN_NETBOX_TOKEN")?;
    if no_verify {
        tracing::warn!("--no-verify disables TLS certificate verification for NetBox");
        eprintln!(
            "WARNING: --no-verify disables TLS certificate verification.\n\
             Only use this against a trusted self-signed NetBox instance; \
             connections can be silently intercepted."
        );
    }
    if is_plain_http(&url) {
        eprintln!(
            "WARNING: --url uses plain HTTP; the NetBox token will travel \
             unencrypted over the network (audit OY-12)."
        );
    }
    let store = open_store(config).await?;
    let mut redactor = orbyn::redact::Redactor::from_env();
    if let Some(token) = &token {
        redactor.add_value(token);
    }
    let client = NetBoxClient::new(&url, token, no_verify)
        .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
    let inventory = client
        .fetch_inventory()
        .await
        .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
    let stats = persist_imported_inventory(store.as_ref(), &inventory, "netbox")
        .await
        .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
    let mut parts = vec![format!("{} assets", stats.assets)];
    if stats.interfaces > 0 {
        parts.push(format!("{} interfaces", stats.interfaces));
    }
    eprintln!("Imported {} from NetBox.", parts.join(", "));
    let jobs = store.list_jobs(Some(1)).await?;
    print!("{}", orbyn::output::jobs(&jobs, Format::Table));
    Ok(())
}

/// Handle `orbyn prometheus <action>`.
pub(crate) async fn prometheus(config: &Config, action: PrometheusAction) -> Result<()> {
    let PrometheusAction::Import {
        url,
        token,
        no_verify,
        lookback_hours,
        step,
        cpu_query,
        ram_query,
        swap_query,
    } = action;
    let token = resolve_secret(token, "--token", "ORBYN_PROMETHEUS_TOKEN")?;
    if no_verify {
        tracing::warn!("--no-verify disables TLS certificate verification for Prometheus");
        eprintln!(
            "WARNING: --no-verify disables TLS certificate verification.\n\
             Only use this against a trusted self-signed Prometheus instance; \
             connections can be silently intercepted."
        );
    }
    if is_plain_http(&url) && token.is_some() {
        eprintln!(
            "WARNING: --url uses plain HTTP; the Prometheus token will travel \
             unencrypted over the network (audit OY-12)."
        );
    }
    if lookback_hours <= 0 {
        bail!("--lookback-hours must be positive");
    }
    let store = open_store(config).await?;
    let mut redactor = orbyn::redact::Redactor::from_env();
    if let Some(token) = &token {
        redactor.add_value(token);
    }
    let audit = begin_audit(
        store.as_ref(),
        "prometheus.import",
        "metrics",
        Some(&format!("{lookback_hours}h lookback, step {step}")),
    )
    .await?;
    let result: Result<()> = async {
        let client = PrometheusClient::new(&url, token, no_verify)
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        let end = Utc::now();
        let start = end - chrono::Duration::hours(lookback_hours);
        let opts = ImportOptions {
            start,
            end,
            step: step.clone(),
            cpu_query: cpu_query.unwrap_or_else(|| DEFAULT_CPU_QUERY.to_string()),
            ram_query: ram_query.unwrap_or_else(|| DEFAULT_RAM_QUERY.to_string()),
            swap_query: swap_query.unwrap_or_else(|| DEFAULT_SWAP_QUERY.to_string()),
        };
        let fetched = client
            .fetch_utilization(&opts)
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        if fetched.skipped_points > 0 {
            tracing::warn!(
                skipped = fetched.skipped_points,
                "Prometheus returned points that did not parse; they were skipped"
            );
        }
        let assets = store.list_assets().await?;
        let assembled = assemble_samples(&fetched, &assets);
        if assembled.samples.is_empty() {
            bail!(
                "no series matched a known asset ({} unmatched series); discover \
                 or import assets first, or check the `instance` labels",
                assembled.unmatched_series
            );
        }
        let inserted = store.insert_metric_samples(&assembled.samples).await?;
        eprintln!(
            "Imported {inserted} metric samples from Prometheus ({} duplicates \
             skipped, {} unmatched series); see `orbyn metrics <asset>`.",
            assembled.samples.len() - inserted,
            assembled.unmatched_series
        );
        Ok(())
    }
    .await;
    finish_audit_result(store.as_ref(), audit, result).await?;
    Ok(())
}

/// Handle `orbyn zabbix <action>`.
pub(crate) async fn zabbix(config: &Config, action: ZabbixAction) -> Result<()> {
    let ZabbixAction::Import {
        url,
        token,
        no_verify,
        lookback_hours,
    } = action;
    let token = resolve_secret(token, "--token", "ORBYN_ZABBIX_TOKEN")?;
    if no_verify {
        tracing::warn!("--no-verify disables TLS certificate verification for Zabbix");
        eprintln!(
            "WARNING: --no-verify disables TLS certificate verification.\n\
             Only use this against a trusted self-signed Zabbix instance; \
             connections can be silently intercepted."
        );
    }
    if is_plain_http(&url) && token.is_some() {
        eprintln!(
            "WARNING: --url uses plain HTTP; the Zabbix token will travel \
             unencrypted over the network (audit OY-12)."
        );
    }
    if lookback_hours <= 0 {
        bail!("--lookback-hours must be positive");
    }
    let store = open_store(config).await?;
    let mut redactor = orbyn::redact::Redactor::from_env();
    if let Some(token) = &token {
        redactor.add_value(token);
    }
    let audit = begin_audit(
        store.as_ref(),
        "zabbix.import",
        "metrics",
        Some(&format!("{lookback_hours}h lookback")),
    )
    .await?;
    let result: Result<()> = async {
        let client = ZabbixClient::new(&url, token, no_verify)
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        let end = Utc::now();
        let start = end - chrono::Duration::hours(lookback_hours);
        let opts = ZabbixImportOptions { start, end };
        let fetched = client
            .fetch_utilization(&opts)
            .await
            .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
        if fetched.skipped_points > 0 {
            tracing::warn!(
                skipped = fetched.skipped_points,
                "Zabbix returned points that did not parse; they were skipped"
            );
        }
        if fetched.unsupported_items > 0 {
            tracing::warn!(
                items = fetched.unsupported_items,
                "Zabbix items were skipped: expected bytes for memory, or an \
                 unsupported key"
            );
        }
        if fetched.hosts_without_items > 0 {
            tracing::warn!(
                hosts = fetched.hosts_without_items,
                "Zabbix hosts carry none of the supported utilization items"
            );
        }
        let assets = store.list_assets().await?;
        let assembled = zabbix_assemble_samples(&fetched, &assets);
        if assembled.samples.is_empty() {
            bail!(
                "no Zabbix host matched a known asset ({} unmatched hosts); discover \
                 or import assets first, or check the host interfaces and names",
                assembled.unmatched_hosts
            );
        }
        let inserted = store.insert_metric_samples(&assembled.samples).await?;
        eprintln!(
            "Imported {inserted} metric samples from Zabbix ({} duplicates skipped, \
             {} unmatched hosts); see `orbyn metrics <asset>`.",
            assembled.samples.len() - inserted,
            assembled.unmatched_hosts
        );
        Ok(())
    }
    .await;
    finish_audit_result(store.as_ref(), audit, result).await?;
    Ok(())
}

/// Parse an imported inventory, recording an audit job for the operation.
async fn import_inventory(
    store: &dyn Store,
    input: &str,
    format: ImportFormat,
) -> Result<ImportedStats> {
    let inv: ImportedInventory = match format {
        ImportFormat::Json => {
            if input.trim_start().starts_with('[') {
                let assets = serde_json::from_str(input).with_context(|| {
                    "invalid JSON import; expected an array or {\"assets\": [...]} of {ip, hostname, ...} objects"
                })?;
                ImportedInventory {
                    assets,
                    ..Default::default()
                }
            } else {
                let wrapper: serde_json::Value = serde_json::from_str(input).with_context(|| {
                    "invalid JSON import; expected an array or {\"assets\": [...]} of {ip, hostname, ...} objects"
                })?;
                if !["assets", "interfaces", "services"]
                    .iter()
                    .any(|key| wrapper.get(key).is_some())
                {
                    bail!(
                        "invalid JSON import; expected an object with an assets, interfaces or services array"
                    );
                }
                serde_json::from_value(wrapper).with_context(|| {
                    "invalid JSON import; assets, interfaces and services must be arrays of row objects"
                })?
            }
        }
        ImportFormat::Csv => parse_import_csv(input)?,
    };

    persist_imported_inventory(store, &inv, "import").await
}

/// Persist an imported inventory — assets plus the interfaces and services
/// emitted by `orbyn export` — recording an audit job under the given
/// collector name. Shared by `import` and `netbox`.
///
/// Interface and service rows whose `asset_id` matches neither an asset in
/// this import nor an existing inventory row are skipped with a warning
/// instead of failing the whole import.
async fn persist_imported_inventory(
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
    let mut known_ids: HashSet<String> = assets.iter().map(|&(_, ip, _)| asset_id(ip)).collect();
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

/// Read import input from a file or stdin, bounded by
/// [`orbyn::import::MAX_IMPORT_INPUT_BYTES`] (audit OY-19): a redirected file
/// or a hostile producer must not be able to make Orbyn buffer an unbounded
/// input.
fn read_input(file: Option<&PathBuf>) -> Result<String> {
    match file {
        Some(path) => {
            let mut handle = std::fs::File::open(path)
                .with_context(|| format!("reading import file {}", path.display()))?;
            orbyn::import::read_capped(&mut handle, &format!("import file {}", path.display()))
        }
        None => {
            let stdin = std::io::stdin();
            let mut handle = stdin.lock();
            orbyn::import::read_capped(&mut handle, "import from stdin")
        }
    }
}
