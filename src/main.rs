use std::io::Read;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use clap::{ArgAction, Parser, Subcommand, ValueEnum};

use orbyn::assessment::{run_assessment, AssessmentInput};
use orbyn::collectors::credentials::CredentialProfile;
use orbyn::collectors::nmap::NmapCollector;
use orbyn::collectors::snmp::{SnmpCollector, SnmpVersion};
use orbyn::collectors::ssh::LinuxCollector;
use orbyn::collectors::windows::WindowsCollector;
use orbyn::collectors::{validate_target, Collector, ScanTarget};
use orbyn::config::Config;
use orbyn::domain::{
    Asset, Criticality, Dependency, DiscoveryJob, JobOutcome, JobStatus, Observation,
};
use orbyn::output::{Format, Inventory};
use orbyn::parsing::split_csv_line;
use orbyn::store::sqlite::SqliteStore;
use orbyn::store::traits::AssetAnnotations;
use orbyn::store::Store;

#[derive(Debug, Parser)]
#[command(
    name = "orbyn",
    about = "CLI for infrastructure discovery, dependency mapping, and migration assessment."
)]
struct Cli {
    /// Path to the SQLite database (default: ./data/orbyn.db).
    #[arg(long, global = true, env = "ORBYN_DB")]
    db: Option<PathBuf>,

    /// Increase log verbosity (repeatable: -v, -vv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

/// Collector adapter selected for a discovery run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DiscoveryCollector {
    Nmap,
    Snmp,
    Ssh,
    Windows,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ImportFormat {
    Json,
    Csv,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover assets in a CIDR range (Nmap) or collect a single host
    /// (SNMP walk, SSH Linux probe, or Windows PowerShell probe over SSH).
    Discover {
        /// Target IP or CIDR range, e.g. 10.0.0.0/24 (single IP for snmp/ssh/windows).
        #[arg(long)]
        target: String,
        /// Collector adapter to run.
        #[arg(long, value_enum, default_value_t = DiscoveryCollector::Nmap)]
        collector: DiscoveryCollector,
        /// SNMP v1/v2c community string (default from ORBYN_SNMP_COMMUNITY).
        #[arg(long)]
        community: Option<String>,
        /// SNMP protocol version: 1 or 2c.
        #[arg(long, default_value = "2c")]
        snmp_version: String,
        /// SNMP agent UDP port.
        #[arg(long, default_value_t = 161)]
        snmp_port: u16,
        /// SSH login user for ssh/windows collectors (default: current user).
        #[arg(long)]
        user: Option<String>,
        /// SSH port for ssh/windows collectors.
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// SSH identity (private key) file for ssh/windows collectors.
        #[arg(long)]
        identity_file: Option<PathBuf>,
        /// Output format for the resulting inventory.
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// List discovered assets.
    Assets {
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// Show one asset with its services and interfaces (by ID or IP).
    Asset {
        /// Asset ID or IP address.
        asset: String,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// Annotate an asset with environment, owner, criticality, and tags.
    Annotate {
        /// Asset ID or IP address.
        asset: String,
        #[arg(long)]
        environment: Option<String>,
        #[arg(long)]
        owner: Option<String>,
        /// low | medium | high | critical.
        #[arg(long)]
        criticality: Option<String>,
        /// Add a tag (repeatable).
        #[arg(long, action = ArgAction::Append)]
        add_tag: Vec<String>,
        /// Remove a tag (repeatable).
        #[arg(long = "remove-tag", action = ArgAction::Append)]
        remove_tag: Vec<String>,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// List services observed on an asset (by ID or IP).
    Services {
        /// Asset ID or IP address.
        asset: String,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// List interfaces observed on an asset (by ID or IP).
    Interfaces {
        /// Asset ID or IP address.
        asset: String,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// Show CPU/RAM capacity recorded for an asset (by ID or IP).
    Capacity {
        /// Asset ID or IP address.
        asset: String,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// List filesystems observed on an asset (by ID or IP).
    Disks {
        /// Asset ID or IP address.
        asset: String,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// List running host services observed on an asset (by ID or IP).
    HostServices {
        /// Asset ID or IP address.
        asset: String,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// List active connections observed on an asset (by ID or IP).
    Connections {
        /// Asset ID or IP address.
        asset: String,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// Curate dependency edges (add / confirm / remove / DNS evidence).
    Deps {
        #[command(subcommand)]
        action: DepsAction,
    },

    /// List discovery job history.
    Jobs {
        /// Maximum number of jobs to return.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// Export the inventory to JSON (full) or CSV (assets/interfaces/services).
    Export {
        #[arg(short, long, value_enum, default_value_t = Format::Json)]
        format: Format,
        /// Write to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Import inventory from a JSON or CSV file (or stdin).
    Import {
        #[arg(short, long, value_enum, default_value_t = ImportFormat::Json)]
        format: ImportFormat,
        /// Input file; defaults to stdin when omitted.
        #[arg(short = 'i', long)]
        file: Option<PathBuf>,
    },

    /// Show the dependency graph as an edge list.
    Graph {
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
        /// Render the graph as a Mermaid flowchart instead of a table.
        #[arg(long, conflicts_with = "format")]
        mermaid: bool,
        /// Restrict the view to edges touching this asset (by ID or IP).
        #[arg(long)]
        asset: Option<String>,
    },

    /// Run a migration assessment over discovered assets.
    Assess {
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
        /// List the rule catalog (id + description) instead of assessing.
        #[arg(long, conflicts_with = "format")]
        rules: bool,
    },
}

/// Sub-actions of `orbyn deps`.
#[derive(Debug, Subcommand)]
enum DepsAction {
    /// Add a manual (confirmed) dependency edge between two assets.
    Add {
        /// Source asset ID or IP (the dependent side).
        source: String,
        /// Target asset ID or IP (the depended-on side).
        target: String,
        /// Protocol label, e.g. tcp.
        #[arg(long, default_value = "tcp")]
        proto: String,
        /// Remote port.
        #[arg(long)]
        port: u16,
    },
    /// Confirm observed dependency edges between two assets.
    Confirm {
        source: String,
        target: String,
        /// Narrow to one protocol; omit for all.
        #[arg(long)]
        proto: Option<String>,
        /// Narrow to one port; omit for all.
        #[arg(long)]
        port: Option<u16>,
    },
    /// Delete dependency edges between two assets.
    Remove {
        source: String,
        target: String,
        /// Narrow to one protocol; omit for all.
        #[arg(long)]
        proto: Option<String>,
        /// Narrow to one port; omit for all.
        #[arg(long)]
        port: Option<u16>,
    },
    /// Derive relationship edges from DNS: forward-resolve asset hostnames
    /// and link assets when a hostname points at another asset's IP.
    Dns,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let cli = Cli::parse();
    init_logging(cli.verbose);
    let config = Config::resolve(cli.db.clone());

    match cli.command {
        Command::Discover {
            target,
            format,
            collector,
            community,
            snmp_version,
            snmp_port,
            user,
            port,
            identity_file,
        } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let scan_target = validate_target(&target).map_err(|e| anyhow!(e.to_string()))?;
            let version: SnmpVersion = snmp_version.parse().map_err(anyhow::Error::msg)?;
            let profile = CredentialProfile::new(user.unwrap_or_default(), port, identity_file);

            let collector: Box<dyn Collector> = match collector {
                DiscoveryCollector::Nmap => Box::new(NmapCollector::new()),
                DiscoveryCollector::Snmp => Box::new(SnmpCollector::new(
                    community.as_deref().unwrap_or_default(),
                    version,
                    snmp_port,
                )),
                DiscoveryCollector::Ssh => Box::new(LinuxCollector::new(profile)),
                DiscoveryCollector::Windows => Box::new(WindowsCollector::new(profile)),
            };

            discover(&store, &scan_target, collector.as_ref()).await?;
            let assets = store.list_assets().await?;
            print!("{}", orbyn::output::assets(&assets, format));
        }
        Command::Assets { format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let assets = store.list_assets().await?;
            print!("{}", orbyn::output::assets(&assets, format));
        }
        Command::Asset { asset, format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let asset = resolve_asset(&store, &asset).await?;
            let rendered = render_asset_detail(&store, &asset, format).await?;
            print!("{rendered}");
        }
        Command::Annotate {
            asset,
            environment,
            owner,
            criticality,
            add_tag,
            remove_tag,
            format,
        } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let asset = resolve_asset(&store, &asset).await?;
            let criticality = criticality
                .map(|c| c.parse::<Criticality>())
                .transpose()
                .map_err(anyhow::Error::msg)?;
            store
                .annotate_asset(
                    &asset.id,
                    AssetAnnotations {
                        environment,
                        owner,
                        criticality,
                        add_tags: add_tag,
                        remove_tags: remove_tag,
                    },
                )
                .await?;
            let updated = store.get_asset(&asset.id).await?.expect("asset exists");
            let rendered = render_asset_detail(&store, &updated, format).await?;
            print!("{rendered}");
        }
        Command::Services { asset, format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let asset = resolve_asset(&store, &asset).await?;
            let services = store.list_services(&asset.id).await?;
            print!("{}", orbyn::output::services(&services, format));
        }
        Command::Interfaces { asset, format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let asset = resolve_asset(&store, &asset).await?;
            let ifaces = store.list_interfaces(&asset.id).await?;
            print!("{}", orbyn::output::interfaces(&ifaces, format));
        }
        Command::Capacity { asset, format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let asset = resolve_asset(&store, &asset).await?;
            let capacity = store.get_capacity(&asset.id).await?;
            print!("{}", orbyn::output::capacity(capacity.as_ref(), format));
        }
        Command::Disks { asset, format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let asset = resolve_asset(&store, &asset).await?;
            let filesystems = store.list_filesystems(&asset.id).await?;
            print!("{}", orbyn::output::filesystems(&filesystems, format));
        }
        Command::HostServices { asset, format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let asset = resolve_asset(&store, &asset).await?;
            let running = store.list_running_services(&asset.id).await?;
            print!("{}", orbyn::output::running_services(&running, format));
        }
        Command::Jobs { limit, format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let jobs = store.list_jobs(Some(limit)).await?;
            print!("{}", orbyn::output::jobs(&jobs, format));
        }
        Command::Export { format, output } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let assets = store.list_assets().await?;
            let mut services = Vec::new();
            let mut interfaces = Vec::new();
            for asset in &assets {
                services.extend(store.list_services(&asset.id).await?);
                interfaces.extend(store.list_interfaces(&asset.id).await?);
            }
            let rendered = orbyn::output::inventory(
                &Inventory {
                    assets,
                    services,
                    interfaces,
                },
                format,
            );
            match output {
                Some(path) => std::fs::write(&path, rendered)
                    .with_context(|| format!("writing export to {}", path.display()))?,
                None => print!("{rendered}"),
            }
        }
        Command::Import { format, file } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let input = read_input(file.as_ref())?;
            let count = import_inventory(&store, &input, format).await?;
            eprintln!("Imported {count} assets.");
            let jobs = store.list_jobs(Some(1)).await?;
            print!("{}", orbyn::output::jobs(&jobs, Format::Table));
        }
        Command::Graph {
            format,
            mermaid,
            asset,
        } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let mut edges = store.list_dependencies().await?;
            let assets = store.list_assets().await?;
            if let Some(key) = asset {
                let asset = resolve_asset(&store, &key).await?;
                edges.retain(|d| d.source_asset_id == asset.id || d.target_asset_id == asset.id);
            }
            if mermaid {
                print!("{}", orbyn::output::mermaid(&edges, &assets));
            } else {
                print!("{}", orbyn::output::dependencies(&edges, &assets, format));
            }
        }
        Command::Connections { asset, format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let asset = resolve_asset(&store, &asset).await?;
            let conns = store.list_connections(&asset.id).await?;
            print!("{}", orbyn::output::connections(&conns, format));
        }
        Command::Deps { action } => {
            let store = SqliteStore::open(&config.db_path).await?;
            deps(&store, action).await?;
        }
        Command::Assess { format, rules } => {
            let store = SqliteStore::open(&config.db_path).await?;
            if rules {
                print!(
                    "{}",
                    orbyn::output::rules_catalog(
                        orbyn::assessment::rules::catalog(),
                        orbyn::assessment::RULES_VERSION
                    )
                );
            } else {
                let input = assessment_input(&store).await?;
                let report = run_assessment(&input);
                print!("{}", orbyn::output::report(&report, format));
            }
        }
    }

    Ok(())
}

/// Run one discovery job with the selected collector, persisting observations
/// and job history.
async fn discover(
    store: &SqliteStore,
    scan_target: &ScanTarget,
    collector: &dyn Collector,
) -> Result<()> {
    let target = match scan_target {
        ScanTarget::Ip(ip) => ip.to_string(),
        ScanTarget::Cidr(cidr) => cidr.clone(),
    };

    let job = DiscoveryJob {
        id: uuid::Uuid::new_v4().to_string(),
        collector: collector.name().into(),
        targets: vec![target.clone()],
        status: JobStatus::Running,
        started_at: Utc::now(),
        finished_at: None,
        error: None,
        assets_found: None,
        services_found: None,
    };
    store.create_job(job.clone()).await?;

    tracing::info!(job = %job.id, collector = job.collector, target = %target, "starting discovery");

    match collector.scan(scan_target).await {
        Ok(observations) => {
            let assets = observations
                .iter()
                .filter(|o| matches!(o, Observation::Asset(_)))
                .count();
            let services = observations
                .iter()
                .filter(|o| matches!(o, Observation::Service(_)))
                .count();
            let filesystems = observations
                .iter()
                .filter(|o| matches!(o, Observation::Filesystem(_)))
                .count();
            let running = observations
                .iter()
                .filter(|o| matches!(o, Observation::RunningService(_)))
                .count();
            let connections = observations
                .iter()
                .filter(|o| matches!(o, Observation::Connection(_)))
                .count();
            store.store_observations(observations).await?;
            store
                .finish_job(
                    &job.id,
                    JobStatus::Succeeded,
                    None,
                    Some(JobOutcome {
                        assets_found: assets as u32,
                        services_found: services as u32,
                    }),
                )
                .await?;
            tracing::info!(job = %job.id, assets, services, "discovery complete");
            eprintln!(
                "Discovery job {} complete: {} assets, {} services, {} filesystems, {} running services, {} connections.",
                job.id, assets, services, filesystems, running, connections
            );
            Ok(())
        }
        Err(e) => {
            store
                .finish_job(&job.id, JobStatus::Failed, Some(e.to_string()), None)
                .await?;
            Err(anyhow!("discovery job {} failed: {e:#}", job.id))
        }
    }
}

/// Gather the full inventory snapshot the assessment engine evaluates.
async fn assessment_input(store: &SqliteStore) -> Result<AssessmentInput> {
    let assets = store.list_assets().await?;
    let mut services = Vec::new();
    let mut filesystems = Vec::new();
    let mut capacities = Vec::new();
    let mut connections = Vec::new();
    for asset in &assets {
        services.extend(store.list_services(&asset.id).await?);
        filesystems.extend(store.list_filesystems(&asset.id).await?);
        if let Some(capacity) = store.get_capacity(&asset.id).await? {
            capacities.push(capacity);
        }
        connections.extend(store.list_connections(&asset.id).await?);
    }
    let dependencies = store.list_dependencies().await?;
    Ok(AssessmentInput {
        assets,
        services,
        filesystems,
        capacities,
        dependencies,
        connections,
    })
}

/// Resolve an asset reference that may be an id, an IP address, or a
/// hostname (exact, case-insensitive).
async fn resolve_asset(store: &SqliteStore, key: &str) -> Result<Asset> {
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
async fn render_asset_detail(store: &SqliteStore, asset: &Asset, format: Format) -> Result<String> {
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

/// Resolve both endpoints of a dependency pair, rejecting self-edges.
async fn resolve_dep_pair(
    store: &SqliteStore,
    source: &str,
    target: &str,
) -> Result<(Asset, Asset)> {
    let source = resolve_asset(store, source).await?;
    let target = resolve_asset(store, target).await?;
    if source.id == target.id {
        anyhow::bail!(
            "source and target resolve to the same asset ({})",
            source.id
        );
    }
    Ok((source, target))
}

/// Handle `orbyn deps <action>`.
async fn deps(store: &SqliteStore, action: DepsAction) -> Result<()> {
    match action {
        DepsAction::Add {
            source,
            target,
            proto,
            port,
        } => {
            let (source, target) = resolve_dep_pair(store, &source, &target).await?;
            let via = format!("{proto}/{port}");
            store
                .store_observation(Observation::Dependency(Dependency {
                    source_asset_id: source.id.clone(),
                    target_asset_id: target.id.clone(),
                    proto,
                    port,
                    evidence_source: "manual".into(),
                    confidence: 1.0,
                    confirmed: true,
                }))
                .await?;
            // If the edge already existed as observed evidence, mark it confirmed.
            store
                .confirm_dependency(&source.id, &target.id, None, None)
                .await?;
            eprintln!(
                "Dependency added: {} -> {} ({}).",
                source
                    .hostname
                    .clone()
                    .unwrap_or_else(|| source.ip.to_string()),
                target
                    .hostname
                    .clone()
                    .unwrap_or_else(|| target.ip.to_string()),
                via
            );
        }
        DepsAction::Confirm {
            source,
            target,
            proto,
            port,
        } => {
            let (source, target) = resolve_dep_pair(store, &source, &target).await?;
            let confirmed = store
                .confirm_dependency(&source.id, &target.id, proto.as_deref(), port)
                .await?;
            if confirmed == 0 {
                anyhow::bail!(
                    "no observed dependency between {} and {} to confirm; \
                     use `orbyn deps add` to create one",
                    source.id,
                    target.id
                );
            }
            eprintln!("Confirmed {confirmed} edge(s).");
        }
        DepsAction::Remove {
            source,
            target,
            proto,
            port,
        } => {
            let (source, target) = resolve_dep_pair(store, &source, &target).await?;
            let removed = store
                .remove_dependency(&source.id, &target.id, proto.as_deref(), port)
                .await?;
            eprintln!("Removed {removed} edge(s).");
        }
        DepsAction::Dns => {
            let assets = store.list_assets().await?;
            let mut resolutions = Vec::new();
            let mut failed = 0usize;
            for asset in &assets {
                let Some(hostname) = &asset.hostname else {
                    continue;
                };
                match orbyn::collectors::dns::resolve_host(hostname).await {
                    Ok(ips) => resolutions.push((hostname.clone(), ips)),
                    Err(e) => {
                        failed += 1;
                        tracing::warn!(hostname = %hostname, error = %e, "DNS resolution failed");
                    }
                }
            }
            let edges = orbyn::collectors::dns::dns_edges(&assets, &resolutions);
            let count = edges.len();
            for edge in edges {
                store
                    .store_observation(Observation::Dependency(edge))
                    .await?;
            }
            if failed > 0 {
                eprintln!("{failed} hostname(s) could not be resolved; skipped.");
            }
            eprintln!("DNS evidence produced {count} relationship edge(s).");
        }
    }
    Ok(())
}

/// An asset row accepted by `orbyn import`.
#[derive(Debug, serde::Deserialize)]
struct ImportedAsset {
    ip: String,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    device_class: Option<String>,
    #[serde(default)]
    os_name: Option<String>,
    #[serde(default)]
    os_version: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    criticality: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

/// Persist an imported inventory, recording an audit job for the operation.
async fn import_inventory(store: &SqliteStore, input: &str, format: ImportFormat) -> Result<usize> {
    let rows: Vec<ImportedAsset> = match format {
        ImportFormat::Json => {
            let raw: Vec<ImportedAsset> = if input.trim_start().starts_with('[') {
                serde_json::from_str(input)
            } else {
                let wrapper: serde_json::Value = serde_json::from_str(input)?;
                serde_json::from_value(wrapper.get("assets").cloned().unwrap_or_default())
            }
            .with_context(|| {
                "invalid JSON import; expected an array or {\"assets\": [...]} of {ip, hostname, ...} objects"
            })?;
            raw
        }
        ImportFormat::Csv => parse_import_csv(input)?,
    };

    if rows.is_empty() {
        return Ok(0);
    }

    let job = DiscoveryJob {
        id: uuid::Uuid::new_v4().to_string(),
        collector: "import".into(),
        targets: rows.iter().map(|r| r.ip.clone()).collect(),
        status: JobStatus::Running,
        started_at: Utc::now(),
        finished_at: None,
        error: None,
        assets_found: None,
        services_found: None,
    };
    store.create_job(job.clone()).await?;

    let mut persisted = 0u32;
    for row in &rows {
        let ip: std::net::IpAddr = row
            .ip
            .parse()
            .with_context(|| format!("invalid IP '{}' in import", row.ip))?;
        let id = ip.to_string().replace(['.', ':'], "-");
        let criticality = row
            .criticality
            .as_deref()
            .map(str::parse::<Criticality>)
            .transpose()
            .map_err(anyhow::Error::msg)?;

        let now = Utc::now();
        store
            .store_observation(Observation::Asset(Asset {
                id: id.clone(),
                ip,
                hostname: row.hostname.clone(),
                device_class: row.device_class.clone(),
                os_name: row.os_name.clone(),
                os_version: row.os_version.clone(),
                environment: None,
                owner: None,
                criticality: None,
                tags: Vec::new(),
                first_seen: now,
                last_seen: now,
            }))
            .await?;
        let annotations = AssetAnnotations {
            environment: row.environment.clone(),
            owner: row.owner.clone(),
            criticality,
            add_tags: row.tags.clone(),
            remove_tags: Vec::new(),
        };
        store.annotate_asset(&id, annotations).await?;
        persisted += 1;
    }

    store
        .finish_job(
            &job.id,
            JobStatus::Succeeded,
            None,
            Some(JobOutcome {
                assets_found: persisted,
                services_found: 0,
            }),
        )
        .await?;

    Ok(persisted as usize)
}

/// Parse the assets worksheet of an Orbyn CSV export.
fn parse_import_csv(input: &str) -> Result<Vec<ImportedAsset>> {
    let mut rows = Vec::new();
    let mut section = String::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('#') {
            section = name.trim().to_lowercase();
            continue;
        }
        if section != "assets" {
            continue;
        }
        if line.starts_with("id,ip") {
            continue; // column header
        }
        let fields = split_csv_line(line);
        // Accept both the 12-column export and a compact 7-column import form.
        let (
            ip,
            hostname,
            device_class,
            os_name,
            os_version,
            environment,
            owner,
            criticality,
            tags,
        ) = match fields.len() {
            12 => {
                let mut it = fields.into_iter();
                let _id = it.next().unwrap();
                let ip = it.next().unwrap();
                let hostname = it.next().unwrap();
                let device_class = it.next().unwrap();
                let os_name = it.next().unwrap();
                let os_version = it.next().unwrap();
                let environment = it.next().unwrap();
                let owner = it.next().unwrap();
                let criticality = it.next().unwrap();
                let tags = it.next().unwrap();
                let _first_seen = it.next().unwrap();
                let _last_seen = it.next().unwrap();
                (
                    ip,
                    opt(hostname),
                    opt(device_class),
                    opt(os_name),
                    opt(os_version),
                    opt(environment),
                    opt(owner),
                    opt(criticality),
                    tags,
                )
            }
            7 => {
                let mut it = fields.into_iter();
                let ip = it.next().unwrap();
                let hostname = it.next().unwrap();
                let device_class = it.next().unwrap();
                let environment = it.next().unwrap();
                let owner = it.next().unwrap();
                let criticality = it.next().unwrap();
                let tags = it.next().unwrap();
                (
                    ip,
                    opt(hostname),
                    opt(device_class),
                    None,
                    None,
                    opt(environment),
                    opt(owner),
                    opt(criticality),
                    tags,
                )
            }
            other => bail!("unexpected CSV column count {other} in import line"),
        };
        let tags = tags
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect();
        rows.push(ImportedAsset {
            ip,
            hostname,
            device_class,
            os_name,
            os_version,
            environment,
            owner,
            criticality,
            tags,
        });
    }
    Ok(rows)
}

fn opt(value: String) -> Option<String> {
    if value.is_empty() || value == "-" {
        None
    } else {
        Some(value)
    }
}

fn read_input(file: Option<&PathBuf>) -> Result<String> {
    match file {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading import file {}", path.display())),
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading import from stdin")?;
            Ok(buf)
        }
    }
}

fn init_logging(verbose: u8) {
    let default_filter = match verbose {
        0 => "orbyn=warn",
        1 => "orbyn=info",
        _ => "orbyn=debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| default_filter.into()),
        )
        .with_writer(std::io::stderr)
        .init();
}
