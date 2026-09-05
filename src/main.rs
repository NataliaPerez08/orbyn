use std::io::Read;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use clap::{ArgAction, Parser, Subcommand, ValueEnum};

use orbyn::assessment::{assess, AssessmentReport, Finding, Severity};
use orbyn::collectors::nmap::NmapCollector;
use orbyn::collectors::snmp::{SnmpCollector, SnmpVersion};
use orbyn::collectors::{validate_target, Collector, ScanTarget};
use orbyn::config::Config;
use orbyn::domain::{Asset, Criticality, DiscoveryJob, JobOutcome, JobStatus, Observation};
use orbyn::output::{Format, Inventory};
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ImportFormat {
    Json,
    Csv,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover assets in a CIDR range (Nmap) or walk a single host (SNMP).
    Discover {
        /// Target IP or CIDR range, e.g. 10.0.0.0/24.
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
    },

    /// Run a migration assessment over discovered assets.
    Assess {
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },
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
        } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let scan_target = validate_target(&target).map_err(|e| anyhow!(e.to_string()))?;
            let version: SnmpVersion = snmp_version.parse().map_err(anyhow::Error::msg)?;

            let collector: Box<dyn Collector> = match collector {
                DiscoveryCollector::Nmap => Box::new(NmapCollector::new()),
                DiscoveryCollector::Snmp => Box::new(SnmpCollector::new(
                    community.as_deref().unwrap_or_default(),
                    version,
                    snmp_port,
                )),
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
            let services = store.list_services(&asset.id).await?;
            let ifaces = store.list_interfaces(&asset.id).await?;
            print!(
                "{}",
                orbyn::output::asset_detail(&asset, &services, &ifaces, format)
            );
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
            let services = store.list_services(&updated.id).await?;
            let ifaces = store.list_interfaces(&updated.id).await?;
            print!(
                "{}",
                orbyn::output::asset_detail(&updated, &services, &ifaces, format)
            );
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
        Command::Graph { format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let edges = store.list_dependencies().await?;
            print!("{}", orbyn::output::dependencies(&edges, format));
        }
        Command::Assess { format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let assets = store.list_assets().await?;

            let findings: Vec<Finding> = assets
                .iter()
                .filter(|a| a.os_name.is_none())
                .map(|a| Finding {
                    rule_id: "os.missing".into(),
                    severity: Severity::Info,
                    message: "no operating system details discovered for this asset".into(),
                    evidence: vec![format!("asset {} scanned by Nmap", a.ip)],
                    asset_id: Some(a.id.clone()),
                })
                .collect();

            let report = AssessmentReport {
                assets_assessed: assets.len(),
                overall_score: assess(&findings),
                findings,
            };
            print!("{}", orbyn::output::report(&report, format));
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
                "Discovery job {} complete: {} assets, {} services.",
                job.id, assets, services
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

/// Resolve an asset reference that may be an id or an IP address.
async fn resolve_asset(store: &SqliteStore, key: &str) -> Result<Asset> {
    match store.get_asset(key).await? {
        Some(asset) => Ok(asset),
        None => store
            .get_asset_by_ip(key)
            .await?
            .ok_or_else(|| anyhow!("no asset matches '{key}'")),
    }
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
        let fields = csv_fields(line);
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

/// Split a CSV line into fields, honoring double-quote escaping.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    fields.push(current);
    fields
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
