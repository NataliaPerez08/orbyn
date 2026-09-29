use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};

use orbyn::assessment::{run_assessment, AssessmentInput};
use orbyn::collectors::credentials::CredentialProfile;
use orbyn::collectors::nmap::NmapCollector;
use orbyn::collectors::snmp::{SnmpCollector, SnmpVersion};
use orbyn::collectors::ssh::LinuxCollector;
use orbyn::collectors::windows::WindowsCollector;
use orbyn::collectors::{validate_target, Collector, ScanTarget};
use orbyn::config::Config;
use orbyn::domain::{
    asset_id, Asset, AuditEvent, Criticality, Dependency, DiscoveryJob, EvidenceKind, Interface,
    JobOutcome, JobStatus, Observation, Service,
};
use orbyn::import::{parse_import_csv, resolve_asset_id, ImportedInventory, ImportedStats};
use orbyn::integrations::ansible::{render_ansible_inventory, render_ansible_yaml, GroupBy};
use orbyn::integrations::netbox::NetBoxClient;
use orbyn::integrations::terraform::{render_import_blocks, render_terraform};
use orbyn::output::{Format, Inventory};
use orbyn::store::sqlite::SqliteStore;
use orbyn::store::traits::{AnnotationField, AssetAnnotations};
use orbyn::store::Store;

#[derive(Debug, Parser)]
#[command(
    name = "orbyn",
    about = "CLI for infrastructure discovery, dependency mapping, and migration assessment.",
    version = env!("CARGO_PKG_VERSION")
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

/// Export target: Orbyn's own formats, or automation-oriented formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ExportFormat {
    Json,
    Csv,
    /// Ansible INI inventory.
    Ansible,
    /// Ansible YAML inventory.
    AnsibleYaml,
    Terraform,
}

/// An annotation field clearable via `orbyn annotate --unset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum UnsetField {
    Environment,
    Owner,
    Criticality,
}

impl From<UnsetField> for AnnotationField {
    fn from(field: UnsetField) -> Self {
        match field {
            UnsetField::Environment => AnnotationField::Environment,
            UnsetField::Owner => AnnotationField::Owner,
            UnsetField::Criticality => AnnotationField::Criticality,
        }
    }
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
        /// Clear a field (repeatable): environment | owner | criticality.
        #[arg(long, value_enum, action = ArgAction::Append)]
        unset: Vec<UnsetField>,
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

    /// Show a resource utilization window (avg/p95/p99/peak + confidence) for
    /// an asset (by ID or IP).
    Metrics {
        /// Asset ID or IP address.
        asset: String,
        /// Only use the most recent N samples.
        #[arg(long)]
        samples: Option<usize>,
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

    /// List mutating CLI operations recorded in the audit trail.
    Audit {
        /// Maximum number of events to return.
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// Export the inventory to JSON/CSV (Orbyn), Ansible (INI or YAML), or
    /// Terraform formats.
    Export {
        #[arg(short, long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
        /// Grouping key for the Ansible inventory.
        #[arg(long, value_enum, default_value_t = GroupBy::DeviceClass)]
        group_by: GroupBy,
        /// Generate Terraform `import` blocks for this resource type
        /// (requires --format terraform), e.g. aws_instance.
        #[arg(long, value_name = "RESOURCE_TYPE")]
        tf_import: Option<String>,
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

    /// Pull devices, VMs, interfaces and assigned IPs from NetBox
    /// (source of truth).
    Netbox {
        #[command(subcommand)]
        action: NetboxAction,
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

    /// Generate a shell completion script (bash, zsh, or fish).
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: Shell,
    },
}

/// Shell backends supported by `orbyn completions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Shell {
    Bash,
    Zsh,
    Fish,
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

/// Sub-actions of `orbyn netbox`.
#[derive(Debug, Subcommand)]
enum NetboxAction {
    /// Import devices, VMs, their interfaces and assigned IPs from NetBox.
    Import {
        /// NetBox base URL, e.g. https://netbox.example.com.
        #[arg(long)]
        url: String,
        /// NetBox API token (falls back to ORBYN_NETBOX_TOKEN).
        #[arg(long, env = "ORBYN_NETBOX_TOKEN")]
        token: Option<String>,
        /// Skip TLS certificate verification (for self-signed NetBox).
        #[arg(long)]
        no_verify: bool,
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
        Command::Completions { shell } => {
            let shell = match shell {
                Shell::Bash => clap_complete::Shell::Bash,
                Shell::Zsh => clap_complete::Shell::Zsh,
                Shell::Fish => clap_complete::Shell::Fish,
            };
            let mut cmd = Cli::command();
            let mut buf = Vec::new();
            clap_complete::generate(shell, &mut cmd, "orbyn", &mut buf);
            // Broken pipe (e.g. `orbyn completions zsh | head`) must not panic.
            std::io::stdout().write_all(&buf).or_else(|e| {
                if e.kind() == std::io::ErrorKind::BrokenPipe {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
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
            unset,
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
            let audit =
                begin_audit(&store, "annotate", &asset.id, Some("asset annotation")).await?;
            let result = store
                .annotate_asset(
                    &asset.id,
                    AssetAnnotations {
                        environment,
                        owner,
                        criticality,
                        unset: unset.into_iter().map(AnnotationField::from).collect(),
                        add_tags: add_tag,
                        remove_tags: remove_tag,
                    },
                )
                .await;
            finish_audit_result(&store, audit, result).await?;
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
        Command::Audit { limit, format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let events = store.list_audit_events(Some(limit)).await?;
            print!("{}", orbyn::output::audit_events(&events, format));
        }
        Command::Export {
            format,
            group_by,
            tf_import,
            output,
        } => {
            if tf_import.is_some() && format != ExportFormat::Terraform {
                bail!("--tf-import requires --format terraform");
            }
            let store = SqliteStore::open(&config.db_path).await?;
            let assets = store.list_assets().await?;

            let rendered = match format {
                ExportFormat::Ansible => render_ansible_inventory(&assets, group_by),
                ExportFormat::AnsibleYaml => render_ansible_yaml(&assets, group_by),
                ExportFormat::Terraform => {
                    let mut out = render_terraform(&assets);
                    if let Some(resource_type) = tf_import {
                        out.push_str(&render_import_blocks(&assets, &resource_type)?);
                    }
                    out
                }
                ExportFormat::Json | ExportFormat::Csv => {
                    let mut services = Vec::new();
                    let mut interfaces = Vec::new();
                    for asset in &assets {
                        services.extend(store.list_services(&asset.id).await?);
                        interfaces.extend(store.list_interfaces(&asset.id).await?);
                    }
                    let format = match format {
                        ExportFormat::Json => Format::Json,
                        ExportFormat::Csv => Format::Csv,
                        _ => unreachable!(),
                    };
                    orbyn::output::inventory(
                        &Inventory {
                            assets,
                            services,
                            interfaces,
                        },
                        format,
                    )
                }
            };
            match output {
                Some(path) => std::fs::write(&path, rendered)
                    .with_context(|| format!("writing export to {}", path.display()))?,
                None => print!("{rendered}"),
            }
        }
        Command::Import { format, file } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let input = read_input(file.as_ref())?;
            let stats = import_inventory(&store, &input, format).await?;
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
        }
        Command::Netbox {
            action:
                NetboxAction::Import {
                    url,
                    token,
                    no_verify,
                },
        } => {
            if no_verify {
                tracing::warn!("--no-verify disables TLS certificate verification for NetBox");
                eprintln!(
                    "WARNING: --no-verify disables TLS certificate verification.\n\
                     Only use this against a trusted self-signed NetBox instance; \
                     connections can be silently intercepted."
                );
            }
            let store = SqliteStore::open(&config.db_path).await?;
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
            let stats = persist_imported_inventory(&store, &inventory, "netbox")
                .await
                .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
            let mut parts = vec![format!("{} assets", stats.assets)];
            if stats.interfaces > 0 {
                parts.push(format!("{} interfaces", stats.interfaces));
            }
            eprintln!("Imported {} from NetBox.", parts.join(", "));
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
        Command::Metrics {
            asset,
            samples,
            format,
        } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let asset = resolve_asset(&store, &asset).await?;
            let collected = store.list_metric_samples(&asset.id, samples).await?;
            let stats = orbyn::metrics::summarize(&collected);
            print!("{}", orbyn::output::metrics(stats.as_ref(), format));
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
        filesystems_found: None,
        running_services_found: None,
        connections_found: None,
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
                        filesystems_found: filesystems as u32,
                        running_services_found: running as u32,
                        connections_found: connections as u32,
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
            let redactor = orbyn::redact::Redactor::from_env();
            let redacted = redactor.redact(&format!("{e:#}"));
            store
                .finish_job(&job.id, JobStatus::Failed, Some(redacted.clone()), None)
                .await?;
            Err(anyhow!("discovery job {} failed: {redacted}", job.id))
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

async fn begin_audit(
    store: &SqliteStore,
    action: &str,
    target: &str,
    details: Option<&str>,
) -> Result<AuditEvent> {
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        action: action.into(),
        target: target.into(),
        status: JobStatus::Running,
        started_at: Utc::now(),
        finished_at: None,
        details: details.map(str::to_string),
        error: None,
    };
    store.create_audit_event(event.clone()).await?;
    Ok(event)
}

async fn finish_audit_result<T>(
    store: &SqliteStore,
    event: AuditEvent,
    result: Result<T>,
) -> Result<T> {
    match result {
        Ok(value) => {
            store
                .finish_audit_event(&event.id, JobStatus::Succeeded, None)
                .await?;
            Ok(value)
        }
        Err(error) => {
            let message = error.to_string();
            if let Err(audit_error) = store
                .finish_audit_event(&event.id, JobStatus::Failed, Some(message))
                .await
            {
                tracing::error!(error = %audit_error, "could not finish failed audit event");
            }
            Err(error)
        }
    }
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
            let audit = begin_audit(
                store,
                "deps.add",
                &format!("{source} -> {target}"),
                Some(&format!("{proto}/{port}")),
            )
            .await?;
            let result: Result<()> = async {
                let (source, target) = resolve_dep_pair(store, &source, &target).await?;
                let via = format!("{proto}/{port}");
                store
                    .store_observation(Observation::Dependency(Dependency {
                        source_asset_id: source.id.clone(),
                        target_asset_id: target.id.clone(),
                        proto,
                        port,
                        evidence_source: EvidenceKind::Manual.as_str().into(),
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
                Ok(())
            }
            .await;
            finish_audit_result(store, audit, result).await?;
        }
        DepsAction::Confirm {
            source,
            target,
            proto,
            port,
        } => {
            let audit = begin_audit(
                store,
                "deps.confirm",
                &format!("{source} -> {target}"),
                Some("dependency confirmation"),
            )
            .await?;
            let result: Result<()> = async {
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
                Ok(())
            }
            .await;
            finish_audit_result(store, audit, result).await?;
        }
        DepsAction::Remove {
            source,
            target,
            proto,
            port,
        } => {
            let audit = begin_audit(
                store,
                "deps.remove",
                &format!("{source} -> {target}"),
                Some("dependency removal"),
            )
            .await?;
            let result: Result<()> = async {
                let (source, target) = resolve_dep_pair(store, &source, &target).await?;
                let removed = store
                    .remove_dependency(&source.id, &target.id, proto.as_deref(), port)
                    .await?;
                eprintln!("Removed {removed} edge(s).");
                Ok(())
            }
            .await;
            finish_audit_result(store, audit, result).await?;
        }
        DepsAction::Dns => {
            let audit = begin_audit(store, "deps.dns", "inventory", Some("DNS evidence")).await?;
            let result: Result<()> = async {
                let assets = store.list_assets().await?;
                let mut resolutions = Vec::new();
                let mut reverse = Vec::new();
                let mut failed = 0usize;
                for asset in &assets {
                    let Some(hostname) = &asset.hostname else {
                        continue;
                    };
                    match orbyn::collectors::dns::resolve_host(hostname).await {
                        Ok(resolution) => resolutions.push((hostname.clone(), resolution)),
                        Err(e) => {
                            failed += 1;
                            tracing::warn!(hostname = %hostname, error = %e, "DNS resolution failed");
                        }
                    }
                }
                for asset in &assets {
                    match orbyn::collectors::dns::resolve_ptr(asset.ip).await {
                        Ok(names) if !names.is_empty() => reverse.push((asset.ip, names)),
                        Ok(_) => {}
                        Err(e) => {
                            tracing::debug!(ip = %asset.ip, error = %e, "PTR resolution failed");
                        }
                    }
                }
                let mut edges = orbyn::collectors::dns::dns_edges(&assets, &resolutions);
                edges.extend(orbyn::collectors::dns::dns_edges_ptr(&assets, &reverse));
                // Forward and reverse evidence can name the same pair; keep
                // one edge per (source, target).
                let mut seen = std::collections::HashSet::new();
                edges.retain(|e| seen.insert((e.source_asset_id.clone(), e.target_asset_id.clone())));
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
                Ok(())
            }
            .await;
            finish_audit_result(store, audit, result).await?;
        }
    }
    Ok(())
}

/// Parse an imported inventory, recording an audit job for the operation.
async fn import_inventory(
    store: &SqliteStore,
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
    store: &SqliteStore,
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

    let mut persisted = 0u32;
    for (row, ip, criticality) in assets {
        let id = asset_id(ip);

        let now = Utc::now();
        store
            .store_observation(Observation::Asset(Asset {
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
            }))
            .await?;
        let annotations = AssetAnnotations {
            environment: row.environment.clone(),
            owner: row.owner.clone(),
            criticality,
            unset: Vec::new(),
            add_tags: row.tags.clone(),
            remove_tags: Vec::new(),
        };
        store.annotate_asset(&id, annotations).await?;
        persisted += 1;
    }

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
    let filter = std::env::var("ORBYN_LOG")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| default_filter.to_string());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completions_render_for_every_shell() {
        for shell in [Shell::Bash, Shell::Zsh, Shell::Fish] {
            let clap_shell = match shell {
                Shell::Bash => clap_complete::Shell::Bash,
                Shell::Zsh => clap_complete::Shell::Zsh,
                Shell::Fish => clap_complete::Shell::Fish,
            };
            let mut cmd = Cli::command();
            let mut buf = Vec::new();
            clap_complete::generate(clap_shell, &mut cmd, "orbyn", &mut buf);
            let script = String::from_utf8(buf).expect("utf-8 completion script");
            assert!(
                script.contains("discover") && script.contains("assess"),
                "shell {shell:?} script covers subcommands: {script}"
            );
        }
    }

    #[test]
    fn cli_surface_contains_the_stable_commands() {
        let command = Cli::command();
        let names: Vec<&str> = command
            .get_subcommands()
            .map(|sub| sub.get_name())
            .collect();
        let expected = [
            "discover",
            "assets",
            "asset",
            "annotate",
            "services",
            "interfaces",
            "capacity",
            "disks",
            "host-services",
            "connections",
            "metrics",
            "deps",
            "jobs",
            "audit",
            "export",
            "import",
            "netbox",
            "graph",
            "assess",
            "completions",
        ];
        for name in expected {
            assert!(names.contains(&name), "missing stable command: {name}");
        }
    }
}
