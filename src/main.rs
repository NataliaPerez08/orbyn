use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};

use orbyn::assessment::{run_assessment, AssessmentInput, AssetWindow};
use orbyn::collectors::credentials::CredentialProfile;
use orbyn::collectors::nmap::NmapCollector;
use orbyn::collectors::snmp::{SnmpCollector, SnmpVersion};
use orbyn::collectors::ssh::LinuxCollector;
use orbyn::collectors::windows::{WindowsCollector, WindowsTransport};
use orbyn::collectors::winrm::WinRmTransport;
use orbyn::collectors::{validate_target_with_policy, Collector, ScanTarget, ScanTargetError};
use orbyn::config::{Config, DbTarget};
use orbyn::domain::{
    asset_id, Asset, AuditEvent, Criticality, Dependency, DiscoveryJob, EvidenceKind, Interface,
    JobOutcome, JobStatus, MetricSample, Observation, Service,
};
use orbyn::import::{parse_import_csv, resolve_asset_id, ImportedInventory, ImportedStats};
use orbyn::integrations::ansible::{render_ansible_inventory, render_ansible_yaml, GroupBy};
use orbyn::integrations::cloud::aws::{AwsClient, AwsCredentials};
use orbyn::integrations::cloud::proxmox::ProxmoxClient;
use orbyn::integrations::cloud::{CloudCounts, CloudInventory};
use orbyn::integrations::netbox::NetBoxClient;
use orbyn::integrations::prometheus::{
    assemble_samples, ImportOptions, PrometheusClient, DEFAULT_CPU_QUERY, DEFAULT_RAM_QUERY,
    DEFAULT_SWAP_QUERY,
};
use orbyn::integrations::terraform::{render_import_blocks, render_terraform};
use orbyn::integrations::zabbix::{
    assemble_samples as zabbix_assemble_samples, ImportOptions as ZabbixImportOptions, ZabbixClient,
};
use orbyn::output::{Format, Inventory};
use orbyn::store::postgres::PostgresStore;
use orbyn::store::sqlite::SqliteStore;
use orbyn::store::traits::{AnnotationField, AssetAnnotations};
use orbyn::store::Store;
use tokio::task::JoinHandle;

#[derive(Debug, Parser)]
#[command(
    name = "orbyn",
    about = "CLI for infrastructure discovery, dependency mapping, and migration assessment.",
    version = env!("CARGO_PKG_VERSION")
)]
struct Cli {
    /// Path to the SQLite database, or a postgres:// URL for the
    /// PostgreSQL backend (default: ./data/orbyn.db).
    #[arg(long, global = true, env = "ORBYN_DB")]
    db: Option<String>,

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
    /// Native WS-Man/WinRM transport for Windows hosts.
    Winrm,
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
    /// Discover assets in CIDR ranges or IPs (Nmap) or collect hosts
    /// (SNMP walk, SSH Linux probe, Windows PowerShell probe over SSH,
    /// or Windows PowerShell over native WinRM).
    Discover {
        /// Target IP or CIDR range, e.g. 10.0.0.0/24 (single IP for
        /// snmp/ssh/windows/winrm). Repeatable.
        #[arg(long, action = ArgAction::Append, required = true)]
        target: Vec<String>,
        /// Collector adapter to run.
        #[arg(long, value_enum, default_value_t = DiscoveryCollector::Nmap)]
        collector: DiscoveryCollector,
        /// Maximum targets scanned in parallel.
        #[arg(long, default_value_t = 4)]
        concurrency: usize,
        /// Maximum target launches per second (default: no pacing).
        #[arg(long)]
        rate_limit: Option<u32>,
        /// Accept CIDR scopes wider than the default floor (IPv4 /16,
        /// IPv6 /48), e.g. an authorized whole-private-range scan.
        #[arg(long)]
        allow_large_cidr: bool,
        /// SNMP v1/v2c community string: from ORBYN_SNMP_COMMUNITY, or `-`
        /// to read one line from stdin so it never lands in argv.
        #[arg(long, env = "ORBYN_SNMP_COMMUNITY", hide_env_values = true)]
        community: Option<String>,
        /// SNMP protocol version: 1 or 2c.
        #[arg(long, default_value = "2c")]
        snmp_version: String,
        /// SNMP agent UDP port.
        #[arg(long, default_value_t = 161)]
        snmp_port: u16,
        /// Login user for ssh/windows/winrm collectors (default: current
        /// user; required for winrm).
        #[arg(long)]
        user: Option<String>,
        /// SSH port for ssh/windows collectors.
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// SSH identity (private key) file for ssh/windows collectors.
        #[arg(long)]
        identity_file: Option<PathBuf>,
        /// WinRM password (winrm collector): from ORBYN_WINRM_PASSWORD, or
        /// `-` to read one line from stdin so it never lands in argv.
        #[arg(long, env = "ORBYN_WINRM_PASSWORD", hide_env_values = true)]
        winrm_password: Option<String>,
        /// WinRM HTTPS port (winrm collector).
        #[arg(long, default_value_t = 5986)]
        winrm_port: u16,
        /// Skip TLS certificate verification for the WinRM endpoint
        /// (self-signed lab certificates).
        #[arg(long)]
        winrm_insecure: bool,
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

    /// Show a resource utilization window (span, avg/p95/p99/peak,
    /// confidence, right-sizing readiness) for an asset (by ID or IP).
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

    /// Pull nodes, VMs and containers from a Proxmox VE cluster (read-only).
    Proxmox {
        #[command(subcommand)]
        action: ProxmoxAction,
    },

    /// Pull EC2 instances from AWS (read-only).
    Aws {
        #[command(subcommand)]
        action: AwsAction,
    },

    /// Pull historical CPU/RAM utilization from Prometheus into metric
    /// samples (one week by default).
    Prometheus {
        #[command(subcommand)]
        action: PrometheusAction,
    },

    /// Pull historical CPU/RAM/swap utilization from Zabbix into metric
    /// samples (one week by default).
    Zabbix {
        #[command(subcommand)]
        action: ZabbixAction,
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
        /// NetBox API token: from ORBYN_NETBOX_TOKEN, or `-` to read one
        /// line from stdin so it never lands in argv.
        #[arg(long, env = "ORBYN_NETBOX_TOKEN", hide_env_values = true)]
        token: Option<String>,
        /// Skip TLS certificate verification (for self-signed NetBox).
        #[arg(long)]
        no_verify: bool,
    },
}

/// Sub-actions of `orbyn proxmox`.
#[derive(Debug, Subcommand)]
enum ProxmoxAction {
    /// Import nodes, VMs and containers from a Proxmox VE cluster.
    Import {
        /// Proxmox VE base URL, e.g. https://pve.example.com:8006.
        #[arg(long)]
        url: String,
        /// Proxmox API token (`user@realm!tokenid=secret`): from
        /// ORBYN_PROXMOX_TOKEN, or `-` to read one line from stdin so it
        /// never lands in argv.
        #[arg(long, env = "ORBYN_PROXMOX_TOKEN", hide_env_values = true)]
        token: Option<String>,
        /// Skip TLS certificate verification (for self-signed Proxmox).
        #[arg(long)]
        no_verify: bool,
        /// Restrict the import to a single cluster node.
        #[arg(long)]
        node: Option<String>,
    },
}

/// Sub-actions of `orbyn aws`.
#[derive(Debug, Subcommand)]
enum AwsAction {
    /// Import EC2 instances and their network interfaces.
    Import {
        /// AWS region, e.g. eu-west-1 (from AWS_REGION or AWS_DEFAULT_REGION).
        #[arg(long)]
        region: Option<String>,
        /// AWS access key id (from AWS_ACCESS_KEY_ID).
        #[arg(long, env = "AWS_ACCESS_KEY_ID", hide_env_values = true)]
        access_key: Option<String>,
        /// AWS secret access key (from AWS_SECRET_ACCESS_KEY), or `-` to read
        /// one line from stdin so it never lands in argv.
        #[arg(long, env = "AWS_SECRET_ACCESS_KEY", hide_env_values = true)]
        secret_key: Option<String>,
        /// AWS session token (from AWS_SESSION_TOKEN), or `-` for stdin.
        #[arg(long, env = "AWS_SESSION_TOKEN", hide_env_values = true)]
        session_token: Option<String>,
        /// Override the EC2 endpoint (from AWS_ENDPOINT_URL), for private
        /// endpoints or tests.
        #[arg(long, env = "AWS_ENDPOINT_URL", hide_env_values = true)]
        endpoint_url: Option<String>,
        /// Skip TLS certificate verification (for a self-signed endpoint).
        #[arg(long)]
        no_verify: bool,
    },
}

/// Sub-actions of `orbyn prometheus`.
#[derive(Debug, Subcommand)]
enum PrometheusAction {
    /// Import historical CPU/RAM utilization samples from Prometheus.
    Import {
        /// Prometheus base URL, e.g. http://prometheus:9090.
        #[arg(long)]
        url: String,
        /// Bearer token: from ORBYN_PROMETHEUS_TOKEN, or `-` to read one
        /// line from stdin so it never lands in argv.
        #[arg(long, env = "ORBYN_PROMETHEUS_TOKEN", hide_env_values = true)]
        token: Option<String>,
        /// Skip TLS certificate verification (for self-signed Prometheus).
        #[arg(long)]
        no_verify: bool,
        /// Hours of history to import (168 = one meeting week, the
        /// right-sizing minimum).
        #[arg(long, default_value_t = 168)]
        lookback_hours: i64,
        /// Query resolution step (Prometheus duration, e.g. 5m).
        #[arg(long, default_value = "5m")]
        step: String,
        /// Override the CPU utilization query (must aggregate per
        /// `instance`, percent).
        #[arg(long)]
        cpu_query: Option<String>,
        /// Override the RAM-used query (must aggregate per `instance`,
        /// bytes).
        #[arg(long)]
        ram_query: Option<String>,
        /// Override the swap-used query (must aggregate per `instance`,
        /// bytes). A swap query the endpoint cannot answer is skipped with a
        /// warning; CPU and RAM history still import.
        #[arg(long)]
        swap_query: Option<String>,
    },
}

/// Sub-actions of `orbyn zabbix`.
#[derive(Debug, Subcommand)]
enum ZabbixAction {
    /// Import historical CPU/RAM/swap utilization samples from Zabbix.
    Import {
        /// Zabbix JSON-RPC endpoint, e.g.
        /// https://zabbix.example.com/zabbix/api_jsonrpc.php.
        #[arg(long)]
        url: String,
        /// API token: from ORBYN_ZABBIX_TOKEN, or `-` to read one line from
        /// stdin so it never lands in argv.
        #[arg(long, env = "ORBYN_ZABBIX_TOKEN", hide_env_values = true)]
        token: Option<String>,
        /// Skip TLS certificate verification (for self-signed Zabbix).
        #[arg(long)]
        no_verify: bool,
        /// Hours of history to import (168 = one meeting week, the
        /// right-sizing minimum).
        #[arg(long, default_value_t = 168)]
        lookback_hours: i64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    load_dotenv_from(std::path::Path::new(".env"));

    let cli = Cli::parse();
    init_logging(cli.verbose);
    let config = Config::resolve(cli.db.clone());

    match cli.command {
        Command::Discover {
            target,
            format,
            collector,
            concurrency,
            rate_limit,
            allow_large_cidr,
            community,
            snmp_version,
            snmp_port,
            user,
            port,
            identity_file,
            winrm_password,
            winrm_port,
            winrm_insecure,
        } => {
            let store = open_store(&config).await?;
            if concurrency == 0 {
                bail!("--concurrency must be at least 1");
            }
            if rate_limit == Some(0) {
                bail!("--rate-limit must be at least 1");
            }
            let mut scan_targets = Vec::with_capacity(target.len());
            for raw in &target {
                scan_targets.push(
                    validate_target_with_policy(raw, allow_large_cidr)
                        .map_err(|e| anyhow!(large_scope_hint(&e, allow_large_cidr)))?,
                );
            }
            let community = resolve_secret(community, "--community", "ORBYN_SNMP_COMMUNITY")?;
            let winrm_password =
                resolve_secret(winrm_password, "--winrm-password", "ORBYN_WINRM_PASSWORD")?;
            validate_ssh_user(user.as_deref())?;
            if collector == DiscoveryCollector::Winrm
                && user.as_deref().unwrap_or_default().is_empty()
            {
                bail!(
                    "--collector winrm requires --user (the Windows account, e.g. Administrator)"
                );
            }
            let version: SnmpVersion = snmp_version.parse().map_err(anyhow::Error::msg)?;
            let profile =
                CredentialProfile::new(user.clone().unwrap_or_default(), port, identity_file);

            let collector: Arc<dyn Collector> = match collector {
                DiscoveryCollector::Nmap => Arc::new(NmapCollector::new()),
                DiscoveryCollector::Snmp => Arc::new(SnmpCollector::new(
                    community.as_deref().unwrap_or_default(),
                    version,
                    snmp_port,
                )),
                DiscoveryCollector::Ssh => Arc::new(LinuxCollector::new(profile)),
                DiscoveryCollector::Windows => Arc::new(WindowsCollector::new(profile)),
                DiscoveryCollector::Winrm => {
                    if winrm_insecure {
                        tracing::warn!(
                            "--winrm-insecure disables TLS certificate verification for the WinRM endpoint"
                        );
                        eprintln!(
                            "WARNING: --winrm-insecure disables TLS certificate verification.\n\
                             Only use it against trusted endpoints with self-signed certificates."
                        );
                    }
                    let winrm_profile =
                        CredentialProfile::new(user.unwrap_or_default(), winrm_port, None);
                    let transport =
                        WinRmTransport::new(winrm_profile, winrm_password.clone(), winrm_insecure)?;
                    Arc::new(WindowsCollector::with_transport(WindowsTransport::WinRm(
                        transport,
                    )))
                }
            };

            let mut redactor = orbyn::redact::Redactor::from_env();
            if let Some(community) = &community {
                redactor.add_value(community);
            }
            if let Some(password) = &winrm_password {
                redactor.add_value(password);
            }

            discover(
                store.as_ref(),
                &scan_targets,
                collector,
                concurrency,
                rate_limit,
                &redactor,
            )
            .await?;
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
            let store = open_store(&config).await?;
            let assets = store.list_assets().await?;
            print!("{}", orbyn::output::assets(&assets, format));
        }
        Command::Asset { asset, format } => {
            let store = open_store(&config).await?;
            let asset = resolve_asset(store.as_ref(), &asset).await?;
            let rendered = render_asset_detail(store.as_ref(), &asset, format).await?;
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
            let store = open_store(&config).await?;
            let asset = resolve_asset(store.as_ref(), &asset).await?;
            let criticality = criticality
                .map(|c| c.parse::<Criticality>())
                .transpose()
                .map_err(anyhow::Error::msg)?;
            let audit = begin_audit(
                store.as_ref(),
                "annotate",
                &asset.id,
                Some("asset annotation"),
            )
            .await?;
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
            finish_audit_result(store.as_ref(), audit, result).await?;
            let updated = store.get_asset(&asset.id).await?.expect("asset exists");
            let rendered = render_asset_detail(store.as_ref(), &updated, format).await?;
            print!("{rendered}");
        }
        Command::Services { asset, format } => {
            let store = open_store(&config).await?;
            let asset = resolve_asset(store.as_ref(), &asset).await?;
            let services = store.list_services(&asset.id).await?;
            print!("{}", orbyn::output::services(&services, format));
        }
        Command::Interfaces { asset, format } => {
            let store = open_store(&config).await?;
            let asset = resolve_asset(store.as_ref(), &asset).await?;
            let ifaces = store.list_interfaces(&asset.id).await?;
            print!("{}", orbyn::output::interfaces(&ifaces, format));
        }
        Command::Capacity { asset, format } => {
            let store = open_store(&config).await?;
            let asset = resolve_asset(store.as_ref(), &asset).await?;
            let capacity = store.get_capacity(&asset.id).await?;
            print!("{}", orbyn::output::capacity(capacity.as_ref(), format));
        }
        Command::Disks { asset, format } => {
            let store = open_store(&config).await?;
            let asset = resolve_asset(store.as_ref(), &asset).await?;
            let filesystems = store.list_filesystems(&asset.id).await?;
            print!("{}", orbyn::output::filesystems(&filesystems, format));
        }
        Command::HostServices { asset, format } => {
            let store = open_store(&config).await?;
            let asset = resolve_asset(store.as_ref(), &asset).await?;
            let running = store.list_running_services(&asset.id).await?;
            print!("{}", orbyn::output::running_services(&running, format));
        }
        Command::Jobs { limit, format } => {
            let store = open_store(&config).await?;
            let jobs = store.list_jobs(Some(limit)).await?;
            print!("{}", orbyn::output::jobs(&jobs, format));
        }
        Command::Audit { limit, format } => {
            let store = open_store(&config).await?;
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
            let store = open_store(&config).await?;
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
                    let services = store.list_all_services().await?;
                    let interfaces = store.list_all_interfaces().await?;
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
            let store = open_store(&config).await?;
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
        }
        Command::Netbox {
            action:
                NetboxAction::Import {
                    url,
                    token,
                    no_verify,
                },
        } => {
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
            let store = open_store(&config).await?;
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
        }
        Command::Proxmox {
            action:
                ProxmoxAction::Import {
                    url,
                    token,
                    no_verify,
                    node,
                },
        } => {
            let token =
                resolve_secret(token, "--token", "ORBYN_PROXMOX_TOKEN")?.ok_or_else(|| {
                    anyhow!(
                        "a Proxmox API token is required: pass --token, set \
                     ORBYN_PROXMOX_TOKEN, or use --token - to read it from stdin"
                    )
                })?;
            if no_verify {
                tracing::warn!("--no-verify disables TLS certificate verification for Proxmox");
                eprintln!(
                    "WARNING: --no-verify disables TLS certificate verification.\n\
                     Only use this against a trusted self-signed Proxmox instance; \
                     connections can be silently intercepted."
                );
            }
            if is_plain_http(&url) {
                eprintln!(
                    "WARNING: --url uses plain HTTP; the Proxmox API token will travel \
                     unencrypted over the network (audit OY-12)."
                );
            }
            let store = open_store(&config).await?;
            let mut redactor = orbyn::redact::Redactor::from_env();
            redactor.add_value(&token);
            let audit = begin_audit(
                store.as_ref(),
                "proxmox.import",
                "cloud",
                Some(&format!(
                    "url={url}{}",
                    node.as_deref()
                        .map(|n| format!(", node={n}"))
                        .unwrap_or_default()
                )),
            )
            .await?;
            let result: Result<()> = async {
                let client = ProxmoxClient::new(&url, token, no_verify)
                    .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?
                    .with_node(node);
                let inventory = client
                    .fetch_inventory()
                    .await
                    .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
                persist_cloud_inventory(store.as_ref(), &inventory)
                    .await
                    .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
                print_cloud_import("Proxmox", &inventory);
                Ok(())
            }
            .await;
            finish_audit_result(store.as_ref(), audit, result).await?;
        }
        Command::Aws {
            action:
                AwsAction::Import {
                    region,
                    access_key,
                    secret_key,
                    session_token,
                    endpoint_url,
                    no_verify,
                },
        } => {
            let region = region
                .or_else(|| std::env::var("AWS_REGION").ok())
                .or_else(|| std::env::var("AWS_DEFAULT_REGION").ok())
                .filter(|r| !r.is_empty())
                .ok_or_else(|| {
                    anyhow!("an AWS region is required: pass --region or set AWS_REGION")
                })?;
            let access_key = access_key.filter(|k| !k.is_empty()).ok_or_else(|| {
                anyhow!(
                    "an AWS access key id is required: pass --access-key or set \
                     AWS_ACCESS_KEY_ID"
                )
            })?;
            let secret_key = resolve_secret(secret_key, "--secret-key", "AWS_SECRET_ACCESS_KEY")?
                .ok_or_else(|| {
                anyhow!(
                    "an AWS secret access key is required: pass --secret-key, set \
                         AWS_SECRET_ACCESS_KEY, or use --secret-key - to read it from stdin"
                )
            })?;
            let session_token =
                resolve_secret(session_token, "--session-token", "AWS_SESSION_TOKEN")?;
            if no_verify {
                tracing::warn!("--no-verify disables TLS certificate verification for AWS");
                eprintln!(
                    "WARNING: --no-verify disables TLS certificate verification.\n\
                     Only use this against a trusted self-signed endpoint; connections \
                     can be silently intercepted."
                );
            }
            if let Some(endpoint) = &endpoint_url {
                if is_plain_http(endpoint) {
                    eprintln!(
                        "WARNING: --endpoint-url uses plain HTTP; AWS credentials and the \
                         signed request will travel unencrypted (audit OY-12)."
                    );
                }
            }
            let store = open_store(&config).await?;
            let mut redactor = orbyn::redact::Redactor::from_env();
            redactor.add_value(&secret_key);
            if let Some(token) = &session_token {
                redactor.add_value(token);
            }
            let audit = begin_audit(
                store.as_ref(),
                "aws.import",
                "cloud",
                Some(&format!(
                    "region={region}{}",
                    endpoint_url
                        .as_deref()
                        .map(|e| format!(", endpoint={e}"))
                        .unwrap_or_default()
                )),
            )
            .await?;
            let result: Result<()> = async {
                let credentials = AwsCredentials {
                    access_key,
                    secret_key,
                    session_token,
                };
                let client =
                    AwsClient::new(credentials, &region, endpoint_url.as_deref(), no_verify)
                        .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
                let inventory = client
                    .fetch_inventory()
                    .await
                    .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
                persist_cloud_inventory(store.as_ref(), &inventory)
                    .await
                    .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
                print_cloud_import("AWS", &inventory);
                Ok(())
            }
            .await;
            finish_audit_result(store.as_ref(), audit, result).await?;
        }
        Command::Prometheus {
            action:
                PrometheusAction::Import {
                    url,
                    token,
                    no_verify,
                    lookback_hours,
                    step,
                    cpu_query,
                    ram_query,
                    swap_query,
                },
        } => {
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
            let store = open_store(&config).await?;
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
        }
        Command::Zabbix {
            action:
                ZabbixAction::Import {
                    url,
                    token,
                    no_verify,
                    lookback_hours,
                },
        } => {
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
            let store = open_store(&config).await?;
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
        }
        Command::Graph {
            format,
            mermaid,
            asset,
        } => {
            let store = open_store(&config).await?;
            let mut edges = store.list_dependencies().await?;
            let assets = store.list_assets().await?;
            if let Some(key) = asset {
                let asset = resolve_asset(store.as_ref(), &key).await?;
                edges.retain(|d| d.source_asset_id == asset.id || d.target_asset_id == asset.id);
            }
            if mermaid {
                print!("{}", orbyn::output::mermaid(&edges, &assets));
            } else {
                print!("{}", orbyn::output::dependencies(&edges, &assets, format));
            }
        }
        Command::Connections { asset, format } => {
            let store = open_store(&config).await?;
            let asset = resolve_asset(store.as_ref(), &asset).await?;
            let conns = store.list_connections(&asset.id).await?;
            print!("{}", orbyn::output::connections(&conns, format));
        }
        Command::Metrics {
            asset,
            samples,
            format,
        } => {
            let store = open_store(&config).await?;
            let asset = resolve_asset(store.as_ref(), &asset).await?;
            let collected = store.list_metric_samples(&asset.id, samples).await?;
            let stats = orbyn::metrics::summarize(&collected);
            print!("{}", orbyn::output::metrics(stats.as_ref(), format));
        }
        Command::Deps { action } => {
            let store = open_store(&config).await?;
            deps(store.as_ref(), action).await?;
        }
        Command::Assess { format, rules } => {
            let store = open_store(&config).await?;
            if rules {
                print!(
                    "{}",
                    orbyn::output::rules_catalog(
                        orbyn::assessment::rules::catalog(),
                        orbyn::assessment::RULES_VERSION
                    )
                );
            } else {
                let input = assessment_input(store.as_ref()).await?;
                let report = run_assessment(&input);
                print!("{}", orbyn::output::report(&report, format));
            }
        }
    }

    Ok(())
}

/// Open the configured store: a SQLite file (filesystem path) or a
/// PostgreSQL database (`postgres://`/`postgresql://` URL). Migrations run
/// automatically on open for both backends.
async fn open_store(config: &Config) -> Result<Arc<dyn Store>> {
    match &config.db {
        DbTarget::Sqlite(path) => {
            let store = SqliteStore::open(path).await?;
            Ok(Arc::new(store))
        }
        DbTarget::Postgres(url) => {
            if orbyn::config::postgres_password_value(url).is_some() {
                eprintln!(
                    "WARNING: the --db URL embeds the PostgreSQL password, which \
                     is visible in the process arguments (ps, /proc); prefer a \
                     URL without a password plus ORBYN_PG_PASSWORD or PGPASSWORD \
                     (audit OY-06)."
                );
            }
            // Defense in depth: register the password (URL userinfo or env
            // fallback) so it is redacted if it ever reaches an error string.
            let mut redactor = orbyn::redact::Redactor::from_env();
            if let Some(password) = orbyn::config::postgres_password_value(url)
                .or_else(orbyn::config::postgres_env_password)
            {
                redactor.add_value(password);
            }
            let store = PostgresStore::open(url)
                .await
                .map_err(|e| anyhow!(redactor.redact(&format!("{e:#}"))))?;
            Ok(Arc::new(store))
        }
    }
}

/// Resolve a secret flag value: the literal `-` reads one trimmed line from
/// stdin so the secret never appears in argv or the environment; any other
/// value passes through unchanged. Values containing newlines or NUL bytes
/// are rejected: they would split the temporary SNMP config file, curl's
/// `-H @-` header stream or curl's `-K -` config stream (config/header
/// injection).
///
/// A literal value warns on stderr: it sits in the process arguments (and
/// shell history) for the whole process lifetime (audit OY-07). Values
/// sourced from `env_var` (clap's env fallback) do not warn.
fn resolve_secret(value: Option<String>, flag: &str, env_var: &str) -> Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let secret = if value == "-" {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .with_context(|| format!("reading {flag} from stdin"))?;
        let secret = line.trim();
        if secret.is_empty() {
            bail!("{flag} read an empty secret from stdin");
        }
        secret.to_string()
    } else {
        if secret_needs_argv_warning(&value, env_var) {
            eprintln!(
                "WARNING: {flag} passed as a literal value is visible in the \
                 process arguments (ps, shell history); prefer '-' to read it \
                 from stdin, or set {env_var} (audit OY-07)."
            );
        }
        value
    };
    if secret.contains(['\n', '\r', '\0']) {
        bail!("{flag} cannot contain newlines or NUL bytes");
    }
    Ok(Some(secret))
}

/// True when a secret arrived as a literal flag value (not the stdin marker
/// and not matching the env fallback), leaving it exposed in argv.
fn secret_needs_argv_warning(value: &str, env_var: &str) -> bool {
    value != "-" && std::env::var(env_var).ok().as_deref() != Some(value)
}

/// Extend an oversized-scope validation error with the override hint when
/// the default CIDR floor rejected the target (audit OY-09).
fn large_scope_hint(e: &ScanTargetError, allow_large_cidr: bool) -> String {
    if !allow_large_cidr && matches!(e, ScanTargetError::TooLarge(_)) {
        format!(
            "{e}; pass --allow-large-cidr to override the default minimum \
             prefix (IPv4 /16, IPv6 /48)"
        )
    } else {
        e.to_string()
    }
}

/// Reject SSH usernames that the ssh binary would parse as options: the
/// username is embedded in the destination argument (`user@host`), and a
/// value starting with `-` is consumed as an ssh option instead
/// (argument injection, audit OY-11).
fn validate_ssh_user(user: Option<&str>) -> Result<()> {
    if let Some(user) = user {
        if user.starts_with('-') {
            bail!("--user cannot start with '-' (ssh would parse it as an option)");
        }
    }
    Ok(())
}

/// True when a NetBox URL uses plaintext HTTP: the Authorization token
/// would travel unencrypted (audit OY-12).
fn is_plain_http(url: &str) -> bool {
    url.trim().to_ascii_lowercase().starts_with("http://")
}

/// Load `.env` from `path` only — never from parent directories (audit
/// OY-01: `dotenvy::dotenv()` ascends the tree, so a stray `.env` in an
/// ancestor could execute arbitrary binaries via `ORBYN_*_BIN`).
///
/// Preserves `dotenvy` semantics: variables already present in the
/// environment win over file values. Warns when the file overrides an
/// `ORBYN_*_BIN` with anything but the built-in default binary name —
/// Orbyn executes that binary, and the operator should see it.
fn load_dotenv_from(path: &std::path::Path) {
    let Ok(iter) = dotenvy::from_path_iter(path) else {
        return;
    };
    for (key, value) in iter.flatten() {
        if key.starts_with("ORBYN_") && key.ends_with("_BIN") && !is_default_bin(&key, &value) {
            eprintln!(
                "WARNING: {} configures {key}={value}; Orbyn will execute that binary.",
                path.display()
            );
        }
        if std::env::var_os(&key).is_none() {
            std::env::set_var(&key, value);
        }
    }
}

/// True when `key`/`value` reproduce the built-in binary default, in which
/// case the `.env` line changes nothing and deserves no warning.
fn is_default_bin(key: &str, value: &str) -> bool {
    matches!(
        (key, value),
        ("ORBYN_NMAP_BIN", "nmap")
            | ("ORBYN_SNMP_BIN", "snmpwalk")
            | ("ORBYN_SSH_BIN", "ssh")
            | ("ORBYN_CURL_BIN", "curl")
    )
}

/// Run one discovery job over the given targets, fanning them out over a
/// bounded worker pool: at most `concurrency` collector scans run at once,
/// optionally paced to at most `rate_limit` launches per second.
///
/// Observations from successful targets are always persisted; if any target
/// fails the job is marked Failed with the per-target errors, keeping the
/// partial data. Errors are scrubbed with `redactor` before they are
/// persisted or printed.
async fn discover(
    store: &dyn Store,
    scan_targets: &[ScanTarget],
    collector: Arc<dyn Collector>,
    concurrency: usize,
    rate_limit: Option<u32>,
    redactor: &orbyn::redact::Redactor,
) -> Result<()> {
    let targets: Vec<String> = scan_targets.iter().map(target_label).collect();

    let job = DiscoveryJob {
        id: uuid::Uuid::new_v4().to_string(),
        collector: collector.name().into(),
        targets: targets.clone(),
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

    tracing::info!(
        job = %job.id,
        collector = job.collector,
        targets = ?targets,
        concurrency,
        rate_limit,
        "starting discovery"
    );

    let mut running: VecDeque<JoinHandle<anyhow::Result<Vec<Observation>>>> = VecDeque::new();
    let mut results: Vec<anyhow::Result<Vec<Observation>>> = Vec::new();
    let first_launch = Instant::now();

    for (index, scan_target) in scan_targets.iter().enumerate() {
        if let Some(rate) = rate_limit {
            // Pace launches: target `index` may not start before
            // `index / rate` seconds have elapsed since the first launch.
            let earliest = Duration::from_secs_f64(index as f64 / f64::from(rate));
            let wait = earliest.saturating_sub(first_launch.elapsed());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        while running.len() >= concurrency {
            let handle = running.pop_front().expect("pool is at capacity");
            collect_scan_result(handle, &mut results).await;
        }
        let collector = Arc::clone(&collector);
        let scan_target = scan_target.clone();
        running.push_back(tokio::spawn(
            async move { collector.scan(&scan_target).await },
        ));
    }
    while let Some(handle) = running.pop_front() {
        collect_scan_result(handle, &mut results).await;
    }

    let mut observations = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for result in results {
        match result {
            Ok(obs) => observations.extend(obs),
            Err(e) => failures.push(redactor.redact(&format!("{e:#}"))),
        }
    }

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
    let running_services = observations
        .iter()
        .filter(|o| matches!(o, Observation::RunningService(_)))
        .count();
    let connections = observations
        .iter()
        .filter(|o| matches!(o, Observation::Connection(_)))
        .count();

    store.store_observations(observations).await?;

    let outcome = JobOutcome {
        assets_found: assets as u32,
        services_found: services as u32,
        filesystems_found: filesystems as u32,
        running_services_found: running_services as u32,
        connections_found: connections as u32,
    };

    if failures.is_empty() {
        store
            .finish_job(&job.id, JobStatus::Succeeded, None, Some(outcome))
            .await?;
        tracing::info!(job = %job.id, assets, services, "discovery complete");
        eprintln!(
            "Discovery job {} complete: {} assets, {} services, {} filesystems, {} running services, {} connections.",
            job.id, assets, services, filesystems, running_services, connections
        );
        Ok(())
    } else {
        let error = format!(
            "{} of {} targets failed: {}",
            failures.len(),
            scan_targets.len(),
            failures.join("; ")
        );
        store
            .finish_job(
                &job.id,
                JobStatus::Failed,
                Some(error.clone()),
                Some(outcome),
            )
            .await?;
        Err(anyhow!("discovery job {} failed: {error}", job.id))
    }
}

/// Await one worker task, flattening a join failure into an error result.
async fn collect_scan_result(
    handle: JoinHandle<anyhow::Result<Vec<Observation>>>,
    results: &mut Vec<anyhow::Result<Vec<Observation>>>,
) {
    match handle.await {
        Ok(result) => results.push(result),
        Err(e) => results.push(Err(anyhow!("collector task failed: {e}"))),
    }
}

fn target_label(target: &ScanTarget) -> String {
    match target {
        ScanTarget::Ip(ip) => ip.to_string(),
        ScanTarget::Cidr(cidr) => cidr.clone(),
    }
}

/// Gather the full inventory snapshot the assessment engine evaluates.
async fn assessment_input(store: &dyn Store) -> Result<AssessmentInput> {
    let assets = store.list_assets().await?;
    let services = store.list_all_services().await?;
    let filesystems = store.list_all_filesystems().await?;
    let capacities = store.list_all_capacities().await?;
    let connections = store.list_all_connections().await?;
    let dependencies = store.list_dependencies().await?;
    let metric_windows = metric_windows(store).await?;
    Ok(AssessmentInput {
        assets,
        services,
        filesystems,
        capacities,
        dependencies,
        connections,
        metric_windows,
    })
}

/// Summarize every asset's recorded samples into utilization windows (one
/// bulk read; no per-asset queries). Assets with too few samples produce
/// no window at all — `capacity.missing` already covers the gap.
async fn metric_windows(store: &dyn Store) -> Result<Vec<AssetWindow>> {
    let samples = store.list_all_metric_samples().await?;
    let mut by_asset: std::collections::HashMap<String, Vec<MetricSample>> =
        std::collections::HashMap::new();
    for sample in samples {
        by_asset
            .entry(sample.asset_id.clone())
            .or_default()
            .push(sample);
    }
    let mut windows: Vec<AssetWindow> = by_asset
        .into_iter()
        .filter_map(|(asset_id, samples)| {
            orbyn::metrics::summarize(&samples).map(|stats| AssetWindow { asset_id, stats })
        })
        .collect();
    windows.sort_by(|a, b| a.asset_id.cmp(&b.asset_id));
    Ok(windows)
}

/// Resolve an asset reference that may be an id, an IP address, or a
/// hostname (exact, case-insensitive).
async fn resolve_asset(store: &dyn Store, key: &str) -> Result<Asset> {
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
async fn render_asset_detail(store: &dyn Store, asset: &Asset, format: Format) -> Result<String> {
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
async fn resolve_dep_pair(store: &dyn Store, source: &str, target: &str) -> Result<(Asset, Asset)> {
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
    store: &dyn Store,
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
    store: &dyn Store,
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
async fn deps(store: &dyn Store, action: DepsAction) -> Result<()> {
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

/// Asset rows written per transaction during an import.
///
/// Large enough that a bulk import pays a handful of commits instead of one
/// per asset, small enough that a single transaction never holds the database
/// write lock for a very long time.
const IMPORT_WRITE_CHUNK: usize = 500;

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

/// Persist a normalized cloud inventory — assets, interfaces, services,
/// capacity and filesystems — recording a discovery job named after the
/// provider and attaching its provenance tags to every asset.
///
/// Unlike a flat file import, a cloud adapter has already validated and
/// normalized its rows, so this writes them directly. Assets are written
/// first so interface/service/capacity references satisfy their foreign keys.
async fn persist_cloud_inventory(store: &dyn Store, inv: &CloudInventory) -> Result<CloudCounts> {
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

/// Print the operator-facing summary of a cloud import.
fn print_cloud_import(provider: &str, inv: &CloudInventory) {
    let counts = inv.counts();
    let mut parts = vec![format!("{} assets", counts.assets)];
    if counts.interfaces > 0 {
        parts.push(format!("{} interfaces", counts.interfaces));
    }
    if counts.capacities > 0 {
        parts.push(format!("{} capacity rows", counts.capacities));
    }
    if counts.filesystems > 0 {
        parts.push(format!("{} filesystems", counts.filesystems));
    }
    eprintln!(
        "Imported {} from {provider} ({}).",
        parts.join(", "),
        inv.provenance.label()
    );
    for note in &inv.skipped {
        tracing::warn!(note, "skipped a cloud resource");
    }
    if !inv.skipped.is_empty() {
        eprintln!(
            "Skipped {} resource(s) that could not be represented.",
            inv.skipped.len()
        );
    }
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
    fn resolve_secret_rejects_control_characters() {
        assert!(resolve_secret(
            Some("bad\nsecret".into()),
            "--community",
            "ORBYN_SNMP_COMMUNITY"
        )
        .is_err());
        assert!(
            resolve_secret(Some("bad\rsecret".into()), "--token", "ORBYN_NETBOX_TOKEN").is_err()
        );
        assert!(
            resolve_secret(Some("bad\0secret".into()), "--token", "ORBYN_NETBOX_TOKEN").is_err()
        );
        assert_eq!(
            resolve_secret(Some("good-secret".into()), "--token", "ORBYN_NETBOX_TOKEN").unwrap(),
            Some("good-secret".to_string())
        );
        assert_eq!(
            resolve_secret(None, "--token", "ORBYN_NETBOX_TOKEN").unwrap(),
            None
        );
    }

    #[test]
    fn literal_secrets_warn_but_env_sourced_do_not() {
        // A throwaway env var keeps this test independent from a developer
        // shell that exports the real secret variables.
        let var = "ORBYN_TEST_SECRET_WARN";
        std::env::remove_var(var);
        assert!(
            secret_needs_argv_warning("literal-value", var),
            "literal flag values are exposed in argv and must warn"
        );
        assert!(
            !secret_needs_argv_warning("-", var),
            "the stdin marker never warns"
        );
        std::env::set_var(var, "from-env");
        assert!(
            !secret_needs_argv_warning("from-env", var),
            "values matching the env fallback do not warn"
        );
        assert!(secret_needs_argv_warning("other", var));
        std::env::remove_var(var);
    }

    #[test]
    fn ssh_user_rejects_leading_dash() {
        assert!(validate_ssh_user(Some("-oProxyCommand=evil")).is_err());
        assert!(validate_ssh_user(Some("-Jevil.example")).is_err());
        assert!(validate_ssh_user(Some("deploy")).is_ok());
        assert!(validate_ssh_user(None).is_ok());
    }

    #[test]
    fn plain_http_urls_are_detected() {
        assert!(is_plain_http("http://netbox.example.com"));
        assert!(is_plain_http("  HTTP://netbox.example.com  "));
        assert!(!is_plain_http("https://netbox.example.com"));
        assert!(!is_plain_http("https://netbox.example.com/http://x"));
    }

    #[test]
    fn dotenv_loads_only_the_given_file_without_overwrite() {
        let dir = std::env::temp_dir().join(format!("orbyn-dotenv-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create dotenv test dir");
        let env_file = dir.join(".env");
        std::fs::write(
            &env_file,
            "ORBYN_DOTENV_TEST_NEW=loaded\nORBYN_DOTENV_TEST_EXISTING=from_file\n",
        )
        .expect("write test .env");
        std::env::set_var("ORBYN_DOTENV_TEST_EXISTING", "from_env");

        load_dotenv_from(&env_file);

        assert_eq!(
            std::env::var("ORBYN_DOTENV_TEST_NEW").expect("new var loaded"),
            "loaded"
        );
        assert_eq!(
            std::env::var("ORBYN_DOTENV_TEST_EXISTING").expect("existing var kept"),
            "from_env",
            "environment must win over the .env file"
        );
        std::env::remove_var("ORBYN_DOTENV_TEST_NEW");
        std::env::remove_var("ORBYN_DOTENV_TEST_EXISTING");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_bin_overrides_are_recognized() {
        assert!(is_default_bin("ORBYN_NMAP_BIN", "nmap"));
        assert!(is_default_bin("ORBYN_SNMP_BIN", "snmpwalk"));
        assert!(is_default_bin("ORBYN_SSH_BIN", "ssh"));
        assert!(is_default_bin("ORBYN_CURL_BIN", "curl"));
        assert!(!is_default_bin("ORBYN_NMAP_BIN", "/tmp/evil-nmap"));
        assert!(!is_default_bin("ORBYN_NMAP_BIN", "nmap-backup"));
        assert!(!is_default_bin("ORBYN_DB", "nmap"));
    }

    #[test]
    fn help_does_not_echo_env_secret_values() {
        std::env::set_var("ORBYN_SNMP_COMMUNITY", "help-leak-canary");
        std::env::set_var("ORBYN_NETBOX_TOKEN", "help-leak-canary");
        std::env::set_var("ORBYN_WINRM_PASSWORD", "help-leak-canary");
        std::env::set_var("ORBYN_PROMETHEUS_TOKEN", "help-leak-canary");
        std::env::set_var("ORBYN_PROXMOX_TOKEN", "help-leak-canary");
        std::env::set_var("AWS_ACCESS_KEY_ID", "help-leak-canary");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "help-leak-canary");
        std::env::set_var("AWS_SESSION_TOKEN", "help-leak-canary");
        let mut cmd = Cli::command();
        let discover_help = cmd
            .find_subcommand_mut("discover")
            .expect("discover subcommand")
            .render_help()
            .to_string();
        let mut cmd = Cli::command();
        let netbox_import_help = cmd
            .find_subcommand_mut("netbox")
            .expect("netbox subcommand")
            .find_subcommand_mut("import")
            .expect("netbox import subcommand")
            .render_help()
            .to_string();
        let mut cmd = Cli::command();
        let prometheus_import_help = cmd
            .find_subcommand_mut("prometheus")
            .expect("prometheus subcommand")
            .find_subcommand_mut("import")
            .expect("prometheus import subcommand")
            .render_help()
            .to_string();
        let zabbix_import_help = cmd
            .find_subcommand_mut("zabbix")
            .expect("zabbix subcommand")
            .find_subcommand_mut("import")
            .expect("zabbix import subcommand")
            .render_help()
            .to_string();
        let mut cmd = Cli::command();
        let proxmox_import_help = cmd
            .find_subcommand_mut("proxmox")
            .expect("proxmox subcommand")
            .find_subcommand_mut("import")
            .expect("proxmox import subcommand")
            .render_help()
            .to_string();
        let mut cmd = Cli::command();
        let aws_import_help = cmd
            .find_subcommand_mut("aws")
            .expect("aws subcommand")
            .find_subcommand_mut("import")
            .expect("aws import subcommand")
            .render_help()
            .to_string();
        std::env::remove_var("ORBYN_SNMP_COMMUNITY");
        std::env::remove_var("ORBYN_NETBOX_TOKEN");
        std::env::remove_var("ORBYN_WINRM_PASSWORD");
        std::env::remove_var("ORBYN_PROMETHEUS_TOKEN");
        std::env::remove_var("ORBYN_ZABBIX_TOKEN");
        std::env::remove_var("ORBYN_PROXMOX_TOKEN");
        std::env::remove_var("AWS_ACCESS_KEY_ID");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        std::env::remove_var("AWS_SESSION_TOKEN");

        // The variable name stays documented, its current value never leaks.
        assert!(
            discover_help.contains("ORBYN_SNMP_COMMUNITY"),
            "env var name stays documented: {discover_help}"
        );
        assert!(
            !discover_help.contains("help-leak-canary"),
            "community env value leaked into help: {discover_help}"
        );
        assert!(
            discover_help.contains("ORBYN_WINRM_PASSWORD"),
            "env var name stays documented: {discover_help}"
        );
        assert!(
            netbox_import_help.contains("ORBYN_NETBOX_TOKEN"),
            "env var name stays documented: {netbox_import_help}"
        );
        assert!(
            !netbox_import_help.contains("help-leak-canary"),
            "token env value leaked into help: {netbox_import_help}"
        );
        assert!(
            prometheus_import_help.contains("ORBYN_PROMETHEUS_TOKEN"),
            "env var name stays documented: {prometheus_import_help}"
        );
        assert!(
            !prometheus_import_help.contains("help-leak-canary"),
            "token env value leaked into help: {prometheus_import_help}"
        );
        assert!(
            zabbix_import_help.contains("ORBYN_ZABBIX_TOKEN"),
            "env var name stays documented: {zabbix_import_help}"
        );
        assert!(
            !zabbix_import_help.contains("help-leak-canary"),
            "token env value leaked into help: {zabbix_import_help}"
        );
        assert!(
            proxmox_import_help.contains("ORBYN_PROXMOX_TOKEN"),
            "env var name stays documented: {proxmox_import_help}"
        );
        assert!(
            !proxmox_import_help.contains("help-leak-canary"),
            "token env value leaked into help: {proxmox_import_help}"
        );
        assert!(
            aws_import_help.contains("AWS_ACCESS_KEY_ID")
                && aws_import_help.contains("AWS_SECRET_ACCESS_KEY"),
            "env var names stay documented: {aws_import_help}"
        );
        assert!(
            !aws_import_help.contains("help-leak-canary"),
            "credential env value leaked into help: {aws_import_help}"
        );
    }

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
            "prometheus",
            "zabbix",
            "proxmox",
            "aws",
            "graph",
            "assess",
            "completions",
        ];
        for name in expected {
            assert!(names.contains(&name), "missing stable command: {name}");
        }
    }
}
