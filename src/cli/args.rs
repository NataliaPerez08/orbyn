//! Command-line surface: clap definitions and argument validation.
//!
//! This module owns the shape of the CLI (`Cli`, `Command`, the per-command
//! action enums) and the argument parsers that have custom validation. It
//! must stay free of application logic: handlers live in
//! [`crate::cli::commands`].

use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand, ValueEnum};

use orbyn::integrations::ansible::GroupBy;
use orbyn::output::Format;
use orbyn::store::traits::AnnotationField;

#[derive(Debug, Parser)]
#[command(
    name = "orbyn",
    about = "CLI for infrastructure discovery, dependency mapping, and migration assessment.",
    version = env!("CARGO_PKG_VERSION")
)]
pub(crate) struct Cli {
    /// Path to the SQLite database, or a postgres:// URL for the
    /// PostgreSQL backend (default: ./data/orbyn.db).
    #[arg(long, global = true, env = "ORBYN_DB")]
    pub(crate) db: Option<String>,

    /// Increase log verbosity (repeatable: -v, -vv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub(crate) verbose: u8,

    #[command(subcommand)]
    pub(crate) command: Command,
}

/// Collector adapter selected for a discovery run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum DiscoveryCollector {
    Nmap,
    Snmp,
    Ssh,
    Windows,
    /// Native WS-Man/WinRM transport for Windows hosts.
    Winrm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ImportFormat {
    Json,
    Csv,
}

/// Export target: Orbyn's own formats, or automation-oriented formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ExportFormat {
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
pub(crate) enum UnsetField {
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
pub(crate) enum Command {
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

    /// Pull ECS instances from Huawei Cloud (read-only).
    Huawei {
        #[command(subcommand)]
        action: HuaweiAction,
    },

    /// Pull instances and networks from OpenStack (read-only).
    Openstack {
        #[command(subcommand)]
        action: OpenstackAction,
    },

    /// Pull Compute Engine inventory from Google Cloud (read-only).
    Gcp {
        #[command(subcommand)]
        action: GcpAction,
    },

    /// Pull virtual machine inventory from Azure Resource Manager (read-only).
    Azure {
        #[command(subcommand)]
        action: AzureAction,
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
        /// Restrict the view to edges touching this application's members.
        #[arg(long, conflicts_with_all = ["asset", "applications"])]
        application: Option<String>,
        /// Application-level graph: nodes are applications, edges are
        /// dependency edges crossing application boundaries.
        #[arg(long, conflicts_with_all = ["asset", "application"])]
        applications: bool,
    },

    /// Discover, inspect and curate applications: groups of assets that
    /// belong together, inferred from evidence or curated manually.
    Applications {
        #[command(subcommand)]
        action: Option<ApplicationsAction>,
    },

    /// Run a migration assessment over discovered assets.
    Assess {
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
        /// List the rule catalog (id + description) instead of assessing.
        #[arg(long, conflicts_with = "format")]
        rules: bool,
        /// Assess one application: roll findings up to its members.
        #[arg(long, conflicts_with = "rules")]
        application: Option<String>,
    },

    /// Match a right-sizing baseline (vCPU + RAM) to candidate instance
    /// types (SKUs) for a provider.
    SkuMatch {
        /// Provider catalog to match against.
        #[arg(long, value_enum)]
        provider: orbyn::sku::Provider,
        /// Required vCPU cores.
        #[arg(long)]
        cores: u32,
        /// Required RAM in MiB.
        #[arg(long)]
        ram_mb: u64,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// Suggest ordered migration waves from the dependency graph, application
    /// groups, criticality, complexity, external coupling and manual
    /// constraints, with the reasoning exposed.
    Waves {
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
        /// Force `<asset>=<wave>` (1-3); moves the whole application group.
        #[arg(long = "pin", value_parser = parse_pin)]
        pins: Vec<(String, usize)>,
        /// Leave an asset out of planning.
        #[arg(long = "exclude")]
        excludes: Vec<String>,
    },

    /// Plan the migration of one application — or all of them: readiness,
    /// strategy, targets, blockers and assumptions, persisted as an
    /// audited artifact.
    Plan {
        /// Application name or ID.
        #[arg(conflicts_with = "all")]
        application: Option<String>,
        /// Plan every application.
        #[arg(long)]
        all: bool,
        /// Target provider for instance-type recommendations
        /// (affects recommendations only, never the discovered evidence).
        #[arg(long, value_enum)]
        target: Option<PlanTarget>,
        /// Show why the strategy and wave were chosen.
        #[arg(long)]
        explain: bool,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// Generate a shell completion script (bash, zsh, or fish).
    Completions {
        /// Target shell.
        #[arg(value_enum)]
        shell: Shell,
    },
}

/// Target providers for `orbyn plan --target`. Huawei and OpenStack are
/// accepted but have no SKU catalog: recommendations report
/// NOT_CALCULATED instead of fabricated instance types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PlanTarget {
    Aws,
    Azure,
    Gcp,
    Huawei,
    Openstack,
}

/// Shell backends supported by `orbyn completions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Shell {
    Bash,
    Zsh,
    Fish,
}

/// Sub-actions of `orbyn deps`.
#[derive(Debug, Subcommand)]
pub(crate) enum DepsAction {
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

/// Sub-actions of `orbyn applications`.
#[derive(Debug, Subcommand)]
pub(crate) enum ApplicationsAction {
    /// Infer applications from dependencies and evidence and persist
    /// them; re-runs refresh and prune.
    Discover {
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },
    /// List applications.
    List {
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },
    /// Show one application and its members.
    Show {
        /// Application name or ID.
        application: String,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },
    /// Show why each member belongs to the application.
    Explain {
        /// Application name or ID.
        application: String,
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },
    /// Create an empty manual application.
    Create {
        /// Application name.
        name: String,
    },
    /// Manually add an asset to an application.
    Add {
        /// Application name or ID.
        application: String,
        /// Asset ID, IP or hostname.
        asset: String,
    },
    /// Remove an asset from an application.
    Remove {
        /// Application name or ID.
        application: String,
        /// Asset ID, IP or hostname.
        asset: String,
    },
}

/// Sub-actions of `orbyn netbox`.
#[derive(Debug, Subcommand)]
pub(crate) enum NetboxAction {
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
pub(crate) enum ProxmoxAction {
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
pub(crate) enum AwsAction {
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

/// Sub-actions of `orbyn huawei`.
#[derive(Debug, Subcommand)]
pub(crate) enum HuaweiAction {
    /// Import ECS instances and their network interfaces.
    Import {
        /// Huawei Cloud region, e.g. cn-north-4 (from HUAWEICLOUD_REGION).
        #[arg(long)]
        region: Option<String>,
        /// Huawei Cloud access key (AK) (from HUAWEICLOUD_SDK_AK).
        #[arg(long, env = "HUAWEICLOUD_SDK_AK", hide_env_values = true)]
        access_key: Option<String>,
        /// Huawei Cloud secret key (SK) (from HUAWEICLOUD_SDK_SK), or `-` to
        /// read one line from stdin so it never lands in argv.
        #[arg(long, env = "HUAWEICLOUD_SDK_SK", hide_env_values = true)]
        secret_key: Option<String>,
        /// Project id to scope the ECS query (from HUAWEICLOUD_PROJECT_ID);
        /// resolved from IAM when omitted.
        #[arg(long, env = "HUAWEICLOUD_PROJECT_ID", hide_env_values = true)]
        project_id: Option<String>,
        /// Override the ECS endpoint, for private endpoints or tests.
        #[arg(long)]
        endpoint_url: Option<String>,
        /// Skip TLS certificate verification (for a self-signed endpoint).
        #[arg(long)]
        no_verify: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum OpenstackAction {
    /// Import an OpenStack project inventory.
    Import {
        /// Nova endpoint, e.g. https://cloud.example/v2.1/project-id.
        #[arg(long)]
        url: String,
        /// Scoped Keystone token.
        #[arg(long, env = "ORBYN_OPENSTACK_TOKEN", hide_env_values = true)]
        token: Option<String>,
        #[arg(long, env = "OS_PROJECT_ID")]
        project: Option<String>,
        #[arg(long, env = "OS_REGION_NAME")]
        region: Option<String>,
        #[arg(long)]
        no_verify: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum GcpAction {
    /// Import Compute Engine instances and disks.
    Import {
        #[arg(long, env = "GOOGLE_CLOUD_PROJECT")]
        project: String,
        /// OAuth bearer token, from ORBYN_GCP_TOKEN or stdin with `-`.
        #[arg(long, env = "ORBYN_GCP_TOKEN", hide_env_values = true)]
        token: Option<String>,
        #[arg(long)]
        endpoint_url: Option<String>,
        #[arg(long)]
        no_verify: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AzureAction {
    /// Import Azure VMs, disks, NICs and virtual networks.
    Import {
        #[arg(long, env = "AZURE_SUBSCRIPTION_ID")]
        subscription_id: String,
        /// Azure AD bearer token, from ORBYN_AZURE_TOKEN or stdin with `-`.
        #[arg(long, env = "ORBYN_AZURE_TOKEN", hide_env_values = true)]
        token: Option<String>,
        #[arg(long)]
        endpoint_url: Option<String>,
        #[arg(long)]
        no_verify: bool,
    },
}

/// Sub-actions of `orbyn prometheus`.
#[derive(Debug, Subcommand)]
pub(crate) enum PrometheusAction {
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
pub(crate) enum ZabbixAction {
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

/// Parse `--pin <asset>=<wave>`.
pub(crate) fn parse_pin(s: &str) -> Result<(String, usize), String> {
    let (asset, wave) = s
        .split_once('=')
        .ok_or_else(|| format!("expected <asset>=<wave>, got {s:?}"))?;
    let wave: usize = wave
        .parse()
        .map_err(|_| format!("wave must be a number 1-3, got {wave:?}"))?;
    if !(1..=3).contains(&wave) {
        return Err(format!("wave must be 1-3, got {wave}"));
    }
    Ok((asset.to_string(), wave))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

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
        std::env::set_var("HUAWEICLOUD_SDK_AK", "help-leak-canary");
        std::env::set_var("HUAWEICLOUD_SDK_SK", "help-leak-canary");
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
        let mut cmd = Cli::command();
        let huawei_import_help = cmd
            .find_subcommand_mut("huawei")
            .expect("huawei subcommand")
            .find_subcommand_mut("import")
            .expect("huawei import subcommand")
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
        std::env::remove_var("HUAWEICLOUD_SDK_AK");
        std::env::remove_var("HUAWEICLOUD_SDK_SK");

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
        assert!(
            huawei_import_help.contains("HUAWEICLOUD_SDK_AK")
                && huawei_import_help.contains("HUAWEICLOUD_SDK_SK"),
            "env var names stay documented: {huawei_import_help}"
        );
        assert!(
            !huawei_import_help.contains("help-leak-canary"),
            "credential env value leaked into help: {huawei_import_help}"
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
            "huawei",
            "graph",
            "applications",
            "assess",
            "sku-match",
            "waves",
            "plan",
            "completions",
        ];
        for name in expected {
            assert!(names.contains(&name), "missing stable command: {name}");
        }
    }
}
