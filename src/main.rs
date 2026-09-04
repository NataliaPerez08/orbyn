use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};

use orbyn::assessment::{assess, AssessmentReport, Finding, Severity};
use orbyn::collectors::nmap::NmapCollector;
use orbyn::collectors::{validate_target, Collector};
use orbyn::config::Config;
use orbyn::domain::{DiscoveryJob, JobStatus, Observation};
use orbyn::output::{Format, Inventory};
use orbyn::store::sqlite::SqliteStore;
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

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover assets in a CIDR range using Nmap.
    Discover {
        /// Target IP or CIDR range, e.g. 10.0.0.0/24.
        #[arg(long)]
        target: String,
        /// Output format for the resulting inventory.
        #[arg(long, value_enum, default_value_t = Format::Table)]
        format: Format,
    },

    /// List discovered assets.
    Assets {
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

    /// Export the inventory to JSON (full) or CSV (assets).
    Export {
        #[arg(short, long, value_enum, default_value_t = Format::Json)]
        format: Format,
        /// Write to a file instead of stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
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
        Command::Discover { target, format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            discover(&store, &target).await?;
            let assets = store.list_assets().await?;
            print!("{}", orbyn::output::assets(&assets, format));
        }
        Command::Assets { format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let assets = store.list_assets().await?;
            print!("{}", orbyn::output::assets(&assets, format));
        }
        Command::Services { asset, format } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let asset = match store.get_asset(&asset).await? {
                Some(a) => a,
                None => store
                    .get_asset_by_ip(&asset)
                    .await?
                    .ok_or_else(|| anyhow!("no asset matches '{asset}'"))?,
            };
            let services = store.list_services(&asset.id).await?;
            print!("{}", orbyn::output::services(&services, format));
        }
        Command::Export { format, output } => {
            let store = SqliteStore::open(&config.db_path).await?;
            let assets = store.list_assets().await?;
            let mut services = Vec::new();
            for asset in &assets {
                services.extend(store.list_services(&asset.id).await?);
            }
            let rendered = orbyn::output::inventory(&Inventory { assets, services }, format);
            match output {
                Some(path) => std::fs::write(&path, rendered)
                    .with_context(|| format!("writing export to {}", path.display()))?,
                None => print!("{rendered}"),
            }
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

/// Run one Nmap discovery job, persisting observations and job history.
async fn discover(store: &SqliteStore, target: &str) -> Result<()> {
    let scan_target = validate_target(target).map_err(|e| anyhow!(e.to_string()))?;

    let job = DiscoveryJob {
        id: uuid::Uuid::new_v4().to_string(),
        collector: "nmap".into(),
        targets: vec![target.to_string()],
        status: JobStatus::Running,
        started_at: Utc::now(),
        finished_at: None,
        error: None,
    };
    store.create_job(job.clone()).await?;

    let collector = NmapCollector::new();
    tracing::info!(job = %job.id, target = target, "starting nmap discovery");

    match collector.scan(&scan_target).await {
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
                .finish_job(&job.id, JobStatus::Succeeded, None)
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
                .finish_job(&job.id, JobStatus::Failed, Some(e.to_string()))
                .await?;
            Err(anyhow!("discovery job {} failed: {e:#}", job.id))
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
