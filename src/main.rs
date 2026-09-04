use clap::{Parser, Subcommand};
use std::path::PathBuf;

use orbyn::api;
use orbyn::collectors::nmap::NmapCollector;
use orbyn::collectors::{validate_target, Collector};
use orbyn::config::Config;
use orbyn::store::sqlite::SqliteStore;
use orbyn::store::Store;

#[derive(Parser)]
#[command(
    name = "orbyn",
    about = "Infrastructure discovery, dependency mapping, and migration assessment."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP API server.
    Serve {
        /// Listen address, e.g. 127.0.0.1:8080.
        #[arg(long, env = "ORBYN_ADDR")]
        addr: Option<String>,
        /// SQLite database path.
        #[arg(long, env = "ORBYN_DB")]
        db: Option<PathBuf>,
    },
    /// Run a single Nmap discovery job against a CIDR range.
    Discover {
        /// CIDR range to scan, e.g. 10.0.0.0/24.
        #[arg(long)]
        target: String,
        /// SQLite database path.
        #[arg(long, env = "ORBYN_DB")]
        db: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "orbyn=info,tower_http=info".into()),
        )
        .init();

    dotenvy::dotenv().ok();

    let cli = Cli::parse();
    let config = Config::from_env()?;

    match cli.command {
        Command::Serve { addr, db } => {
            let config = config.with_overrides(addr, db);
            let store = SqliteStore::open(&config.db_path).await?;
            let app = api::router(store);
            let listener = tokio::net::TcpListener::bind(&config.addr).await?;
            tracing::info!(addr = %config.addr, "Orbyn API listening");
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .await?;
            Ok(())
        }
        Command::Discover { target, db } => {
            let config = config.with_overrides(None, db);
            let target = validate_target(&target)?;
            let collector = NmapCollector::new();
            let observations = collector.scan(&target).await?;
            let store = SqliteStore::open(&config.db_path).await?;
            store.store_observations(observations).await?;
            Ok(())
        }
    }
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::info!("shutdown signal received");
    }
}
