//! Handlers for `orbyn server run|enroll|revoke|list` (v1.6 ingest).

use anyhow::{Context, Result};

use orbyn::config::Config;
use orbyn::domain::asset_id;
use orbyn::server;

use crate::app::open_store;
use crate::cli::args::ServerAction;

pub(crate) async fn server(config: &Config, action: ServerAction) -> Result<()> {
    match action {
        ServerAction::Run { bind } => {
            let bind = bind
                .parse()
                .with_context(|| format!("invalid bind address '{bind}'"))?;
            let store = open_store(config).await?;
            server::run(store.as_ref(), bind).await
        }
        ServerAction::Enroll { asset_ip } => {
            let ip: std::net::IpAddr = asset_ip
                .parse()
                .with_context(|| format!("invalid asset IP '{asset_ip}'"))?;
            let id = asset_id(ip);
            let store = open_store(config).await?;
            // Random UUID token; only its SHA-256 hash is stored.
            let token = uuid::Uuid::new_v4().simple().to_string();
            let hash = server::token_hash(&token);
            store
                .upsert_agent_token(&id, &hash, chrono::Utc::now())
                .await?;
            eprintln!(
                "Enrolled {id}. Copy the token now — it is not stored and \
                 cannot be shown again:"
            );
            println!("{token}");
            Ok(())
        }
        ServerAction::Revoke { asset_id } => {
            let store = open_store(config).await?;
            if store.revoke_agent_token(&asset_id).await? {
                eprintln!("Revoked {asset_id}; its syncs are refused from now on.");
            } else {
                eprintln!("No enrollment found for {asset_id}.");
            }
            Ok(())
        }
        ServerAction::List => {
            let store = open_store(config).await?;
            let enrollments = store.list_agent_tokens().await?;
            if enrollments.is_empty() {
                eprintln!("No agents enrolled yet (`orbyn server enroll --asset-ip <ip>`).");
                return Ok(());
            }
            println!("{:<24} {:<24} REVOKED", "ASSET", "ENROLLED_AT");
            for e in enrollments {
                println!("{:<24} {:<24} {}", e.asset_id, e.enrolled_at, e.revoked);
            }
            Ok(())
        }
    }
}
