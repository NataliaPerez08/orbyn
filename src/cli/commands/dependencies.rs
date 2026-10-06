//! Handlers for dependency curation (`deps`) and the dependency graph
//! views (`graph`). Translation from the parsed CLI arguments into the
//! application requests lives here; the workflows themselves are in
//! `app::dependencies`.

use std::collections::HashSet;

use anyhow::Result;

use orbyn::config::Config;
use orbyn::output::Format;

use crate::app::inventory::resolve_asset;
use crate::app::open_store;
use crate::cli::args::DepsAction;

/// Handle `orbyn deps <action>`.
pub(crate) async fn deps(config: &Config, action: DepsAction) -> Result<()> {
    let store = open_store(config).await?;
    match action {
        DepsAction::Add {
            source,
            target,
            proto,
            port,
        } => {
            crate::app::dependencies::add_edge(store.as_ref(), source, target, proto, port).await?
        }
        DepsAction::Confirm {
            source,
            target,
            proto,
            port,
        } => {
            crate::app::dependencies::confirm_edges(store.as_ref(), source, target, proto, port)
                .await?
        }
        DepsAction::Remove {
            source,
            target,
            proto,
            port,
        } => {
            crate::app::dependencies::remove_edges(store.as_ref(), source, target, proto, port)
                .await?
        }
        DepsAction::Dns => crate::app::dependencies::dns_evidence(store.as_ref()).await?,
    }
    Ok(())
}

/// Handle `orbyn graph`.
pub(crate) async fn graph(
    config: &Config,
    format: Format,
    mermaid: bool,
    asset: Option<String>,
    application: Option<String>,
    applications: bool,
) -> Result<()> {
    let store = open_store(config).await?;
    let mut edges = store.list_dependencies().await?;
    let assets = store.list_assets().await?;
    if let Some(key) = asset {
        let asset = resolve_asset(store.as_ref(), &key).await?;
        edges.retain(|d| d.source_asset_id == asset.id || d.target_asset_id == asset.id);
    }
    if let Some(key) = application {
        let detail = crate::app::applications::show(store.as_ref(), &key).await?;
        let members: HashSet<String> = detail.members.iter().map(|m| m.asset_id.clone()).collect();
        edges.retain(|d| {
            members.contains(&d.source_asset_id) || members.contains(&d.target_asset_id)
        });
    }
    if applications {
        let app_edges = crate::app::applications::application_edges(store.as_ref()).await?;
        if mermaid {
            print!("{}", orbyn::output::application_mermaid(&app_edges));
        } else {
            print!("{}", orbyn::output::application_graph(&app_edges, format));
        }
        return Ok(());
    }
    if mermaid {
        print!("{}", orbyn::output::mermaid(&edges, &assets));
    } else {
        print!("{}", orbyn::output::dependencies(&edges, &assets, format));
    }
    Ok(())
}
