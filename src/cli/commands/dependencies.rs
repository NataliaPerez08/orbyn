//! Handlers for dependency curation (`deps`) and the dependency graph
//! views (`graph`).

use anyhow::Result;

use orbyn::config::Config;
use orbyn::domain::{Asset, Dependency, EvidenceKind, Observation};
use orbyn::output::Format;
use orbyn::store::Store;

use crate::cli::args::DepsAction;
use crate::cli::{begin_audit, finish_audit_result, open_store, resolve_asset};

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

/// Handle `orbyn deps <action>`.
pub(crate) async fn deps(config: &Config, action: DepsAction) -> Result<()> {
    let store = open_store(config).await?;
    deps_actions(store.as_ref(), action).await
}

async fn deps_actions(store: &dyn Store, action: DepsAction) -> Result<()> {
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

/// Handle `orbyn graph`.
pub(crate) async fn graph(
    config: &Config,
    format: Format,
    mermaid: bool,
    asset: Option<String>,
) -> Result<()> {
    let store = open_store(config).await?;
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
    Ok(())
}
