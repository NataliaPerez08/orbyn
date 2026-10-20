//! Handlers for `orbyn targets compare|recommend` and `orbyn catalog`.
//! Read-only workflows; the logic lives in `app::targets`.

use anyhow::{anyhow, Context, Result};

use orbyn::config::Config;
use orbyn::integrations::cloud::CurlClient;
use orbyn::targets::{CatalogManifest, CatalogUpdate};

use crate::app::open_store;
use crate::cli::args::{CatalogAction, TargetsAction};

/// Handle `orbyn targets`.
pub(crate) async fn targets(config: &Config, action: Option<TargetsAction>) -> Result<()> {
    let action = action.ok_or_else(|| anyhow!("specify compare or recommend"))?;
    let store = open_store(config).await?;
    match action {
        TargetsAction::Compare {
            application,
            format,
        } => {
            let comparison = crate::app::targets::compare(store.as_ref(), &application).await?;
            print!("{}", orbyn::output::targets_compare(&comparison, format));
        }
        TargetsAction::Recommend {
            application,
            format,
        } => {
            let recommendation =
                crate::app::targets::recommend(store.as_ref(), &application).await?;
            print!(
                "{}",
                orbyn::output::targets_recommend(&recommendation, format)
            );
        }
    }
    Ok(())
}

/// Handle `orbyn catalog`: status (default), install, update.
pub(crate) async fn catalog(action: Option<CatalogAction>) -> Result<()> {
    match action {
        None | Some(CatalogAction::Status) => {
            print!(
                "{}",
                orbyn::output::catalog_status(
                    orbyn::targets::catalogs(),
                    &orbyn::targets::catalog_dir()
                )
            );
            Ok(())
        }
        Some(CatalogAction::Install { file }) => {
            let raw = std::fs::read_to_string(&file)
                .with_context(|| format!("cannot read catalog package '{file}'"))?;
            let dir = orbyn::targets::catalog_dir();
            let installed = orbyn::targets::install_catalog(&raw, &dir)
                .map_err(|e| anyhow!("invalid catalog package '{file}': {e}"))?;
            print!(
                "Installed {} {} (retrieved {}) into {}\nEffective on the next orbyn run.\n",
                installed.provider,
                installed.catalog_version,
                installed.retrieved_at,
                dir.join(format!("{}.json", installed.provider)).display()
            );
            Ok(())
        }
        Some(CatalogAction::Update { url }) => {
            let base = url.trim_end_matches('/');
            let client = CurlClient::new();
            let raw = client
                .get(&format!("{base}/manifest.json"), &[])
                .await
                .context("cannot fetch the catalog manifest")?;
            let manifest: CatalogManifest =
                serde_json::from_str(&raw).context("invalid catalog manifest")?;
            let dir = orbyn::targets::catalog_dir();
            let mut installed = 0usize;
            for decision in orbyn::targets::update_decisions(&manifest, orbyn::targets::catalogs())
            {
                match decision {
                    CatalogUpdate::Install(entry) => {
                        let raw = client
                            .get(&format!("{base}/{}", entry.file), &[])
                            .await
                            .with_context(|| format!("cannot fetch {}", entry.file))?;
                        match orbyn::targets::install_catalog(&raw, &dir) {
                            Ok(c) => {
                                installed += 1;
                                println!(
                                    "{}: installed {} (retrieved {})",
                                    c.provider, c.catalog_version, c.retrieved_at
                                );
                            }
                            Err(e) => println!("{}: skipped invalid package: {e}", entry.provider),
                        }
                    }
                    CatalogUpdate::UpToDate {
                        provider,
                        have,
                        offered,
                    } => println!("{provider}: up to date ({have} >= {offered})"),
                }
            }
            if installed > 0 {
                println!("Effective on the next orbyn run.");
            }
            Ok(())
        }
    }
}
