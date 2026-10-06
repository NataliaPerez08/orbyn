//! Handlers for `orbyn targets compare|recommend` and `orbyn catalog`.
//! Read-only workflows; the logic lives in `app::targets`.

use anyhow::{anyhow, Result};

use orbyn::config::Config;

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

/// Handle `orbyn catalog update`: report the embedded catalog status.
pub(crate) fn catalog(action: Option<CatalogAction>) -> Result<()> {
    match action {
        Some(CatalogAction::Update) | None => {
            print!(
                "{}",
                orbyn::output::catalog_status(orbyn::targets::catalogs())
            );
            Ok(())
        }
    }
}
