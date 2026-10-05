//! Handler for the per-asset utilization metrics view.

use anyhow::Result;

use orbyn::config::Config;
use orbyn::output::Format;

use crate::cli::{open_store, resolve_asset};

pub(crate) async fn metrics(
    config: &Config,
    asset: String,
    samples: Option<usize>,
    format: Format,
) -> Result<()> {
    let store = open_store(config).await?;
    let asset = resolve_asset(store.as_ref(), &asset).await?;
    let collected = store.list_metric_samples(&asset.id, samples).await?;
    let stats = orbyn::metrics::summarize(&collected);
    print!("{}", orbyn::output::metrics(stats.as_ref(), format));
    Ok(())
}
