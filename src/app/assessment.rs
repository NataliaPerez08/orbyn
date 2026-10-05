//! Assessment workflows: gathering the inventory snapshot the assessment
//! engine and wave planner evaluate.

use anyhow::Result;

use orbyn::assessment::{AssessmentInput, AssetWindow};
use orbyn::domain::MetricSample;
use orbyn::store::Store;

/// Gather the full inventory snapshot the assessment engine evaluates.
pub(crate) async fn assessment_input(store: &dyn Store) -> Result<AssessmentInput> {
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
