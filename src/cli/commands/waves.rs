//! Handler for migration wave planning.

use anyhow::Result;

use orbyn::assessment::run_assessment;
use orbyn::config::Config;
use orbyn::output::Format;

use crate::app::assessment::assessment_input;
use crate::app::open_store;

pub(crate) async fn waves(
    config: &Config,
    format: Format,
    pins: Vec<(String, usize)>,
    excludes: Vec<String>,
) -> Result<()> {
    let store = open_store(config).await?;
    let input = assessment_input(store.as_ref()).await?;
    let mut report = run_assessment(&input);
    // Persisted applications are the planning units when present;
    // otherwise the ephemeral groups the engine computed are used.
    let persisted = crate::app::applications::wave_units(store.as_ref()).await?;
    if !persisted.is_empty() {
        report.application_groups = persisted;
    }
    print!(
        "{}",
        orbyn::waves::render(&report, &input, &pins, &excludes, format)
    );
    Ok(())
}
