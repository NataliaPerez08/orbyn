//! Handler for migration wave planning.

use anyhow::Result;

use orbyn::assessment::run_assessment;
use orbyn::config::Config;
use orbyn::output::Format;

use crate::cli::{assessment_input, open_store};

pub(crate) async fn waves(
    config: &Config,
    format: Format,
    pins: Vec<(String, usize)>,
    excludes: Vec<String>,
) -> Result<()> {
    let store = open_store(config).await?;
    let input = assessment_input(store.as_ref()).await?;
    let report = run_assessment(&input);
    print!(
        "{}",
        orbyn::waves::render(&report, &input, &pins, &excludes, format)
    );
    Ok(())
}
