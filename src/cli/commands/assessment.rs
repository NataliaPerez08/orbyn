//! Handler for the migration assessment command.

use anyhow::Result;

use orbyn::assessment::run_assessment;
use orbyn::config::Config;
use orbyn::output::Format;

use crate::app::assessment::assessment_input;
use crate::app::open_store;

pub(crate) async fn assess(config: &Config, format: Format, rules: bool) -> Result<()> {
    let store = open_store(config).await?;
    if rules {
        print!(
            "{}",
            orbyn::output::rules_catalog(
                orbyn::assessment::rules::catalog(),
                orbyn::assessment::RULES_VERSION
            )
        );
    } else {
        let input = assessment_input(store.as_ref()).await?;
        let report = run_assessment(&input);
        print!("{}", orbyn::output::report(&report, format));
    }
    Ok(())
}
