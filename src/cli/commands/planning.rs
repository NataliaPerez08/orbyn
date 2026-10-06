//! Handler for `orbyn plan`. Translation from the parsed CLI arguments
//! into the planning workflows; the workflows themselves are in
//! `app::planning`.

use anyhow::{anyhow, Result};

use orbyn::config::Config;
use orbyn::output::Format;

use crate::app::open_store;
use crate::cli::args::PlanTarget;

/// Handle `orbyn plan`.
pub(crate) async fn plan(
    config: &Config,
    application: Option<String>,
    all: bool,
    target: Option<PlanTarget>,
    explain: bool,
    format: Format,
) -> Result<()> {
    let store = open_store(config).await?;
    let target = target.map(|t| {
        let (label, provider) = match t {
            PlanTarget::Aws => ("aws", Some(orbyn::sku::Provider::Aws)),
            PlanTarget::Azure => ("azure", Some(orbyn::sku::Provider::Azure)),
            PlanTarget::Gcp => ("gcp", Some(orbyn::sku::Provider::Gcp)),
            // No curated catalog: instance types stay NOT_CALCULATED.
            PlanTarget::Huawei => ("huawei", None),
            PlanTarget::Openstack => ("openstack", None),
        };
        crate::app::planning::TargetSpec {
            label: label.into(),
            provider,
        }
    });
    if all {
        let (outcomes, warnings) = crate::app::planning::plan_all(store.as_ref(), target).await?;
        print!(
            "{}",
            orbyn::output::migration_plans(&outcomes, &warnings, format)
        );
    } else {
        let key = application.ok_or_else(|| anyhow!("specify an application or pass --all"))?;
        let outcome = crate::app::planning::plan(store.as_ref(), &key, target).await?;
        let assets = store.list_assets().await?;
        print!(
            "{}",
            orbyn::output::migration_plan(&outcome, &assets, explain, format)
        );
    }
    Ok(())
}
