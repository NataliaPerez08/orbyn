//! Handlers for `orbyn plan` and `orbyn bundle`. Translation from the
//! parsed CLI arguments into the planning workflows; the workflows
//! themselves are in `app::planning`.

use anyhow::{anyhow, Result};

use orbyn::assessment::run_assessment;
use orbyn::config::Config;
use orbyn::output::Format;

use crate::app::open_store;
use crate::cli::args::PlanTarget;

/// Map a CLI target to its label and SKU catalog (`None` when Orbyn has
/// no catalog for that provider).
fn map_target(target: Option<PlanTarget>) -> Option<crate::app::planning::TargetSpec> {
    target.map(|t| {
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
    })
}

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
    let target = map_target(target);
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

/// Handle `orbyn bundle`: write the self-contained migration handoff
/// directory. Generation is read-only — nothing is persisted or audited.
pub(crate) async fn bundle(
    config: &Config,
    application: String,
    target: Option<PlanTarget>,
) -> Result<()> {
    let store = open_store(config).await?;
    let target = map_target(target);
    let detail = crate::app::applications::show(store.as_ref(), &application).await?;
    let outcome = crate::app::planning::generate(store.as_ref(), &detail, target.as_ref()).await?;
    let assets = store.list_assets().await?;
    let deps = store.list_dependencies().await?;
    let report = run_assessment(&crate::app::assessment::assessment_input(store.as_ref()).await?);

    let dir = format!("{}-migration", detail.application.name);
    std::fs::create_dir_all(&dir)?;
    let files: Vec<(&str, String)> = vec![
        (
            "inventory.json",
            orbyn::output::assets(&assets, Format::Json),
        ),
        ("inventory.csv", orbyn::output::assets(&assets, Format::Csv)),
        (
            "applications.json",
            orbyn::output::application_detail(&detail, &assets, Format::Json),
        ),
        (
            "dependencies.json",
            orbyn::output::dependencies(&deps, &assets, Format::Json),
        ),
        ("dependencies.mmd", orbyn::output::mermaid(&deps, &assets)),
        (
            "assessment.json",
            orbyn::output::report(&report, Format::Json),
        ),
        ("sizing.json", orbyn::output::sizing(&outcome)),
        (
            "migration-plan.json",
            orbyn::output::migration_plan(&outcome, &assets, true, Format::Json),
        ),
        (
            "migration-plan.md",
            orbyn::output::migration_plan(&outcome, &assets, true, Format::Table),
        ),
    ];
    for (name, content) in &files {
        std::fs::write(format!("{dir}/{name}"), content)?;
    }
    let mut names: Vec<String> = files.iter().map(|(n, _)| (*n).to_string()).collect();
    names.push("manifest.json".into());
    std::fs::write(
        format!("{dir}/manifest.json"),
        orbyn::output::bundle_manifest(&outcome, &names),
    )?;
    eprintln!("Bundle written to {dir}/ ({} files).", names.len());
    Ok(())
}
