//! Migration plan workflows (`orbyn plan`): assemble the snapshot, run
//! the readiness and strategy models, match target instance types and
//! persist the plan as an audited artifact.

use anyhow::Result;
use chrono::Utc;

use orbyn::assessment::{run_assessment, AssessmentInput, AssessmentReport};
use orbyn::domain::{
    BlockerSeverity, MigrationAssumption, MigrationBlocker, MigrationPlan, MigrationTarget,
    PlanProvenance,
};
use orbyn::output::{ApplicationDetail, PlanOutcome};
use orbyn::planning::{self, PlanInput};
use orbyn::store::Store;
use orbyn::waves::{plan_waves, WavePlan};

use crate::app::applications;
use crate::app::{begin_audit, finish_audit_result};

/// A requested target provider: the label for the report, and the
/// catalog for instance-type matching (`None` when Orbyn has no catalog
/// for that provider — recommendations stay honest instead of guessed).
pub(crate) struct TargetSpec {
    pub label: String,
    pub provider: Option<orbyn::sku::Provider>,
}

/// Plan one application and persist the artifact.
pub(crate) async fn plan(
    store: &dyn Store,
    key: &str,
    target: Option<TargetSpec>,
) -> Result<PlanOutcome> {
    let detail = applications::show(store, key).await?;
    let audit = begin_audit(
        store,
        "plan.create",
        &detail.application.name,
        Some("migration plan"),
    )
    .await?;
    let result: Result<PlanOutcome> = async {
        let input = crate::app::assessment::assessment_input(store).await?;
        let report = run_assessment(&input);
        let waves = wave_plan(store, &input, &report).await?;
        let outcome = build(&detail, &input, &report, &waves, target.as_ref()).await?;
        store.save_plan(outcome.plan.clone()).await?;
        eprintln!(
            "Plan {} saved for '{}': {} (readiness {}/100).",
            outcome.plan.id,
            detail.application.name,
            outcome.plan.recommendation.strategy,
            outcome.plan.readiness,
        );
        Ok(outcome)
    }
    .await;
    finish_audit_result(store, audit, result).await
}

/// Plan every application against one shared snapshot and wave plan.
pub(crate) async fn plan_all(
    store: &dyn Store,
    target: Option<TargetSpec>,
) -> Result<(Vec<PlanOutcome>, Vec<String>)> {
    let audit = begin_audit(store, "plan.create", "all", Some("migration plans")).await?;
    let result: Result<(Vec<PlanOutcome>, Vec<String>)> = async {
        let input = crate::app::assessment::assessment_input(store).await?;
        let report = run_assessment(&input);
        let waves = wave_plan(store, &input, &report).await?;
        let mut outcomes = Vec::new();
        for application in store.list_applications().await? {
            let detail = applications::show(store, &application.id).await?;
            let outcome = build(&detail, &input, &report, &waves, target.as_ref()).await?;
            store.save_plan(outcome.plan.clone()).await?;
            outcomes.push(outcome);
        }
        eprintln!("Plans: {} generated.", outcomes.len());
        Ok((outcomes, waves.warnings.clone()))
    }
    .await;
    finish_audit_result(store, audit, result).await
}

/// The wave plan over persisted applications (the same planning the
/// `waves` command runs), so plan wave assignments never drift from it.
async fn wave_plan(
    store: &dyn Store,
    input: &AssessmentInput,
    report: &AssessmentReport,
) -> Result<WavePlan> {
    let mut wave_report = report.clone();
    let persisted = applications::wave_units(store).await?;
    if !persisted.is_empty() {
        wave_report.application_groups = persisted;
    }
    Ok(plan_waves(&wave_report, input, &[], &[]))
}

/// The wave an application's members land in, with the reasons of its
/// first member (a unit migrates together, so the reasons are shared).
fn wave_assignment(waves: &WavePlan, detail: &ApplicationDetail) -> (Option<u8>, Vec<String>) {
    for wave in &waves.waves {
        for asset in &wave.assets {
            if detail.members.iter().any(|m| m.asset_id == asset.asset_id) {
                return (Some(wave.index as u8), asset.reasons.clone());
            }
        }
    }
    (None, Vec::new())
}

/// Assemble one application's plan from the snapshot.
async fn build(
    detail: &ApplicationDetail,
    input: &AssessmentInput,
    report: &AssessmentReport,
    waves: &WavePlan,
    target: Option<&TargetSpec>,
) -> Result<PlanOutcome> {
    let members = &detail.members;
    let plan_input = PlanInput {
        application: &detail.application,
        members,
        assets: &input.assets,
        services: &input.services,
        dependencies: &input.dependencies,
        connections: &input.connections,
        capacities: &input.capacities,
        findings: &report.findings,
        asset_scores: &report.asset_scores,
        metric_windows: &input.metric_windows,
    };
    let readiness = planning::readiness::score(&plan_input);
    let recommendation = planning::strategy::recommend(&plan_input, readiness.score);

    // Targets: the sizing baseline is the capacity allocation; the
    // instance type is the smallest catalog fit for that baseline.
    // ponytail: allocation ignores utilization — the rs.* findings flag
    // over-provisioning, but extracting a shrunken baseline from their
    // messages is fragile; application-level target matching is v1.3.
    let mut targets = Vec::new();
    let mut assumptions = Vec::new();
    for member in members {
        let capacity = plan_input.capacity(&member.asset_id);
        let cores = capacity.and_then(|c| c.cpu_cores);
        let ram_mb = capacity.and_then(|c| c.ram_total_mb);
        if cores.is_none() || ram_mb.is_none() {
            assumptions.push(MigrationAssumption {
                assumption: "sizing baseline".into(),
                detail: format!(
                    "{} has no capacity data; no sizing baseline",
                    member.asset_id
                ),
            });
        } else if plan_input.window(&member.asset_id).is_none() {
            assumptions.push(MigrationAssumption {
                assumption: "sizing baseline".into(),
                detail: format!(
                    "{} sized from allocation; no utilization samples to verify",
                    member.asset_id
                ),
            });
        }
        let mut instance_type = None;
        if let (Some(t), Some(c), Some(r)) = (&target, cores, ram_mb) {
            if let Some(provider) = t.provider {
                instance_type = orbyn::sku::match_skus(provider, c, r)
                    .first()
                    .map(|s| s.name.to_string());
            }
        }
        // A provider without a catalog is a fact of the report, independent
        // of whether the sizing baseline exists.
        if let Some(t) = target {
            if t.provider.is_none() {
                assumptions.push(MigrationAssumption {
                    assumption: "instance type".into(),
                    detail: format!("no {} catalog; instance type not calculated", t.label),
                });
            }
        }
        targets.push(MigrationTarget {
            asset_id: member.asset_id.clone(),
            cores,
            ram_mb,
            provider: target.map(|t| t.label.clone()),
            instance_type,
        });
    }

    // Blockers: the readiness concerns, restated as conditions to
    // resolve with a severity.
    let blockers: Vec<MigrationBlocker> = readiness
        .factors
        .iter()
        .map(|f| MigrationBlocker {
            severity: blocker_severity(&f.factor, &f.evidence),
            factor: f.factor.clone(),
            message: blocker_message(&f.factor).into(),
            evidence: f.evidence.clone(),
        })
        .collect();

    let (wave, wave_reasons) = wave_assignment(waves, detail);

    let last_seen = input
        .assets
        .iter()
        .map(|a| a.last_seen)
        .max()
        .unwrap_or_else(Utc::now);
    let plan = MigrationPlan {
        id: uuid::Uuid::new_v4().to_string(),
        application_id: detail.application.id.clone(),
        created_at: Utc::now(),
        provenance: PlanProvenance {
            assets: input.assets.len(),
            last_seen,
            rules_version: report.rules_version.clone(),
            inference_version: orbyn::applications::INFERENCE_VERSION.to_string(),
            readiness_version: planning::readiness::READINESS_VERSION.to_string(),
            strategy_version: planning::strategy::STRATEGY_VERSION.to_string(),
            sku_catalog_version: orbyn::sku::CATALOG_VERSION.to_string(),
        },
        readiness: readiness.score,
        readiness_factors: readiness.factors,
        recommendation,
        wave,
        targets,
        blockers,
        assumptions,
    };
    Ok(PlanOutcome {
        application_name: detail.application.name.clone(),
        plan,
        wave_reasons,
    })
}

/// A missing OS is a hard blocker: the workload cannot be identified.
/// Coupling and EOL concerns warn; the rest is informational.
fn blocker_severity(factor: &str, evidence: &[String]) -> BlockerSeverity {
    match factor {
        "inventory-completeness" if evidence.iter().any(|e| e.contains("no OS information")) => {
            BlockerSeverity::Blocker
        }
        "unconfirmed-dependencies" | "external-dependencies" | "unsupported-software" => {
            BlockerSeverity::Warning
        }
        _ => BlockerSeverity::Info,
    }
}

/// The condition to resolve, per readiness factor.
fn blocker_message(factor: &str) -> &'static str {
    match factor {
        "inventory-completeness" => "inventory gaps must be closed before planning is trustworthy",
        "ownership-metadata" => "no owner assigned; someone must own the migration",
        "capacity-information" => "missing capacity data; no sizing baseline",
        "metrics-window-quality" => {
            "utilization samples missing or weak; right-sizing unverifiable"
        }
        "application-confidence" => "application grouping is weakly evidenced",
        "dependency-confidence" => "dependency edges are weakly evidenced",
        "unconfirmed-dependencies" => "unconfirmed dependency edges; confirm before migrating",
        "external-dependencies" => "endpoints outside the inventory; coupling not fully known",
        "unsupported-software" => "EOL software needs an upgrade path",
        _ => "readiness concern",
    }
}
