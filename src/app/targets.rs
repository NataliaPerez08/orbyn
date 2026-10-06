//! Target intelligence workflows (`orbyn targets`): compare every
//! provider catalog for one application and recommend one, with the
//! reasoning exposed. Read-only — nothing is persisted or audited.

use anyhow::Result;

use orbyn::output::{TargetComparison, TargetRecommendation, TargetVersions};
use orbyn::planning::{readiness, strategy, PlanInput};
use orbyn::store::Store;
use orbyn::targets::cost::{self, CostEstimate};
use orbyn::targets::matching;

use crate::app::applications;
use crate::app::planning;

/// Compare every catalog provider for one application: fit, cost and
/// the version stamps that make the comparison reproducible.
pub(crate) async fn compare(store: &dyn Store, key: &str) -> Result<TargetComparison> {
    let detail = applications::show(store, key).await?;
    let (input, report) = planning::snapshot(store).await?;
    let plan_input =
        PlanInput::from_snapshot(&detail.application, &detail.members, &input, &report);
    let readiness = readiness::score(&plan_input);
    let recommendation = strategy::recommend(&plan_input, readiness.score);
    let fits = matching::fit(&plan_input, recommendation.strategy);
    let costs: Vec<CostEstimate> = fits.iter().map(|f| cost::cost(f, &plan_input)).collect();
    let waves = planning::wave_plan(store, &input, &report).await?;
    let (wave, _) = planning::wave_assignment(&waves, &detail);

    Ok(TargetComparison {
        application_name: detail.application.name.clone(),
        strategy: recommendation.strategy,
        readiness: readiness.score,
        wave,
        fits,
        costs,
        versions: TargetVersions {
            rules_version: report.rules_version.clone(),
            inference_version: orbyn::applications::INFERENCE_VERSION.to_string(),
            readiness_version: readiness::READINESS_VERSION.to_string(),
            strategy_version: strategy::STRATEGY_VERSION.to_string(),
            target_fit_version: matching::TARGET_FIT_VERSION.to_string(),
            cost_model_version: cost::COST_MODEL_VERSION.to_string(),
        },
    })
}

/// Recommend one provider plus an alternative, with the "why X instead
/// of Y" evidence. Price never determines the recommendation — only
/// fit-relevant inputs do; prices are reported as information.
pub(crate) async fn recommend(store: &dyn Store, key: &str) -> Result<TargetRecommendation> {
    let comparison = compare(store, key).await?;
    let (recommended, alternative, why) = rank(&comparison);
    Ok(TargetRecommendation {
        comparison,
        recommended,
        alternative,
        why,
    })
}

/// Rank providers by fit (score first, then name for determinism) and
/// explain the difference between the top two.
fn rank(comparison: &TargetComparison) -> (Option<usize>, Option<usize>, Vec<String>) {
    let mut scored: Vec<usize> = (0..comparison.fits.len())
        .filter(|i| comparison.fits[*i].score.is_some())
        .collect();
    scored.sort_by(|a, b| {
        let sa = comparison.fits[*a].score.unwrap();
        let sb = comparison.fits[*b].score.unwrap();
        sb.cmp(&sa).then_with(|| {
            comparison.fits[*a]
                .provider
                .cmp(&comparison.fits[*b].provider)
        })
    });
    if scored.is_empty() {
        return (
            None,
            None,
            vec![format!(
                "strategy is {}: no provider fit is calculated",
                comparison.strategy.as_str()
            )],
        );
    }
    let recommended = scored[0];
    let alternative = scored.get(1).copied();

    let mut why = Vec::new();
    if let Some(alt) = alternative {
        let rec = &comparison.fits[recommended];
        let other = &comparison.fits[alt];
        for reason in &rec.reasons {
            let counterpart = other
                .reasons
                .iter()
                .find(|r| r.input == reason.input && r.delta != reason.delta);
            if let Some(c) = counterpart {
                why.push(format!(
                    "{}: {} scores {} ({}) vs {} ({})",
                    reason.input,
                    rec.provider,
                    reason.delta,
                    reason.detail,
                    other.provider,
                    c.detail
                ));
            }
        }
        if why.is_empty() {
            why.push(format!(
                "no fit-relevant difference between {} and {}; pricing, region and existing tooling should decide",
                rec.provider, other.provider
            ));
        }
    } else {
        why.push("only one provider has a catalog; no alternative to compare".into());
    }
    (Some(recommended), alternative, why)
}
