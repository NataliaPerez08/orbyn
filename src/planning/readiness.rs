//! Readiness scoring (v1.2).
//!
//! Readiness answers "how safe is it to migrate this application now?" —
//! deliberately separate from the assessment's complexity score. It
//! starts at 100 and subtracts explainable penalties: every factor emits
//! `{factor, delta, evidence}` so the number is never a mystery.
//!
//! The model is a pure function over a [`PlanInput`] snapshot.

use crate::assessment::external_endpoints;
use crate::domain::ReadinessFactor;
use crate::metrics::SampleConfidence;

use super::PlanInput;

/// Version of the readiness model; stamped into plan provenance.
pub const READINESS_VERSION: &str = "readiness/v1";

/// The readiness result: the score plus every factor that moved it.
#[derive(Debug, Clone, PartialEq)]
pub struct Readiness {
    /// 0-100: 100 = no readiness concerns observed.
    pub score: u8,
    /// Only factors with a nonzero delta are listed.
    pub factors: Vec<ReadinessFactor>,
}

/// Score the application's migration readiness.
pub fn score(input: &PlanInput) -> Readiness {
    let mut factors: Vec<ReadinessFactor> = Vec::new();
    let mut total: i32 = 100;

    let mut penalize = |factor: &str, delta: i32, evidence: Vec<String>| {
        if delta == 0 {
            return;
        }
        total += delta;
        factors.push(ReadinessFactor {
            factor: factor.into(),
            delta: delta as i8,
            evidence,
        });
    };

    // Inventory completeness: OS and hostname are the minimum facts to
    // plan a migration around.
    let mut evidence = Vec::new();
    let mut delta = 0i32;
    for asset in input.member_assets() {
        if asset.os_name.is_none() {
            delta -= 3;
            evidence.push(format!("{}: no OS information", asset.id));
        }
        if asset.hostname.is_none() {
            delta -= 2;
            evidence.push(format!("{}: no hostname", asset.id));
        }
    }
    penalize("inventory-completeness", delta.max(-20), evidence);

    // Ownership metadata: someone must own the migration.
    let mut evidence = Vec::new();
    let mut delta = 0i32;
    for asset in input.member_assets() {
        if asset.owner.is_none() {
            delta -= 2;
            evidence.push(format!("{}: no owner", asset.id));
        }
        if asset.environment.is_none() {
            delta -= 1;
            evidence.push(format!("{}: no environment", asset.id));
        }
    }
    penalize("ownership-metadata", delta.max(-10), evidence);

    // Capacity information: without allocation there is no sizing input.
    let evidence: Vec<String> = input
        .member_assets()
        .iter()
        .filter(|a| input.capacity(&a.id).is_none())
        .map(|a| format!("{}: no capacity data", a.id))
        .collect();
    penalize(
        "capacity-information",
        -(evidence.len() as i32 * 4).min(16),
        evidence,
    );

    // Metrics window quality: right-sizing needs trustworthy samples.
    let mut evidence = Vec::new();
    let mut delta = 0i32;
    for asset in input.member_assets() {
        match input.window(&asset.id).map(|w| w.stats.confidence) {
            None => {
                delta -= 4;
                evidence.push(format!("{}: no utilization samples", asset.id));
            }
            Some(SampleConfidence::Low) => {
                delta -= 2;
                evidence.push(format!("{}: low sample confidence", asset.id));
            }
            Some(SampleConfidence::Medium) => {
                delta -= 1;
                evidence.push(format!("{}: medium sample confidence", asset.id));
            }
            Some(SampleConfidence::High) => {}
        }
    }
    penalize("metrics-window-quality", delta.max(-16), evidence);

    // Application confidence: how well-evidenced the grouping itself is.
    let gap = 1.0 - input.application.confidence;
    if gap > f32::EPSILON {
        penalize(
            "application-confidence",
            -(gap * 20.0).round() as i32,
            vec![format!(
                "application confidence {:.0}%",
                input.application.confidence * 100.0
            )],
        );
    }

    // Dependency confidence: edges the plan relies on.
    let touching: Vec<&crate::domain::Dependency> = input
        .dependencies
        .iter()
        .filter(|d| input.is_member(&d.source_asset_id) || input.is_member(&d.target_asset_id))
        .collect();
    if !touching.is_empty() {
        let avg = touching.iter().map(|d| d.confidence).sum::<f32>() / touching.len() as f32;
        let gap = 1.0 - avg;
        if gap > f32::EPSILON {
            penalize(
                "dependency-confidence",
                -(gap * 20.0).round() as i32,
                vec![format!(
                    "average edge confidence {:.0}% over {} edge(s)",
                    avg * 100.0,
                    touching.len()
                )],
            );
        }
    }

    // Unconfirmed dependencies: guesses the plan would act on.
    let evidence: Vec<String> = touching
        .iter()
        .filter(|d| !d.confirmed)
        .map(|d| {
            format!(
                "{} -> {}:{} unconfirmed",
                d.source_asset_id, d.target_asset_id, d.port
            )
        })
        .collect();
    penalize(
        "unconfirmed-dependencies",
        -(evidence.len() as i32 * 3).min(15),
        evidence,
    );

    // External dependencies: endpoints outside the managed inventory.
    let external = external_endpoints(input.assets, input.connections);
    let mut evidence = Vec::new();
    let mut delta = 0i32;
    for asset in input.member_assets() {
        if let Some(endpoints) = external.get(&asset.id) {
            if !endpoints.is_empty() {
                delta -= 2;
                evidence.push(format!(
                    "{}: {} external endpoint(s)",
                    asset.id,
                    endpoints.len()
                ));
            }
        }
    }
    penalize("external-dependencies", delta.max(-8), evidence);

    // Unsupported software: EOL operating systems need an upgrade path
    // before anything moves.
    let evidence: Vec<String> = input
        .member_findings("os.eol")
        .iter()
        .map(|f| f.message.clone())
        .collect();
    penalize(
        "unsupported-software",
        -(evidence.len() as i32 * 5).min(15),
        evidence,
    );

    Readiness {
        score: total.clamp(0, 100) as u8,
        factors,
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;

    #[test]
    fn complete_inventory_scores_100_with_no_factors() {
        let fx = testkit::complete_application(2);
        let r = score(&fx.input());
        assert_eq!(r.score, 100);
        assert!(r.factors.is_empty(), "{:?}", r.factors);
    }

    #[test]
    fn missing_facts_subtract_explainable_penalties() {
        // One of two members lacks OS, owner, environment, capacity and
        // samples: -3 -2 -1 -4 -4 = -14.
        let mut fx = testkit::complete_application(2);
        fx.assets[1].os_name = None;
        fx.assets[1].owner = None;
        fx.assets[1].environment = None;
        fx.capacities.truncate(1);
        fx.metric_windows.truncate(1);
        let r = score(&fx.input());
        assert_eq!(r.score, 86, "{:?}", r.factors);
        for factor in [
            "inventory-completeness",
            "ownership-metadata",
            "capacity-information",
            "metrics-window-quality",
        ] {
            assert!(
                r.factors.iter().any(|f| f.factor == factor),
                "missing factor {factor}: {:?}",
                r.factors
            );
        }
    }

    #[test]
    fn weak_evidence_and_unconfirmed_edges_penalize() {
        let mut fx = testkit::complete_application(2);
        fx.application.confidence = 0.5; // -10
        fx.dependencies[0].confidence = 0.5; // -10
        fx.dependencies[0].confirmed = false; // -3
        let r = score(&fx.input());
        assert_eq!(r.score, 77, "{:?}", r.factors);
        assert!(r
            .factors
            .iter()
            .any(|f| f.factor == "application-confidence"));
        assert!(r
            .factors
            .iter()
            .any(|f| f.factor == "dependency-confidence"));
        assert!(r
            .factors
            .iter()
            .any(|f| f.factor == "unconfirmed-dependencies"));
    }

    #[test]
    fn score_never_falls_below_zero() {
        let mut fx = testkit::complete_application(3);
        for asset in fx.assets.iter_mut() {
            asset.os_name = None;
            asset.hostname = None;
            asset.owner = None;
            asset.environment = None;
        }
        fx.capacities.clear();
        fx.metric_windows.clear();
        fx.application.confidence = 0.0;
        for dep in fx.dependencies.iter_mut() {
            dep.confidence = 0.0;
            dep.confirmed = false;
        }
        fx.connections
            .push(testkit::connection(&fx.assets[0].id, "203.0.113.9", 443));
        for asset in &fx.assets {
            fx.findings
                .push(testkit::finding("os.eol", &asset.id, "EOL OS"));
        }
        let r = score(&fx.input());
        assert_eq!(r.score, 0, "{:?}", r.factors);
    }
}
