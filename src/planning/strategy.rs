//! Strategy recommendation (v1.2).
//!
//! Deterministic rules map the snapshot to one of REHOST | REPLATFORM |
//! REFACTOR | RETAIN | RETIRE, or UNKNOWN when the evidence is
//! insufficient — never fabricated certainty. The first matching rule
//! wins; every decision carries its confidence, rationale, evidence and
//! the alternatives that were considered.
//!
//! Pure functions over a [`PlanInput`] snapshot, like the assessment
//! rules: the store is never read here.

use crate::assessment::external_endpoints;
use crate::domain::{MigrationRecommendation, MigrationStrategy};

use super::PlanInput;

/// Version of the strategy rules; stamped into plan provenance.
pub const STRATEGY_VERSION: &str = "strategy/v1";

/// Recommend a migration strategy for an application.
pub fn recommend(input: &PlanInput, readiness: u8) -> MigrationRecommendation {
    let members = input.member_assets();

    // 1. Not enough inventory evidence to decide anything.
    let missing_os = members.iter().filter(|a| a.os_name.is_none()).count();
    if !members.is_empty() && missing_os * 2 > members.len() {
        return MigrationRecommendation {
            strategy: MigrationStrategy::Unknown,
            confidence: 0.2,
            rationale: "most member assets lack OS information; collect inventory first".into(),
            evidence: vec![format!(
                "{missing_os} of {} members have no OS data",
                members.len()
            )],
            alternatives: Vec::new(),
        };
    }

    // 2. No observed activity: a retire candidate, stated with low
    // confidence so it is verified, never executed blindly.
    let has_services = input.services.iter().any(|s| input.is_member(&s.asset_id));
    let has_deps = input
        .dependencies
        .iter()
        .any(|d| input.is_member(&d.source_asset_id) || input.is_member(&d.target_asset_id));
    let has_samples = input
        .metric_windows
        .iter()
        .any(|w| input.is_member(&w.asset_id));
    if !has_services && !has_deps && !has_samples {
        return MigrationRecommendation {
            strategy: MigrationStrategy::Retire,
            confidence: 0.3,
            rationale: "no services, dependencies or utilization samples observed".into(),
            evidence: vec![
                "0 listening services on members".into(),
                "0 dependency edges touching members".into(),
                "0 utilization samples".into(),
            ],
            alternatives: vec![MigrationStrategy::Retain],
        };
    }

    // 3. Network gear stays: it is infrastructure, not a workload.
    let network: Vec<String> = members
        .iter()
        .filter(|a| a.device_class.as_deref() == Some("network"))
        .map(|a| a.id.clone())
        .collect();
    if !network.is_empty() {
        return MigrationRecommendation {
            strategy: MigrationStrategy::Retain,
            confidence: 0.6,
            rationale: "network infrastructure is typically retained, not migrated".into(),
            evidence: vec![format!("network members: {}", network.join(", "))],
            alternatives: vec![MigrationStrategy::Rehost],
        };
    }

    // 4. EOL OS: the migration includes an OS upgrade — replatform.
    let eol: Vec<String> = input
        .member_findings("os.eol")
        .iter()
        .map(|f| f.message.clone())
        .collect();
    if !eol.is_empty() {
        return MigrationRecommendation {
            strategy: MigrationStrategy::Replatform,
            confidence: 0.6,
            rationale: "EOL operating systems require an upgrade during migration".into(),
            evidence: eol,
            alternatives: vec![MigrationStrategy::Rehost, MigrationStrategy::Refactor],
        };
    }

    // 5. High complexity with external coupling needs rework first.
    // 50 is the assessment engine's high-complexity band boundary.
    let high_complexity = members.iter().any(|a| {
        input
            .asset_scores
            .iter()
            .any(|s| s.asset_id == a.id && s.score >= 50)
    });
    let external = external_endpoints(input.assets, input.connections);
    let coupled = members
        .iter()
        .any(|a| external.get(&a.id).is_some_and(|e| !e.is_empty()));
    if high_complexity && coupled {
        return MigrationRecommendation {
            strategy: MigrationStrategy::Refactor,
            confidence: 0.5,
            rationale: "high member complexity plus external coupling: rework before moving".into(),
            evidence: vec![
                "at least one member scores high complexity (>= 50/100)".into(),
                "at least one member talks to endpoints outside the inventory".into(),
            ],
            alternatives: vec![MigrationStrategy::Replatform, MigrationStrategy::Rehost],
        };
    }

    // 6. Default: a standard workload — lift and shift, with confidence
    // scaled by readiness (readiness 80 -> 0.9).
    MigrationRecommendation {
        strategy: MigrationStrategy::Rehost,
        confidence: (0.5 + readiness as f32 / 200.0).min(0.95),
        rationale: "standard workload with no blocking signals observed".into(),
        evidence: vec![
            format!("readiness {readiness}/100"),
            format!("{} member assets", members.len()),
        ],
        alternatives: vec![MigrationStrategy::Replatform],
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;

    #[test]
    fn standard_workload_rehosts_with_readiness_scaled_confidence() {
        let fx = testkit::complete_application(2);
        let r = recommend(&fx.input(), 80);
        assert_eq!(r.strategy, MigrationStrategy::Rehost);
        assert!((r.confidence - 0.9).abs() < f32::EPSILON, "{:?}", r);
        assert_eq!(r.alternatives, vec![MigrationStrategy::Replatform]);
    }

    #[test]
    fn missing_os_majority_is_unknown_not_guessed() {
        let mut fx = testkit::complete_application(3);
        for asset in fx.assets.iter_mut() {
            asset.os_name = None;
        }
        let r = recommend(&fx.input(), 40);
        assert_eq!(r.strategy, MigrationStrategy::Unknown);
        assert!(r.alternatives.is_empty());
    }

    #[test]
    fn no_observed_activity_suggests_retire_with_low_confidence() {
        let mut fx = testkit::complete_application(2);
        fx.services.clear();
        fx.dependencies.clear();
        fx.metric_windows.clear();
        let r = recommend(&fx.input(), 100);
        assert_eq!(r.strategy, MigrationStrategy::Retire);
        assert!(r.confidence < 0.5);
    }

    #[test]
    fn network_gear_is_retained() {
        let mut fx = testkit::complete_application(2);
        fx.assets[0].device_class = Some("network".into());
        let r = recommend(&fx.input(), 90);
        assert_eq!(r.strategy, MigrationStrategy::Retain);
        assert!(r.evidence[0].contains("network members"));
    }

    #[test]
    fn eol_os_forces_replatform() {
        let mut fx = testkit::complete_application(2);
        fx.findings.push(testkit::finding(
            "os.eol",
            &fx.assets[0].id,
            "Ubuntu 18.04 is end of life",
        ));
        let r = recommend(&fx.input(), 90);
        assert_eq!(r.strategy, MigrationStrategy::Replatform);
        assert_eq!(
            r.alternatives,
            vec![MigrationStrategy::Rehost, MigrationStrategy::Refactor]
        );
    }

    #[test]
    fn high_complexity_with_external_coupling_refactors() {
        let mut fx = testkit::complete_application(2);
        fx.asset_scores[0].score = 60;
        fx.connections
            .push(testkit::connection(&fx.assets[0].id, "203.0.113.9", 443));
        let r = recommend(&fx.input(), 50);
        assert_eq!(r.strategy, MigrationStrategy::Refactor);
    }
}
