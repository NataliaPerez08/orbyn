//! Migration assessment engine (v0.5 milestone).
//!
//! Assessment evaluates the normalized domain — never raw collector output —
//! through a versioned rule catalog ([`rules`]). Every finding carries its
//! rule id, severity, human rationale and evidence, so recommendations stay
//! explainable: a score is never a mystery number.
//!
//! [`run_assessment`] turns an [`AssessmentInput`] (the full inventory
//! snapshot) into an [`AssessmentReport`] consumed by `orbyn assess`.

pub mod grouping;
pub mod rules;

use serde::{Deserialize, Serialize};

use crate::domain::{Asset, Capacity, Connection, Dependency, Filesystem, Service};

/// Version of the rule catalog. Bump whenever a rule changes behavior so
/// reports stay comparable across releases.
pub const RULES_VERSION: &str = "0.6.0";

/// A named assessment rule result: what was found, why it matters, and the
/// evidence that produced it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub evidence: Vec<String>,
    pub asset_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    High,
}

impl Severity {
    /// Contribution of one finding to its asset's complexity score.
    pub fn weight(self) -> u32 {
        match self {
            Severity::Info => 2,
            Severity::Warning => 10,
            Severity::High => 25,
        }
    }
}

/// Complexity band of the overall score.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Complexity {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Complexity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Complexity::Low => write!(f, "low"),
            Complexity::Medium => write!(f, "medium"),
            Complexity::High => write!(f, "high"),
        }
    }
}

/// Everything the rule engine may look at: a full inventory snapshot.
#[derive(Debug, Clone, Default)]
pub struct AssessmentInput {
    pub assets: Vec<Asset>,
    pub services: Vec<Service>,
    pub filesystems: Vec<Filesystem>,
    pub capacities: Vec<Capacity>,
    pub dependencies: Vec<Dependency>,
    pub connections: Vec<Connection>,
}

/// Per-asset migration complexity (0-100, higher = more complex).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetScore {
    pub asset_id: String,
    pub score: u8,
    pub findings: usize,
}

/// A set of assets that appear to belong to one application because they are
/// connected by runtime/manual dependency edges.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplicationGroup {
    pub id: String,
    pub asset_ids: Vec<String>,
    pub edge_count: usize,
}

/// The result of `orbyn assess`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssessmentReport {
    pub rules_version: String,
    pub assets_assessed: usize,
    /// Average per-asset complexity, 0-100.
    pub overall_score: u8,
    pub complexity: Complexity,
    pub findings: Vec<Finding>,
    pub asset_scores: Vec<AssetScore>,
    pub application_groups: Vec<ApplicationGroup>,
}

/// Run every rule in the catalog and compute the report.
pub fn run_assessment(input: &AssessmentInput) -> AssessmentReport {
    let mut findings = Vec::new();
    for rule in rules::catalog() {
        (rule.evaluate)(input, &mut findings);
    }

    // Most severe first, then per asset, then stable by rule id.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.asset_id.cmp(&b.asset_id))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    let mut asset_scores: Vec<AssetScore> = input
        .assets
        .iter()
        .map(|asset| {
            let own: Vec<&Finding> = findings
                .iter()
                .filter(|f| f.asset_id.as_deref() == Some(asset.id.as_str()))
                .collect();
            let score: u32 = own.iter().map(|f| f.severity.weight()).sum();
            AssetScore {
                asset_id: asset.id.clone(),
                score: score.min(100) as u8,
                findings: own.len(),
            }
        })
        .collect();
    asset_scores.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.asset_id.cmp(&b.asset_id))
    });

    let overall_score = if asset_scores.is_empty() {
        0
    } else {
        let total: u32 = asset_scores.iter().map(|s| s.score as u32).sum();
        let avg = total as f64 / asset_scores.len() as f64;
        avg.round() as u8
    };

    AssessmentReport {
        rules_version: RULES_VERSION.to_string(),
        assets_assessed: input.assets.len(),
        overall_score,
        complexity: complexity_band(overall_score),
        findings,
        asset_scores,
        application_groups: grouping::application_groups(&input.assets, &input.dependencies),
    }
}

fn complexity_band(score: u8) -> Complexity {
    if score < 20 {
        Complexity::Low
    } else if score < 50 {
        Complexity::Medium
    } else {
        Complexity::High
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(assets: Vec<Asset>) -> AssessmentInput {
        AssessmentInput {
            assets,
            ..Default::default()
        }
    }

    fn asset(id: &str) -> Asset {
        Asset {
            id: id.into(),
            ip: format!("10.0.0.{}", id).parse().unwrap(),
            hostname: None,
            device_class: None,
            os_name: None,
            os_version: None,
            environment: None,
            owner: None,
            criticality: None,
            tags: Vec::new(),
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
        }
    }

    #[test]
    fn empty_inventory_is_low_complexity() {
        let report = run_assessment(&input(vec![]));
        assert_eq!(report.overall_score, 0);
        assert_eq!(report.complexity, Complexity::Low);
        assert!(report.findings.is_empty());
        assert_eq!(report.rules_version, RULES_VERSION);
    }

    #[test]
    fn scores_average_and_band() {
        // Both assets: os.missing (Info 2) + capacity.missing (Info 2) = 4 each.
        let report = run_assessment(&input(vec![asset("1"), asset("2")]));
        assert_eq!(report.overall_score, 4);
        assert_eq!(report.complexity, Complexity::Low);
        assert_eq!(report.asset_scores.len(), 2);
        assert_eq!(report.asset_scores[0].score, 4);
        // tie on score -> lexicographic order
        assert_eq!(report.asset_scores[0].asset_id, "1");
    }

    #[test]
    fn high_findings_cap_at_100_per_asset() {
        // One asset with several High findings (EOL OS + insecure services +
        // hub) must cap at 100 rather than overflow the score.
        let mut inp = input(vec![asset("1")]);
        inp.assets[0].os_name = Some("CentOS 7".into());
        inp.services = vec![crate::domain::Service {
            asset_id: "1".into(),
            proto: "tcp".into(),
            port: 23,
            name: None,
            state: "open".into(),
            banner: None,
        }];
        let report = run_assessment(&inp);
        let score = report
            .asset_scores
            .iter()
            .find(|s| s.asset_id == "1")
            .unwrap();
        // EOL OS (High 25) + insecure service (High 25) + capacity.missing (Info 2)
        assert_eq!(score.score, 52);
    }
}
