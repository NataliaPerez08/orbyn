//! Migration assessment engine.
//!
//! Assessment evaluates the normalized domain, never raw collector output.
//! Every finding must carry its evidence and the rule/version that produced it
//! so recommendations stay explainable.

use serde::{Deserialize, Serialize};

/// A named assessment rule and its human-readable rationale.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub evidence: Vec<String>,
    pub asset_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    High,
}

/// Overall migration complexity for a set of assets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssessmentReport {
    pub assets_assessed: usize,
    pub overall_score: u8,
    pub findings: Vec<Finding>,
}

/// The primitive from which scores are computed — a placeholder that will grow
/// into a rule engine during v0.5.
pub fn assess(findings: &[Finding]) -> u8 {
    findings.iter().fold(0u8, |score, f| match f.severity {
        Severity::Info => score,
        Severity::Warning => score.saturating_add(10),
        Severity::High => score.saturating_add(25),
    })
}
