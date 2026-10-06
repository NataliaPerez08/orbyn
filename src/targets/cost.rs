//! Cost engine (v1.3): estimated monthly baseline per provider.
//!
//! Every component is labeled `known | estimated | not_calculated` — an
//! unknown component never silently becomes zero. Prices come from the
//! curated catalog (list prices), so even a fully-sized compute component
//! is an estimate, never a quote.

use crate::metrics::SampleConfidence;
use crate::planning::PlanInput;

use super::matching::{ProviderFit, DB_PORTS};

/// Version of the cost model; stamped into compare/recommend output.
pub const COST_MODEL_VERSION: &str = "cost/v1";

/// Hours in a 30-day month, the standard billing approximation.
const HOURS_PER_MONTH: f64 = 730.0;

/// How much of a component's cost is actually known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CostLabel {
    Known,
    Estimated,
    NotCalculated,
}

impl CostLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            CostLabel::Known => "known",
            CostLabel::Estimated => "estimated",
            CostLabel::NotCalculated => "not_calculated",
        }
    }
}

/// One cost component of the monthly baseline.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CostComponent {
    pub component: &'static str,
    pub label: CostLabel,
    /// Monthly cost in `currency`, `None` when not calculated.
    pub monthly: Option<f64>,
    pub currency: String,
    pub detail: String,
}

/// The monthly baseline estimate for one provider.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CostEstimate {
    pub provider: String,
    pub currency: String,
    /// Sum of the calculated components only; the reasons state what is
    /// missing. `None` when nothing could be calculated.
    pub monthly_total: Option<f64>,
    pub components: Vec<CostComponent>,
    pub confidence: SampleConfidence,
    pub reasons: Vec<String>,
    pub cost_model_version: &'static str,
}

/// Estimate the monthly baseline for one provider from its fit.
///
/// ponytail: confidence caps at Medium — compute is priced from curated
/// list prices and storage/managed-database are not calculated; High is
/// reserved for when every component is priced from a live source.
pub fn cost(fit: &ProviderFit, input: &PlanInput) -> CostEstimate {
    let currency = super::catalog(&fit.provider)
        .map(|c| c.currency.clone())
        .unwrap_or_else(|| "USD".into());

    // Compute: the smallest-fit instance for every sized member.
    let priced: Vec<&super::matching::AssetMatch> = fit
        .matches
        .iter()
        .filter(|m| m.hourly_price.is_some())
        .collect();
    let unsized_members = fit.matches.len() - priced.len();
    let (compute, compute_detail) = if fit.matches.is_empty() {
        (
            None,
            "no member matches; compute not calculated".to_string(),
        )
    } else if priced.is_empty() {
        (
            None,
            format!("no member has a priced instance type ({unsized_members} without sizing data)"),
        )
    } else {
        let total: f64 =
            priced.iter().filter_map(|m| m.hourly_price).sum::<f64>() * HOURS_PER_MONTH;
        let detail = if unsized_members == 0 {
            format!(
                "{} instance(s) at curated on-demand list prices x {HOURS_PER_MONTH} h",
                priced.len()
            )
        } else {
            format!(
                "{} of {} instance(s) priced; {unsized_members} member(s) without sizing data are not in the total",
                priced.len(),
                fit.matches.len()
            )
        };
        (Some(total), detail)
    };

    // Storage: disk sizing is not part of the fit input and storage
    // pricing is not in the catalog — never guessed.
    let storage = CostComponent {
        component: "storage",
        label: CostLabel::NotCalculated,
        monthly: None,
        currency: currency.clone(),
        detail: "storage sizing and storage pricing are not in the catalog; not calculated".into(),
    };

    // Managed database: detected workloads are named, but managed-service
    // pricing is not in the catalog.
    let databases: Vec<&crate::domain::Service> = input
        .services
        .iter()
        .filter(|s| input.is_member(&s.asset_id) && DB_PORTS.contains(&s.port))
        .collect();
    let managed_db = CostComponent {
        component: "managed-database",
        label: CostLabel::NotCalculated,
        monthly: None,
        currency: currency.clone(),
        detail: if databases.is_empty() {
            "no database service detected on members".into()
        } else {
            format!(
                "database service detected ({}); managed-service pricing is not in the catalog",
                databases
                    .iter()
                    .map(|s| format!("port {}", s.port))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
    };

    let compute_component = CostComponent {
        component: "compute",
        label: match compute {
            Some(_) => CostLabel::Estimated,
            None => CostLabel::NotCalculated,
        },
        monthly: compute,
        currency: currency.clone(),
        detail: compute_detail,
    };

    let mut reasons = Vec::new();
    if compute.is_some() {
        reasons.push(
            "total covers calculated components only; storage and managed database are not calculated"
                .to_string(),
        );
        if unsized_members > 0 {
            reasons.push(format!(
                "{unsized_members} member(s) without sizing data are excluded from compute"
            ));
        }
    }
    let confidence = if compute.is_some() && unsized_members == 0 {
        SampleConfidence::Medium
    } else {
        SampleConfidence::Low
    };

    CostEstimate {
        provider: fit.provider.clone(),
        currency,
        monthly_total: compute,
        components: vec![compute_component, storage, managed_db],
        confidence,
        reasons,
        cost_model_version: COST_MODEL_VERSION,
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::MigrationStrategy;
    use crate::planning::testkit;
    use crate::targets::matching::fit;

    use super::*;

    #[test]
    fn complete_application_gets_an_estimated_compute_baseline() {
        let fx = testkit::complete_application(2);
        let fits = fit(&fx.input(), MigrationStrategy::Rehost);
        let estimate = cost(&fits[0], &fx.input());
        assert_eq!(estimate.provider, "aws");
        assert_eq!(estimate.currency, "USD");
        // 2x c5.xlarge at $0.17/h x 730 h.
        let expected = 2.0 * 0.17 * HOURS_PER_MONTH;
        let compute = estimate
            .components
            .iter()
            .find(|c| c.component == "compute")
            .unwrap();
        assert_eq!(compute.label, CostLabel::Estimated);
        assert!(
            (compute.monthly.unwrap() - expected).abs() < 0.01,
            "{compute:?}"
        );
        assert_eq!(estimate.monthly_total, compute.monthly);
        assert_eq!(estimate.confidence, SampleConfidence::Medium);
        assert!(estimate
            .reasons
            .iter()
            .any(|r| r.contains("storage and managed database are not calculated")));
    }

    #[test]
    fn unsized_members_never_become_a_silent_zero() {
        let mut fx = testkit::complete_application(2);
        fx.capacities.clear();
        let fits = fit(&fx.input(), MigrationStrategy::Rehost);
        let estimate = cost(&fits[0], &fx.input());
        assert_eq!(estimate.monthly_total, None);
        assert_eq!(estimate.confidence, SampleConfidence::Low);
        let compute = estimate
            .components
            .iter()
            .find(|c| c.component == "compute")
            .unwrap();
        assert_eq!(compute.label, CostLabel::NotCalculated);
        assert!(compute.detail.contains("without sizing data"));
    }

    #[test]
    fn database_detection_is_named_but_not_priced() {
        let mut fx = testkit::complete_application(2);
        fx.services.push(crate::domain::Service {
            asset_id: "a0".into(),
            proto: "tcp".into(),
            port: 5432,
            name: Some("postgresql".into()),
            state: "open".into(),
            banner: None,
        });
        let fits = fit(&fx.input(), MigrationStrategy::Rehost);
        let estimate = cost(&fits[0], &fx.input());
        let db = estimate
            .components
            .iter()
            .find(|c| c.component == "managed-database")
            .unwrap();
        assert_eq!(db.label, CostLabel::NotCalculated);
        assert!(db.detail.contains("port 5432"), "{db:?}");
    }
}
