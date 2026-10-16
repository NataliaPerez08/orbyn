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
/// ponytail: confidence caps at Medium — compute and storage are priced
/// from curated list prices and managed-database is not calculated;
/// High is reserved for when every component is priced from a live
/// source.
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

    // Storage: observed member filesystem capacity at the catalog's
    // curated general-purpose SSD tier. No disk sizing or no storage
    // pricing means not calculated — never guessed.
    let member_filesystems: Vec<&crate::domain::Filesystem> = input
        .filesystems
        .iter()
        .filter(|f| input.is_member(&f.asset_id))
        .collect();
    let disk_gib: f64 = member_filesystems
        .iter()
        .map(|f| f.size_kb as f64 / 1_048_576.0)
        .sum();
    let storage_pricing = super::catalog(&fit.provider).and_then(|c| c.storage.clone());
    let storage = match (disk_gib > 0.0, &storage_pricing) {
        (true, Some(pricing)) => CostComponent {
            component: "storage",
            label: CostLabel::Estimated,
            monthly: Some(disk_gib * pricing.gb_monthly_price),
            currency: currency.clone(),
            detail: format!(
                "{disk_gib:.0} GiB across {} filesystem(s) at {} list price ${}/GiB-month",
                member_filesystems.len(),
                pricing.sku,
                pricing.gb_monthly_price
            ),
        },
        (true, None) => CostComponent {
            component: "storage",
            label: CostLabel::NotCalculated,
            monthly: None,
            currency: currency.clone(),
            detail: "storage pricing is not in the catalog; not calculated".into(),
        },
        (false, _) => CostComponent {
            component: "storage",
            label: CostLabel::NotCalculated,
            monthly: None,
            currency: currency.clone(),
            detail: "no disk sizing observed on members; not calculated".into(),
        },
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

    // The total sums the calculated components only; the reasons name
    // everything that is missing.
    let mut calculated: Vec<f64> = Vec::new();
    if let Some(compute) = compute {
        calculated.push(compute);
    }
    if let Some(storage) = storage.monthly {
        calculated.push(storage);
    }
    let monthly_total = (!calculated.is_empty()).then(|| calculated.iter().sum::<f64>());

    let mut reasons = Vec::new();
    if monthly_total.is_some() {
        reasons.push(
            "total covers calculated components only; managed database is not calculated"
                .to_string(),
        );
        if compute.is_none() {
            reasons.push("compute is not calculated".to_string());
        }
        if storage.monthly.is_none() {
            reasons.push("storage is not calculated".to_string());
        }
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
        monthly_total,
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
        // Storage: 2 x 100 GiB at gp3 $0.08/GiB-month.
        let storage = estimate
            .components
            .iter()
            .find(|c| c.component == "storage")
            .unwrap();
        assert_eq!(storage.label, CostLabel::Estimated);
        assert!(
            (storage.monthly.unwrap() - 16.0).abs() < 0.01,
            "{storage:?}"
        );
        assert_eq!(estimate.monthly_total, compute.monthly.map(|c| c + 16.0));
        assert_eq!(estimate.confidence, SampleConfidence::Medium);
        assert!(estimate
            .reasons
            .iter()
            .any(|r| r.contains("managed database is not calculated")));
    }

    #[test]
    fn unsized_members_never_become_a_silent_zero() {
        let mut fx = testkit::complete_application(2);
        fx.capacities.clear();
        let fits = fit(&fx.input(), MigrationStrategy::Rehost);
        let estimate = cost(&fits[0], &fx.input());
        // Compute is not calculable, but observed storage still is; the
        // total never invents the missing compute.
        assert_eq!(estimate.monthly_total, Some(16.0));
        assert_eq!(estimate.confidence, SampleConfidence::Low);
        let compute = estimate
            .components
            .iter()
            .find(|c| c.component == "compute")
            .unwrap();
        assert_eq!(compute.label, CostLabel::NotCalculated);
        assert!(compute.detail.contains("without sizing data"));
        assert!(estimate
            .reasons
            .iter()
            .any(|r| r.contains("compute is not calculated")));
    }

    #[test]
    fn storage_without_disk_sizing_is_not_calculated() {
        let mut fx = testkit::complete_application(2);
        fx.filesystems.clear();
        let fits = fit(&fx.input(), MigrationStrategy::Rehost);
        let estimate = cost(&fits[0], &fx.input());
        let storage = estimate
            .components
            .iter()
            .find(|c| c.component == "storage")
            .unwrap();
        assert_eq!(storage.label, CostLabel::NotCalculated);
        assert!(storage.detail.contains("no disk sizing"), "{storage:?}");
        assert!(estimate
            .reasons
            .iter()
            .any(|r| r.contains("storage is not calculated")));
    }

    #[test]
    fn storage_without_catalog_pricing_is_not_calculated() {
        let fx = testkit::complete_application(2);
        // A provider with no embedded catalog: nothing may be guessed.
        let synthetic = crate::targets::matching::ProviderFit {
            provider: "huawei".into(),
            region: "cn-north-4".into(),
            score: None,
            reasons: Vec::new(),
            matches: Vec::new(),
            catalog_version: String::new(),
        };
        let estimate = cost(&synthetic, &fx.input());
        assert_eq!(estimate.currency, "USD");
        let storage = estimate
            .components
            .iter()
            .find(|c| c.component == "storage")
            .unwrap();
        assert_eq!(storage.label, CostLabel::NotCalculated);
        assert!(storage.detail.contains("not in the catalog"), "{storage:?}");
        assert_eq!(estimate.monthly_total, None);
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
