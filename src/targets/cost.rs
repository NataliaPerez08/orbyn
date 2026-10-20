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

/// Map a detected database port to a managed-service engine with
/// catalog tiers. First cut: postgres and mysql; other engines stay
/// honestly not calculated until their catalog data is curated.
fn db_engine(port: u16) -> Option<&'static str> {
    match port {
        5432 => Some("postgres"),
        3306 => Some("mysql"),
        _ => None,
    }
}

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
/// ponytail: confidence caps at Medium — every component is priced
/// from curated list prices; High is reserved for when every component
/// is priced from a live source.
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

    // Managed database: a detected database workload is priced as a
    // managed-service alternative when the catalog has tiers for its
    // engine and the host's sizing; otherwise it is named but not
    // calculated. The priced tier is an alternative to self-hosting —
    // the members' compute already covers the self-hosted cost, so it
    // is never added to the total.
    let databases: Vec<&crate::domain::Service> = input
        .services
        .iter()
        .filter(|s| input.is_member(&s.asset_id) && DB_PORTS.contains(&s.port))
        .collect();
    let mut db_monthly = 0.0;
    let mut db_unpriced = 0usize;
    let mut db_details: Vec<String> = Vec::new();
    for s in &databases {
        let tiers = db_engine(s.port)
            .and_then(|e| super::catalog(&fit.provider).map(|c| c.managed_db_tiers(e)))
            .unwrap_or_default();
        let size = input
            .capacity(&s.asset_id)
            .and_then(|c| c.cpu_cores.zip(c.ram_total_mb));
        let tier = match (size, tiers.is_empty()) {
            (Some((cores, ram)), false) => {
                let tier = tiers
                    .iter()
                    .filter(|t| t.cpu >= cores && t.memory_mib >= ram)
                    .min_by_key(|t| (t.cpu, t.memory_mib));
                match tier {
                    Some(t) => {
                        db_monthly += t.hourly_price * HOURS_PER_MONTH;
                        db_details.push(format!(
                            "{} on {} ({} cores, {} MiB) -> {} at ${}/h",
                            db_engine(s.port).unwrap_or("db"),
                            s.asset_id,
                            cores,
                            ram,
                            t.sku,
                            t.hourly_price
                        ));
                        continue;
                    }
                    None => format!(
                        "{} on {}: no managed tier covers {} cores / {} MiB",
                        db_engine(s.port).unwrap_or("db"),
                        s.asset_id,
                        cores,
                        ram
                    ),
                }
            }
            (None, _) => format!(
                "port {} on {}: no capacity data for the database host",
                s.port, s.asset_id
            ),
            (Some(_), true) => format!(
                "port {}: no managed-service pricing for its engine in the catalog",
                s.port
            ),
        };
        db_unpriced += 1;
        db_details.push(tier);
    }
    let managed_db = if databases.is_empty() {
        CostComponent {
            component: "managed-database",
            label: CostLabel::NotCalculated,
            monthly: None,
            currency: currency.clone(),
            detail: "no database service detected on members".into(),
        }
    } else if db_unpriced == 0 {
        CostComponent {
            component: "managed-database",
            label: CostLabel::Estimated,
            monthly: Some(db_monthly),
            currency: currency.clone(),
            detail: format!(
                "{} — a managed alternative to self-hosting, excluded from the total",
                db_details.join("; ")
            ),
        }
    } else if db_monthly > 0.0 {
        CostComponent {
            component: "managed-database",
            label: CostLabel::Estimated,
            monthly: Some(db_monthly),
            currency: currency.clone(),
            detail: format!(
                "{} of {} database service(s) priced; the rest stay not calculated — {}",
                databases.len() - db_unpriced,
                databases.len(),
                db_details.join("; ")
            ),
        }
    } else {
        CostComponent {
            component: "managed-database",
            label: CostLabel::NotCalculated,
            monthly: None,
            currency: currency.clone(),
            detail: db_details.join("; "),
        }
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
        reasons.push("total covers calculated components only".to_string());
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
    if !databases.is_empty() {
        if db_unpriced == 0 {
            reasons.push(
                "managed database priced as a managed alternative to self-hosting; \
                 excluded from the total (the members' compute already covers self-hosting)"
                    .to_string(),
            );
        } else if db_monthly > 0.0 {
            reasons.push(format!(
                "{db_unpriced} database service(s) not priced; managed database partially calculated"
            ));
        } else {
            reasons.push("managed database is not calculated".to_string());
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
            .any(|r| r.contains("total covers calculated components only")));
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
        // A provider with no catalog at all: nothing may be guessed.
        let synthetic = crate::targets::matching::ProviderFit {
            provider: "digitalocean".into(),
            region: "nyc1".into(),
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
    fn database_service_is_priced_as_a_managed_alternative() {
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
        // a0 has 4 cores / 8192 MiB -> smallest aws postgres tier is
        // db.m6g.xlarge at $0.258/h.
        assert_eq!(db.label, CostLabel::Estimated, "{db:?}");
        assert!(db.detail.contains("postgres on a0"), "{db:?}");
        assert!(db.detail.contains("db.m6g.xlarge"), "{db:?}");
        let expected = 0.258 * HOURS_PER_MONTH;
        assert!((db.monthly.unwrap() - expected).abs() < 0.01, "{db:?}");
        // The managed alternative is excluded from the total: the
        // members' compute already covers self-hosting.
        assert!(estimate
            .reasons
            .iter()
            .any(|r| r.contains("excluded from the total")));
        let compute = estimate
            .components
            .iter()
            .find(|c| c.component == "compute")
            .unwrap();
        assert_eq!(
            estimate.monthly_total,
            compute.monthly.map(|c| c + 16.0),
            "total must not double-count the managed alternative"
        );
    }

    #[test]
    fn engines_without_catalog_tiers_stay_not_calculated() {
        let mut fx = testkit::complete_application(2);
        fx.services.push(crate::domain::Service {
            asset_id: "a0".into(),
            proto: "tcp".into(),
            port: 1433,
            name: Some("sqlserver".into()),
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
        assert_eq!(db.label, CostLabel::NotCalculated, "{db:?}");
        assert!(db.detail.contains("port 1433"), "{db:?}");
        assert!(db.detail.contains("no managed-service pricing"), "{db:?}");
        assert!(estimate
            .reasons
            .iter()
            .any(|r| r.contains("managed database is not calculated")));
    }

    #[test]
    fn database_without_host_capacity_stays_not_calculated() {
        let mut fx = testkit::complete_application(2);
        fx.services.push(crate::domain::Service {
            asset_id: "a0".into(),
            proto: "tcp".into(),
            port: 5432,
            name: Some("postgresql".into()),
            state: "open".into(),
            banner: None,
        });
        fx.capacities.clear();
        let fits = fit(&fx.input(), MigrationStrategy::Rehost);
        let estimate = cost(&fits[0], &fx.input());
        let db = estimate
            .components
            .iter()
            .find(|c| c.component == "managed-database")
            .unwrap();
        assert_eq!(db.label, CostLabel::NotCalculated, "{db:?}");
        assert!(db.detail.contains("no capacity data"), "{db:?}");
    }
}
