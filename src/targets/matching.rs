//! Application-level target matching and per-provider fit score (v1.3).
//!
//! Pure functions over the same [`PlanInput`] snapshot the planner uses
//! (the store is never read here). For every provider catalog the
//! per-asset SKU fit is computed, then the application-level fit score:
//! each roadmap input moves the score and says why, so a fit is never a
//! bare number. Providers without a catalog are not scored at all —
//! NOT_CALCULATED, never guessed.

use crate::assessment::external_endpoints;
use crate::domain::MigrationStrategy;
use crate::planning::PlanInput;

use super::{catalog, TargetCatalog};

/// Version of the fit model; stamped into compare/recommend output.
pub const TARGET_FIT_VERSION: &str = "target-fit/v1";

/// Database ports: workloads that map to a managed database service.
const DB_PORTS: [u16; 5] = [3306, 5432, 1433, 1521, 27017];

/// One reason a fit input moved (or held) the score.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct FitReason {
    /// The roadmap input: capacity-fit, managed-service, architecture,
    /// migration-complexity, dependency-compatibility, region-availability,
    /// pricing-completeness, data-confidence.
    pub input: &'static str,
    pub delta: i8,
    pub detail: String,
}

/// The smallest catalog fit for one member asset.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AssetMatch {
    pub asset_id: String,
    pub sku: Option<String>,
    pub hourly_price: Option<f64>,
    pub detail: String,
}

/// The fit of one provider for the application.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderFit {
    pub provider: String,
    pub region: String,
    /// 0-100, or `None` when the fit is not calculable (no catalog, or a
    /// strategy that has no target).
    pub score: Option<u8>,
    pub reasons: Vec<FitReason>,
    pub matches: Vec<AssetMatch>,
    pub catalog_version: String,
}

/// The smallest catalog SKU covering the allocation, with its price.
fn smallest_fit(
    catalog: &TargetCatalog,
    cores: u32,
    ram_mib: u64,
) -> Option<&crate::targets::TargetSku> {
    catalog
        .skus
        .iter()
        .filter(|s| s.cpu >= cores && s.memory_mib >= ram_mib)
        .min_by_key(|s| (s.cpu, s.memory_mib))
}

/// Compute the fit of every catalog provider for the application.
pub fn fit(input: &PlanInput, strategy: MigrationStrategy) -> Vec<ProviderFit> {
    // Strategy gate: these strategies have no target to fit.
    if matches!(
        strategy,
        MigrationStrategy::Retain | MigrationStrategy::Retire | MigrationStrategy::Unknown
    ) {
        return catalog_providers(strategy);
    }

    let members = input.member_assets();
    let external = external_endpoints(input.assets, input.connections);
    let unconfirmed: Vec<&crate::domain::Dependency> = input
        .dependencies
        .iter()
        .filter(|d| {
            !d.confirmed
                && (input.is_member(&d.source_asset_id) || input.is_member(&d.target_asset_id))
        })
        .collect();
    let databases: Vec<&crate::domain::Service> = input
        .services
        .iter()
        .filter(|s| input.is_member(&s.asset_id) && DB_PORTS.contains(&s.port))
        .collect();
    let complex: Vec<&crate::assessment::AssetScore> = input
        .asset_scores
        .iter()
        .filter(|s| input.is_member(&s.asset_id) && s.score >= 50)
        .collect();
    let unsized_members: Vec<&crate::domain::Asset> = members
        .iter()
        .filter(|a| input.capacity(&a.id).is_none())
        .copied()
        .collect();
    let unsampled: Vec<&crate::domain::Asset> = members
        .iter()
        .filter(|a| input.window(&a.id).is_none())
        .copied()
        .collect();

    let mut fits = Vec::new();
    for provider in ["aws", "azure", "gcp"] {
        let catalog = match catalog(provider) {
            Some(c) => c,
            None => continue,
        };

        // Per-asset matches.
        let mut matches = Vec::new();
        let mut no_fit = 0usize;
        let mut unpriced = 0usize;
        for asset in &members {
            let capacity = input.capacity(&asset.id);
            let (cores, ram) = match capacity {
                Some(c) => (c.cpu_cores, c.ram_total_mb),
                None => (None, None),
            };
            match (cores, ram) {
                (Some(c), Some(r)) => match smallest_fit(catalog, c, r) {
                    Some(sku) => {
                        let price = catalog.price(&sku.sku).map(|p| p.hourly_price);
                        if price.is_none() {
                            unpriced += 1;
                        }
                        matches.push(AssetMatch {
                            asset_id: asset.id.clone(),
                            sku: Some(sku.sku.clone()),
                            hourly_price: price,
                            detail: format!("{c} cores, {r} MiB -> smallest fit"),
                        });
                    }
                    None => {
                        no_fit += 1;
                        matches.push(AssetMatch {
                            asset_id: asset.id.clone(),
                            sku: None,
                            hourly_price: None,
                            detail: format!("{c} cores, {r} MiB exceed the catalog"),
                        });
                    }
                },
                _ => matches.push(AssetMatch {
                    asset_id: asset.id.clone(),
                    sku: None,
                    hourly_price: None,
                    detail: "no capacity data; instance type not calculated".into(),
                }),
            }
        }

        // Score: every roadmap input, each with its reason.
        let mut score: i32 = 100;
        let mut reasons = Vec::new();

        let delta = -(unsized_members.len() as i32 * 10).min(30);
        reasons.push(FitReason {
            input: "capacity-fit",
            delta: delta as i8,
            detail: if unsized_members.is_empty() {
                format!("every member has a sizing baseline ({})", matches.len())
            } else {
                format!(
                    "{} member(s) without capacity data",
                    unsized_members
                        .iter()
                        .map(|a| a.id.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
        });
        score += delta;
        if no_fit > 0 {
            let delta = -(no_fit as i32 * 20).min(40);
            reasons.push(FitReason {
                input: "capacity-fit",
                delta: delta as i8,
                detail: format!("{no_fit} member(s) exceed the largest catalog SKU"),
            });
            score += delta;
        }

        reasons.push(FitReason {
            input: "managed-service",
            delta: 0,
            detail: if databases.is_empty() {
                "no database service detected on members".into()
            } else {
                format!(
                    "database workload detected (port(s) {}); a managed database service is an alternative to self-hosting",
                    databases.iter().map(|s| s.port.to_string()).collect::<Vec<_>>().join(", ")
                )
            },
        });

        reasons.push(FitReason {
            input: "architecture",
            delta: 0,
            detail: "all catalog SKUs are x86_64; asset CPU architecture is not collected".into(),
        });

        if !complex.is_empty() {
            let delta = -(complex.len() as i32 * 5).min(15);
            reasons.push(FitReason {
                input: "migration-complexity",
                delta: delta as i8,
                detail: format!(
                    "{} member(s) score high complexity (>= 50/100)",
                    complex.len()
                ),
            });
            score += delta;
        }

        if !unconfirmed.is_empty() {
            let delta = -(unconfirmed.len() as i32 * 3).min(12);
            reasons.push(FitReason {
                input: "dependency-compatibility",
                delta: delta as i8,
                detail: format!("{} unconfirmed edge(s) touching members", unconfirmed.len()),
            });
            score += delta;
        }
        let coupled: Vec<&crate::domain::Asset> = members
            .iter()
            .filter(|a| external.get(&a.id).is_some_and(|e| !e.is_empty()))
            .copied()
            .collect();
        if !coupled.is_empty() {
            let delta = -(coupled.len() as i32 * 2).min(8);
            reasons.push(FitReason {
                input: "dependency-compatibility",
                delta: delta as i8,
                detail: format!(
                    "{} member(s) talk to endpoints outside the inventory",
                    coupled.len()
                ),
            });
            score += delta;
        }

        reasons.push(FitReason {
            input: "region-availability",
            delta: 0,
            detail: format!("catalog pinned to {}", catalog.region),
        });

        if unpriced > 0 {
            let delta = -(unpriced as i32 * 5).min(15);
            reasons.push(FitReason {
                input: "pricing-completeness",
                delta: delta as i8,
                detail: format!("{unpriced} matched SKU(s) without price data"),
            });
            score += delta;
        }

        if !unsampled.is_empty() {
            let delta = -(unsampled.len() as i32 * 2).min(10);
            reasons.push(FitReason {
                input: "data-confidence",
                delta: delta as i8,
                detail: format!(
                    "{} member(s) without utilization samples; right-sizing unverifiable",
                    unsampled.len()
                ),
            });
            score += delta;
        }

        fits.push(ProviderFit {
            provider: catalog.provider.clone(),
            region: catalog.region.clone(),
            score: Some(score.clamp(0, 100) as u8),
            reasons,
            matches,
            catalog_version: catalog.catalog_version.clone(),
        });
    }
    fits
}

/// The not-calculated result for every catalog provider (the strategy
/// has no target to fit).
fn catalog_providers(strategy: MigrationStrategy) -> Vec<ProviderFit> {
    let detail = match strategy {
        MigrationStrategy::Retain => {
            "strategy is retain: network/infrastructure workloads are not migrated"
        }
        MigrationStrategy::Retire => {
            "strategy is retire: the application is planned for decommissioning"
        }
        MigrationStrategy::Unknown => "strategy is unknown: insufficient evidence to fit a target",
        _ => "no catalog for this provider",
    };
    ["aws", "azure", "gcp"]
        .iter()
        .filter_map(|p| catalog(p))
        .map(|c| ProviderFit {
            provider: c.provider.clone(),
            region: c.region.clone(),
            score: None,
            reasons: vec![FitReason {
                input: "strategy",
                delta: 0,
                detail: detail.into(),
            }],
            matches: Vec::new(),
            catalog_version: c.catalog_version.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::planning::testkit;

    use super::*;

    #[test]
    fn complete_application_fits_every_provider_at_full_score() {
        let fx = testkit::complete_application(2);
        let fits = fit(&fx.input(), MigrationStrategy::Rehost);
        assert_eq!(fits.len(), 3);
        for f in &fits {
            assert_eq!(f.score, Some(100), "{}: {:?}", f.provider, f.reasons);
            assert_eq!(f.matches.len(), 2);
            let m = &f.matches[0];
            assert!(m.sku.is_some(), "{}: {:?}", f.provider, m);
            assert!(m.hourly_price.is_some());
            assert_eq!(f.catalog_version, format!("{}-catalog/2026-10", f.provider));
        }
        let aws = &fits[0];
        assert_eq!(aws.matches[0].sku.as_deref(), Some("c5.xlarge"));
    }

    #[test]
    fn missing_capacity_penalizes_and_never_gives_a_free_zero() {
        let mut fx = testkit::complete_application(2);
        fx.capacities.clear();
        let fits = fit(&fx.input(), MigrationStrategy::Rehost);
        let aws = &fits[0];
        assert_eq!(aws.score, Some(80));
        assert!(aws.matches.iter().all(|m| m.sku.is_none()));
        assert!(aws.matches[0]
            .detail
            .contains("no capacity data; instance type not calculated"));
        let capacity: Vec<&FitReason> = aws
            .reasons
            .iter()
            .filter(|r| r.input == "capacity-fit")
            .collect();
        assert_eq!(capacity[0].delta, -20);
    }

    #[test]
    fn retain_retire_and_unknown_are_not_calculated() {
        let fx = testkit::complete_application(2);
        for strategy in [
            MigrationStrategy::Retain,
            MigrationStrategy::Retire,
            MigrationStrategy::Unknown,
        ] {
            let fits = fit(&fx.input(), strategy);
            assert!(fits.iter().all(|f| f.score.is_none()), "{strategy:?}");
            assert!(
                fits[0].reasons[0].detail.starts_with("strategy is"),
                "{strategy:?}"
            );
        }
    }

    #[test]
    fn database_service_and_coupling_show_up_as_reasons() {
        let mut fx = testkit::complete_application(2);
        fx.services.push(crate::domain::Service {
            asset_id: "a0".into(),
            proto: "tcp".into(),
            port: 5432,
            name: Some("postgresql".into()),
            state: "open".into(),
            banner: None,
        });
        fx.connections
            .push(testkit::connection("a0", "203.0.113.9", 443));
        let fits = fit(&fx.input(), MigrationStrategy::Rehost);
        let aws = &fits[0];
        assert!(
            aws.reasons
                .iter()
                .any(|r| r.input == "managed-service"
                    && r.detail.contains("database workload detected")),
            "{:?}",
            aws.reasons
        );
        assert_eq!(
            aws.score,
            Some(98),
            "external coupling on one member: {:?}",
            aws.reasons
        );
    }
}
