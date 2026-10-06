//! Application workflows: inference discovery, manual curation, and the
//! read paths behind `orbyn applications`. Mutating operations record
//! audit events around the store changes.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use chrono::Utc;

use orbyn::applications::{InferenceInput, InferredMember};
use orbyn::assessment::{ApplicationGroup, AssetScore, Finding, Severity};
use orbyn::domain::{AppSource, Application, ApplicationMember};
use orbyn::output::{
    ApplicationAssessment, ApplicationDetail, ApplicationEdge, ApplicationSummary,
};
use orbyn::store::Store;

use crate::app::inventory::resolve_asset;
use crate::app::{begin_audit, finish_audit_result};

/// Resolve an application by name or id, or fail with a clean error.
pub(crate) async fn resolve_application(store: &dyn Store, key: &str) -> Result<Application> {
    store
        .get_application(key)
        .await?
        .ok_or_else(|| anyhow!("no application matches '{key}'"))
}

/// The non-excluded members of an application.
async fn active_members(store: &dyn Store, application_id: &str) -> Result<Vec<ApplicationMember>> {
    Ok(store
        .list_application_members(application_id)
        .await?
        .into_iter()
        .filter(|m| !m.is_excluded)
        .collect())
}

/// List every application with its member count.
pub(crate) async fn list(store: &dyn Store) -> Result<Vec<ApplicationSummary>> {
    let mut summaries = Vec::new();
    for application in store.list_applications().await? {
        let members = active_members(store, &application.id).await?.len();
        summaries.push(ApplicationSummary {
            application,
            members,
        });
    }
    Ok(summaries)
}

/// Show one application with its members.
pub(crate) async fn show(store: &dyn Store, key: &str) -> Result<ApplicationDetail> {
    let application = resolve_application(store, key).await?;
    let members = active_members(store, &application.id).await?;
    Ok(ApplicationDetail {
        application,
        members,
    })
}

/// Re-infer applications from the current evidence and persist them.
///
/// Manual precedence: assets with a manual membership anywhere, or an
/// exclusion tombstone anywhere, are never re-inferred. Existing inferred
/// applications are matched to candidates by member set, so re-running
/// discovery on unchanged evidence refreshes the same entities and
/// manual overrides survive.
///
/// ponytail: exact member-set matching; membership drift (a group that
/// grows or shrinks) creates a new application and drops the old one's
/// manual overrides — fuzzy overlap matching if drift proves common.
pub(crate) async fn discover(store: &dyn Store) -> Result<Vec<ApplicationSummary>> {
    let audit = begin_audit(
        store,
        "applications.discover",
        "inventory",
        Some("application inference"),
    )
    .await?;
    let result: Result<Vec<ApplicationSummary>> = async {
        // Assets the user has explicitly spoken about: manual members
        // and exclusion tombstones, across every application.
        let mut blocked: HashSet<String> = HashSet::new();
        let mut stored: Vec<(Application, HashSet<String>)> = Vec::new();
        for application in store.list_applications().await? {
            let mut active_inferred: HashSet<String> = HashSet::new();
            for member in store.list_application_members(&application.id).await? {
                if member.is_excluded || member.source == AppSource::Manual {
                    blocked.insert(member.asset_id.clone());
                }
                if member.source == AppSource::Inferred && !member.is_excluded {
                    active_inferred.insert(member.asset_id);
                }
            }
            if application.source == AppSource::Inferred {
                stored.push((application, active_inferred));
            }
        }

        let assets = store.list_assets().await?;
        let dependencies = store.list_dependencies().await?;
        let evidence = store.list_dependency_evidence().await?;
        let candidates = orbyn::applications::infer(&InferenceInput {
            assets,
            dependencies,
            evidence,
        });

        struct Candidate {
            id: String,
            name: String,
            confidence: f32,
            members: Vec<InferredMember>,
            set: HashSet<String>,
        }
        let mut fresh: Vec<Candidate> = Vec::new();
        for candidate in candidates {
            let members: Vec<InferredMember> = candidate
                .members
                .into_iter()
                .filter(|m| !blocked.contains(&m.asset_id))
                .collect();
            if members.len() < 2 {
                continue; // a single asset is not an application
            }
            let ids: Vec<&str> = members.iter().map(|m| m.asset_id.as_str()).collect();
            fresh.push(Candidate {
                id: member_set_id(&ids),
                name: candidate.name,
                confidence: candidate.confidence,
                set: members.iter().map(|m| m.asset_id.clone()).collect(),
                members,
            });
        }

        // Stale inferred applications (no matching candidate) are removed
        // first, freeing their names for re-derivation.
        let mut removed = 0usize;
        for (application, set) in &stored {
            if !fresh.iter().any(|c| c.set == *set) {
                store.delete_application(&application.id).await?;
                removed += 1;
            }
        }

        let mut created = 0usize;
        let mut refreshed = 0usize;
        for candidate in &fresh {
            if let Some((application, _)) = stored.iter().find(|(_, set)| *set == candidate.set) {
                store
                    .update_application_confidence(&application.id, candidate.confidence)
                    .await?;
                store
                    .replace_inferred_members(
                        &application.id,
                        member_rows(&application.id, &candidate.members),
                    )
                    .await?;
                refreshed += 1;
            } else {
                // A derived name may already be taken (a manual
                // application or another group): fall back to the id.
                let name = match store.get_application(&candidate.name).await? {
                    Some(_) => candidate.id.clone(),
                    None => candidate.name.clone(),
                };
                let now = Utc::now();
                store
                    .create_application(Application {
                        id: candidate.id.clone(),
                        name,
                        source: AppSource::Inferred,
                        confidence: candidate.confidence,
                        created_at: now,
                        updated_at: now,
                    })
                    .await?;
                store
                    .replace_inferred_members(
                        &candidate.id,
                        member_rows(&candidate.id, &candidate.members),
                    )
                    .await?;
                created += 1;
            }
        }

        eprintln!(
            "Applications: {} discovered ({created} created, {refreshed} refreshed, {removed} removed).",
            fresh.len()
        );
        list(store).await
    }
    .await;
    finish_audit_result(store, audit, result).await
}

/// Create an empty manual application.
pub(crate) async fn create(store: &dyn Store, name: String) -> Result<()> {
    let audit = begin_audit(
        store,
        "applications.create",
        &name,
        Some("manual application"),
    )
    .await?;
    let result: Result<()> = async {
        let now = Utc::now();
        store
            .create_application(Application {
                id: uuid::Uuid::new_v4().to_string(),
                name: name.clone(),
                source: AppSource::Manual,
                confidence: 1.0,
                created_at: now,
                updated_at: now,
            })
            .await?;
        eprintln!(
            "Application '{name}' created. Add members with `orbyn applications add {name} <asset>`."
        );
        Ok(())
    }
    .await;
    finish_audit_result(store, audit, result).await
}

/// Manually add an asset to an application. On an inferred member this
/// upgrades the row to manual, so discovery stops managing it.
pub(crate) async fn add(store: &dyn Store, application: String, asset: String) -> Result<()> {
    let audit = begin_audit(
        store,
        "applications.add",
        &format!("{application} += {asset}"),
        Some("manual member"),
    )
    .await?;
    let result: Result<()> = async {
        let application = resolve_application(store, &application).await?;
        let asset = resolve_asset(store, &asset).await?;
        store
            .add_application_member(ApplicationMember {
                application_id: application.id.clone(),
                asset_id: asset.id.clone(),
                source: AppSource::Manual,
                confidence: 1.0,
                evidence: Vec::new(),
                is_excluded: false,
            })
            .await?;
        eprintln!(
            "Added {} to '{}'.",
            asset
                .hostname
                .clone()
                .unwrap_or_else(|| asset.ip.to_string()),
            application.name
        );
        Ok(())
    }
    .await;
    finish_audit_result(store, audit, result).await
}

/// Remove an asset from an application. An inferred member becomes an
/// exclusion tombstone; a manual member row is deleted.
pub(crate) async fn remove(store: &dyn Store, application: String, asset: String) -> Result<()> {
    let audit = begin_audit(
        store,
        "applications.remove",
        &format!("{application} -= {asset}"),
        Some("member removal"),
    )
    .await?;
    let result: Result<()> = async {
        let application = resolve_application(store, &application).await?;
        let asset = resolve_asset(store, &asset).await?;
        let label = asset
            .hostname
            .clone()
            .unwrap_or_else(|| asset.ip.to_string());
        let removed = store
            .remove_application_member(&application.id, &asset.id)
            .await?;
        if !removed {
            anyhow::bail!("{label} is not a member of '{}'", application.name);
        }
        eprintln!("Removed {label} from '{}'.", application.name);
        Ok(())
    }
    .await;
    finish_audit_result(store, audit, result).await
}

/// Aggregate dependency edges crossing application boundaries into
/// application-to-application edges. Edges inside one application or
/// touching unassigned assets are not application edges.
pub(crate) async fn application_edges(store: &dyn Store) -> Result<Vec<ApplicationEdge>> {
    let mut owner: HashMap<String, String> = HashMap::new();
    for application in store.list_applications().await? {
        for member in active_members(store, &application.id).await? {
            // ponytail: an asset in two applications counts for the
            // lexicographically last name; per-edge attribution if dual
            // membership shows up in practice.
            owner.insert(member.asset_id, application.name.clone());
        }
    }
    let mut counts: HashMap<(String, String), usize> = HashMap::new();
    for d in store.list_dependencies().await? {
        if let (Some(source), Some(target)) =
            (owner.get(&d.source_asset_id), owner.get(&d.target_asset_id))
        {
            if source != target {
                *counts.entry((source.clone(), target.clone())).or_insert(0) += 1;
            }
        }
    }
    let mut edges: Vec<ApplicationEdge> = counts
        .into_iter()
        .map(|((source, target), edges)| ApplicationEdge {
            source,
            target,
            edges,
        })
        .collect();
    edges.sort_by(|a, b| (&a.source, &a.target).cmp(&(&b.source, &b.target)));
    Ok(edges)
}

/// Assess one application: the rule engine runs unchanged over the full
/// inventory, then findings and scores are filtered to the members and
/// rolled up (counts, hubs, external coupling, right-sizing readiness).
pub(crate) async fn assess(store: &dyn Store, key: &str) -> Result<ApplicationAssessment> {
    let detail = show(store, key).await?;
    let members: HashSet<String> = detail.members.iter().map(|m| m.asset_id.clone()).collect();
    let input = crate::app::assessment::assessment_input(store).await?;
    let report = orbyn::assessment::run_assessment(&input);

    let findings: Vec<Finding> = report
        .findings
        .iter()
        .filter(|f| f.asset_id.as_deref().is_some_and(|id| members.contains(id)))
        .cloned()
        .collect();
    let asset_scores: Vec<AssetScore> = report
        .asset_scores
        .iter()
        .filter(|s| members.contains(&s.asset_id))
        .cloned()
        .collect();

    let overall_score = if asset_scores.is_empty() {
        0
    } else {
        let total: u32 = asset_scores.iter().map(|s| s.score as u32).sum();
        (total as f64 / asset_scores.len() as f64).round() as u8
    };

    let mut internal = 0usize;
    let mut external = 0usize;
    let mut unconfirmed = 0usize;
    for d in &input.dependencies {
        let (source_in, target_in) = (
            members.contains(&d.source_asset_id),
            members.contains(&d.target_asset_id),
        );
        if source_in && target_in {
            internal += 1;
        } else if source_in || target_in {
            external += 1;
        } else {
            continue;
        }
        if !d.confirmed {
            unconfirmed += 1;
        }
    }

    let mut hub_assets: Vec<String> = findings
        .iter()
        .filter(|f| f.rule_id == "dep.hub")
        .filter_map(|f| f.asset_id.clone())
        .collect();
    hub_assets.sort();
    hub_assets.dedup();
    let mut externally_coupled_assets: Vec<String> = findings
        .iter()
        .filter(|f| f.rule_id == "dep.external")
        .filter_map(|f| f.asset_id.clone())
        .collect();
    externally_coupled_assets.sort();
    externally_coupled_assets.dedup();

    Ok(ApplicationAssessment {
        application: detail.application,
        rules_version: report.rules_version,
        assets: members.len(),
        overall_score,
        complexity: orbyn::assessment::complexity_band(overall_score),
        internal_dependencies: internal,
        external_dependencies: external,
        unconfirmed_dependencies: unconfirmed,
        high_findings: findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count(),
        warning_findings: findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count(),
        hub_assets,
        externally_coupled_assets,
        right_sizing_findings: findings
            .iter()
            .filter(|f| f.rule_id.starts_with("rs."))
            .count(),
        findings,
        asset_scores,
    })
}

/// Persisted applications as wave-planning units; empty when nothing has
/// been discovered or created yet (the planner then falls back to the
/// ephemeral groups the assessment engine computes).
pub(crate) async fn wave_units(store: &dyn Store) -> Result<Vec<ApplicationGroup>> {
    let mut units = Vec::new();
    for application in store.list_applications().await? {
        let asset_ids: Vec<String> = active_members(store, &application.id)
            .await?
            .into_iter()
            .map(|m| m.asset_id)
            .collect();
        if asset_ids.is_empty() {
            continue;
        }
        units.push(ApplicationGroup {
            id: application.name,
            asset_ids,
            edge_count: 0,
        });
    }
    Ok(units)
}

/// Persist inferred members as store rows.
fn member_rows(application_id: &str, members: &[InferredMember]) -> Vec<ApplicationMember> {
    members
        .iter()
        .map(|m| ApplicationMember {
            application_id: application_id.to_string(),
            asset_id: m.asset_id.clone(),
            source: AppSource::Inferred,
            confidence: m.confidence,
            evidence: m.evidence.clone(),
            is_excluded: false,
        })
        .collect()
}

/// Deterministic id for a newly inferred application: FNV-1a over the
/// sorted member ids, so it is a pure function of the member set.
/// Matching runs on member sets, so the id only has to be unique and
/// stable, not meaningful.
fn member_set_id(ids: &[&str]) -> String {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for id in &ids {
        for byte in id.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!("app-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_set_id_is_order_independent_and_set_sensitive() {
        let a = member_set_id(&["x", "y"]);
        assert_eq!(a, member_set_id(&["y", "x"]));
        assert_ne!(a, member_set_id(&["x", "z"]));
        assert!(a.starts_with("app-"));
    }
}
