//! Application inference engine (v1.1).
//!
//! Reconstructs logical applications from the dependency graph: assets
//! coupled by runtime or manual edges form one application, and every
//! membership carries a confidence score plus the evidence records
//! behind it. Grouping reuses the union-find in
//! [`crate::assessment::grouping`], so metadata signals can boost
//! confidence but never form a group on their own.
//!
//! The engine is a pure function over an [`InferenceInput`] snapshot:
//! identical evidence and rule versions produce identical results.

mod signals;
mod weights;

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::assessment::grouping::application_groups;
use crate::domain::{ApplicationEvidence, Asset, Dependency, DependencyEvidence, EvidenceKind};

/// Version of the inference model. Any weight or signal change must bump
/// this; it is stamped on every inferred application.
pub const INFERENCE_VERSION: &str = "application-inference/v1";

/// Everything the inference engine may look at: a full inventory
/// snapshot.
#[derive(Debug, Clone, Default)]
pub struct InferenceInput {
    pub assets: Vec<Asset>,
    pub dependencies: Vec<Dependency>,
    /// Aggregated per-edge connection observation counts.
    pub evidence: Vec<DependencyEvidence>,
}

/// An application reconstructed from evidence, before persistence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InferredApplication {
    /// Stable group id (`app-1`, `app-2`, ...).
    pub id: String,
    /// Derived name: hostname prefix, shared owner, or the group id.
    pub name: String,
    /// Mean member confidence, 0.0-1.0.
    pub confidence: f32,
    pub members: Vec<InferredMember>,
}

/// One asset's inferred membership, with the evidence behind it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InferredMember {
    pub asset_id: String,
    /// Noisy-OR combination of the evidence weights, 0.0-1.0.
    pub confidence: f32,
    pub evidence: Vec<ApplicationEvidence>,
}

/// Infer applications from the snapshot. Groups of a single asset are
/// not applications; an inventory without dependency edges yields none.
pub fn infer(input: &InferenceInput) -> Vec<InferredApplication> {
    application_groups(&input.assets, &input.dependencies)
        .into_iter()
        .map(|group| score_group(&group, input))
        .collect()
}

/// Score one group: assemble per-member evidence records, combine them
/// into confidences, and derive a name.
fn score_group(
    group: &crate::assessment::ApplicationGroup,
    input: &InferenceInput,
) -> InferredApplication {
    let member_ids: HashSet<&str> = group.asset_ids.iter().map(String::as_str).collect();
    let asset_by_id: HashMap<&str, &Asset> =
        input.assets.iter().map(|a| (a.id.as_str(), a)).collect();

    // In-group edges, deterministically ordered.
    let mut edges: Vec<&Dependency> = input
        .dependencies
        .iter()
        .filter(|d| {
            member_ids.contains(d.source_asset_id.as_str())
                && member_ids.contains(d.target_asset_id.as_str())
        })
        .collect();
    edges.sort_by(|a, b| {
        a.source_asset_id
            .cmp(&b.source_asset_id)
            .then_with(|| a.target_asset_id.cmp(&b.target_asset_id))
            .then_with(|| a.proto.cmp(&b.proto))
            .then_with(|| a.port.cmp(&b.port))
    });

    // Observation counts per ordered member pair.
    let mut observations: HashMap<(&str, &str), u32> = HashMap::new();
    for ev in &input.evidence {
        if member_ids.contains(ev.source_asset_id.as_str())
            && member_ids.contains(ev.target_asset_id.as_str())
        {
            *observations
                .entry((ev.source_asset_id.as_str(), ev.target_asset_id.as_str()))
                .or_insert(0) += ev.observations;
        }
    }

    let label = |id: &str| -> String {
        asset_by_id
            .get(id)
            .and_then(|a| a.hostname.clone())
            .unwrap_or_else(|| id.to_string())
    };

    let members: Vec<&Asset> = group
        .asset_ids
        .iter()
        .filter_map(|id| asset_by_id.get(id.as_str()).copied())
        .collect();

    // Group-level metadata signals. These boost confidence only; they
    // never form groups (grouping runs on dependency edges alone).
    let shared_owner = shared_value(&members, |a| a.owner.as_deref());
    let shared_environment = shared_value(&members, |a| a.environment.as_deref());
    let mut tag_counts: HashMap<&str, usize> = HashMap::new();
    for asset in &members {
        for tag in &asset.tags {
            *tag_counts.entry(tag.as_str()).or_insert(0) += 1;
        }
    }
    let shared_tags: Vec<&str> = {
        let mut tags: Vec<&str> = tag_counts
            .iter()
            .filter(|(_, &count)| count >= 2)
            .map(|(tag, _)| *tag)
            .collect();
        tags.sort_unstable();
        tags
    };
    let subnet = {
        let subnets: HashSet<String> = members
            .iter()
            .filter_map(|a| signals::subnet_of(a))
            .collect();
        if members.iter().all(|a| signals::subnet_of(a).is_some()) && subnets.len() == 1 {
            subnets.into_iter().next()
        } else {
            None
        }
    };

    let mut inferred_members: Vec<InferredMember> = Vec::new();
    for id in &group.asset_ids {
        let mut records: Vec<ApplicationEvidence> = Vec::new();

        // Edge evidence: an edge ties both endpoints to the application,
        // so each endpoint carries the record.
        for edge in &edges {
            if edge.source_asset_id != *id && edge.target_asset_id != *id {
                continue;
            }
            let (source, target) = (&edge.source_asset_id, &edge.target_asset_id);
            let obs = observations
                .get(&(source.as_str(), target.as_str()))
                .copied()
                .unwrap_or(0);
            match EvidenceKind::parse(&edge.evidence_source) {
                EvidenceKind::Manual => records.push(record(
                    "manual-dependency",
                    weights::MANUAL_EDGE,
                    format!("manual dependency: {} -> {}", label(source), label(target)),
                )),
                EvidenceKind::ActiveConnections => {
                    records.push(record(
                        "runtime-connection",
                        weights::RUNTIME_EDGE,
                        format!(
                            "runtime connection: {} -> {}:{} (observations: {obs})",
                            label(source),
                            label(target),
                            edge.port
                        ),
                    ));
                    if let Some(service) = signals::known_service(edge.port) {
                        records.push(record(
                            "service-combination",
                            weights::SERVICE_COMBO,
                            format!("{service} detected on {}", label(target)),
                        ));
                    }
                }
                EvidenceKind::Dns => records.push(record(
                    "dns-alias",
                    weights::DNS_EDGE,
                    format!("DNS alias: {} ~ {}", label(source), label(target)),
                )),
                EvidenceKind::Other => records.push(record(
                    "other-dependency",
                    weights::OTHER_EDGE,
                    format!("dependency: {} -> {}", label(source), label(target)),
                )),
            }
        }

        // Shared backend neighborhood: this member targets an in-group
        // backend that another member also targets.
        let mut shared: Vec<String> = Vec::new();
        for target in targets_of(id, &edges) {
            if edges
                .iter()
                .any(|e| e.source_asset_id != *id && e.target_asset_id == target)
            {
                shared.push(label(target));
            }
        }
        if !shared.is_empty() {
            shared.sort();
            shared.dedup();
            records.push(record(
                "shared-backend",
                weights::SHARED_BACKEND,
                format!("shared dependency neighborhood: {}", shared.join(", ")),
            ));
        }

        // Metadata signals: only members carrying the value score it.
        if let Some(owner) = &shared_owner {
            if asset_by_id
                .get(id.as_str())
                .and_then(|a| a.owner.as_deref())
                == Some(owner.as_str())
            {
                records.push(record(
                    "matching-owner",
                    weights::MATCHING_OWNER,
                    format!("matching owner: {owner}"),
                ));
            }
        }
        if let Some(environment) = &shared_environment {
            if asset_by_id
                .get(id.as_str())
                .and_then(|a| a.environment.as_deref())
                == Some(environment.as_str())
            {
                records.push(record(
                    "matching-environment",
                    weights::MATCHING_ENVIRONMENT,
                    format!("matching environment: {environment}"),
                ));
            }
        }
        for tag in &shared_tags {
            if asset_by_id
                .get(id.as_str())
                .is_some_and(|a| a.tags.iter().any(|t| t == tag))
            {
                records.push(record(
                    "matching-tag",
                    weights::MATCHING_TAG,
                    format!("matching tag: {tag}"),
                ));
            }
        }
        if let Some(subnet) = &subnet {
            records.push(record(
                "same-subnet",
                weights::SAME_SUBNET,
                format!("same subnet: {subnet}"),
            ));
        }

        // Stable order keeps both the display and the float fold
        // deterministic.
        records.sort_by(|a, b| {
            a.source
                .cmp(&b.source)
                .then_with(|| a.description.cmp(&b.description))
        });
        let confidence = combine(&records);
        inferred_members.push(InferredMember {
            asset_id: id.clone(),
            confidence,
            evidence: records,
        });
    }

    let confidence = if inferred_members.is_empty() {
        0.0
    } else {
        inferred_members.iter().map(|m| m.confidence).sum::<f32>() / inferred_members.len() as f32
    };

    InferredApplication {
        id: group.id.clone(),
        name: derive_name(group, &input.assets),
        confidence,
        members: inferred_members,
    }
}

/// Noisy-OR combination of evidence weights: every independent signal
/// closes part of the gap to certainty. Records must already be sorted;
/// the fold order is part of determinism.
fn combine(records: &[ApplicationEvidence]) -> f32 {
    let doubt = records.iter().map(|r| 1.0 - r.weight).product::<f32>();
    (1.0 - doubt).clamp(0.0, 1.0)
}

/// The single value shared by every member that has one, when at least
/// two members carry it.
fn shared_value<'a>(
    members: &[&'a Asset],
    get: impl Fn(&'a Asset) -> Option<&'a str>,
) -> Option<String> {
    let values: Vec<&str> = members.iter().filter_map(|a| get(a)).collect();
    if values.len() >= 2 && values.iter().all(|v| *v == values[0]) {
        Some(values[0].to_string())
    } else {
        None
    }
}

/// Distinct in-group targets of this member's outgoing edges, sorted.
fn targets_of<'a>(id: &str, edges: &[&'a Dependency]) -> Vec<&'a str> {
    let mut targets: Vec<&str> = edges
        .iter()
        .filter(|e| e.source_asset_id == id)
        .map(|e| e.target_asset_id.as_str())
        .collect();
    targets.sort_unstable();
    targets.dedup();
    targets
}

/// Derive a deterministic name: a hostname key shared by a majority of
/// members, then a shared owner, then the stable group id.
fn derive_name(group: &crate::assessment::ApplicationGroup, assets: &[Asset]) -> String {
    let by_id: HashMap<&str, &Asset> = assets.iter().map(|a| (a.id.as_str(), a)).collect();
    let members: Vec<&Asset> = group
        .asset_ids
        .iter()
        .filter_map(|id| by_id.get(id.as_str()).copied())
        .collect();

    // 1. Hostname key held by a majority (at least two members).
    let mut keys: HashMap<String, usize> = HashMap::new();
    for asset in &members {
        if let Some(key) = signals::hostname_key(asset) {
            *keys.entry(key).or_insert(0) += 1;
        }
    }
    let threshold = std::cmp::max(2, members.len() / 2);
    let mut candidates: Vec<(String, usize)> = keys
        .into_iter()
        .filter(|(_, count)| *count >= threshold)
        .collect();
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if let Some((key, _)) = candidates.first() {
        let name = signals::slugify(key);
        if !name.is_empty() {
            return name;
        }
    }

    // 2. Owner shared by every member that has one (at least two).
    if let Some(owner) = shared_value(&members, |a| a.owner.as_deref()) {
        let name = signals::slugify(&owner);
        if !name.is_empty() {
            return name;
        }
    }

    // 3. Stable fallback.
    group.id.clone()
}

fn record(source: &str, weight: f32, description: String) -> ApplicationEvidence {
    ApplicationEvidence {
        source: source.into(),
        weight,
        description,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn asset(id: &str, ip: &str) -> Asset {
        Asset {
            id: id.into(),
            ip: ip.parse().unwrap(),
            hostname: None,
            device_class: None,
            os_name: None,
            os_version: None,
            sys_descr: None,
            environment: None,
            owner: None,
            criticality: None,
            tags: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    fn edge(source: &str, target: &str, port: u16) -> Dependency {
        Dependency {
            source_asset_id: source.into(),
            target_asset_id: target.into(),
            proto: "tcp".into(),
            port,
            evidence_source: EvidenceKind::ActiveConnections.as_str().into(),
            confidence: 0.9,
            confirmed: false,
        }
    }

    fn obs(source: &str, target: &str, count: u32) -> DependencyEvidence {
        DependencyEvidence {
            source_asset_id: source.into(),
            target_asset_id: target.into(),
            proto: "tcp".into(),
            port: 0,
            observations: count,
        }
    }

    fn input(
        assets: Vec<Asset>,
        dependencies: Vec<Dependency>,
        evidence: Vec<DependencyEvidence>,
    ) -> InferenceInput {
        InferenceInput {
            assets,
            dependencies,
            evidence,
        }
    }

    fn all_records(app: &InferredApplication) -> Vec<&ApplicationEvidence> {
        app.members.iter().flat_map(|m| m.evidence.iter()).collect()
    }

    #[test]
    fn runtime_edges_infer_one_application() {
        let assets = vec![
            asset("a", "10.0.0.1"),
            asset("b", "10.0.0.2"),
            asset("c", "10.0.0.3"),
        ];
        let deps = vec![edge("a", "b", 443), edge("b", "c", 5432)];
        let apps = infer(&input(
            assets,
            deps,
            vec![obs("a", "b", 823), obs("b", "c", 483)],
        ));
        assert_eq!(apps.len(), 1);
        let app = &apps[0];
        assert_eq!(app.id, "app-1");
        assert_eq!(app.members.len(), 3);
        for member in &app.members {
            assert!(
                member
                    .evidence
                    .iter()
                    .any(|r| r.source == "runtime-connection"),
                "every member carries edge evidence"
            );
            assert!(member.confidence > 0.9);
        }
        assert!(all_records(app)
            .iter()
            .any(|r| r.source == "service-combination" && r.description.contains("PostgreSQL")));
        assert!(all_records(app)
            .iter()
            .any(|r| r.description.contains("observations: 823")));
        assert!(all_records(app)
            .iter()
            .any(|r| r.source == "same-subnet" && r.description.contains("10.0.0.0/24")));
    }

    #[test]
    fn metadata_alone_never_groups() {
        let mut a = asset("a", "10.0.0.1");
        let mut b = asset("b", "10.0.0.2");
        for asset in [&mut a, &mut b] {
            asset.owner = Some("payments".into());
            asset.environment = Some("production".into());
            asset.tags = vec!["team-x".into()];
        }
        let apps = infer(&input(vec![a, b], Vec::new(), Vec::new()));
        assert!(
            apps.is_empty(),
            "metadata must never form an application on its own"
        );
    }

    #[test]
    fn inference_is_deterministic() {
        let assets = vec![
            asset("a", "10.0.0.1"),
            asset("b", "10.0.0.2"),
            asset("c", "10.0.0.3"),
        ];
        let deps = vec![edge("a", "b", 443), edge("b", "c", 6379)];
        let input = input(assets, deps, vec![obs("a", "b", 12), obs("b", "c", 30)]);
        assert_eq!(infer(&input), infer(&input));
    }

    #[test]
    fn name_comes_from_hostname_prefix() {
        let mut a = asset("a", "10.0.0.1");
        a.hostname = Some("frontend01".into());
        let mut b = asset("b", "10.0.0.2");
        b.hostname = Some("frontend02".into());
        let mut c = asset("c", "10.0.0.3");
        c.hostname = Some("backend01".into());
        let apps = infer(&input(
            vec![a, b, c],
            vec![edge("a", "c", 8080), edge("b", "c", 8080)],
            Vec::new(),
        ));
        assert_eq!(apps[0].name, "frontend");
    }

    #[test]
    fn name_comes_from_shared_owner() {
        let mut a = asset("a", "10.0.0.1");
        let mut b = asset("b", "10.0.0.2");
        a.owner = Some("payments team".into());
        b.owner = Some("payments team".into());
        let apps = infer(&input(vec![a, b], vec![edge("a", "b", 443)], Vec::new()));
        assert_eq!(apps[0].name, "payments-team");
    }

    #[test]
    fn name_falls_back_to_group_id() {
        let apps = infer(&input(
            vec![asset("a", "10.0.0.1"), asset("b", "10.0.0.2")],
            vec![edge("a", "b", 443)],
            Vec::new(),
        ));
        assert_eq!(apps[0].name, "app-1");
    }

    #[test]
    fn shared_backend_scores_sources_only() {
        let apps = infer(&input(
            vec![
                asset("f1", "10.0.0.1"),
                asset("f2", "10.0.0.2"),
                asset("be", "10.0.0.3"),
            ],
            vec![edge("f1", "be", 8080), edge("f2", "be", 8080)],
            Vec::new(),
        ));
        let app = &apps[0];
        for id in ["f1", "f2"] {
            let member = app.members.iter().find(|m| m.asset_id == id).unwrap();
            assert!(
                member.evidence.iter().any(|r| r.source == "shared-backend"),
                "{id} shares the backend"
            );
        }
        let backend = app.members.iter().find(|m| m.asset_id == "be").unwrap();
        assert!(
            !backend
                .evidence
                .iter()
                .any(|r| r.source == "shared-backend"),
            "the backend itself does not share itself"
        );
    }

    #[test]
    fn manual_edge_scores_full_confidence() {
        let mut dep = edge("a", "b", 443);
        dep.evidence_source = EvidenceKind::Manual.as_str().into();
        dep.confidence = 1.0;
        dep.confirmed = true;
        let apps = infer(&input(
            vec![asset("a", "10.0.0.1"), asset("b", "10.0.0.2")],
            vec![dep],
            Vec::new(),
        ));
        let app = &apps[0];
        for member in &app.members {
            assert!(member
                .evidence
                .iter()
                .any(|r| r.source == "manual-dependency" && r.weight == 1.0));
        }
        assert!((app.members[0].confidence - 1.0).abs() < f32::EPSILON);
    }
}
