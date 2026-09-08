//! Application grouping primitives (v0.5).
//!
//! Assets coupled by runtime or manual dependency edges probably belong to
//! the same application and should migrate together. Grouping is a union-find
//! over the dependency graph; DNS alias edges are excluded because they are
//! identity evidence, not runtime coupling.

use std::collections::HashMap;

use super::ApplicationGroup;
use crate::domain::{Asset, Dependency};

/// Group assets connected by non-DNS dependency edges.
///
/// Returns components of two or more assets, largest first, with stable ids
/// (`app-1`, `app-2`, ...) and the number of edges inside each group.
pub fn application_groups(assets: &[Asset], dependencies: &[Dependency]) -> Vec<ApplicationGroup> {
    let edges: Vec<&Dependency> = dependencies
        .iter()
        .filter(|d| d.evidence_source != "dns")
        .collect();
    if edges.is_empty() {
        return Vec::new();
    }

    let mut parent: HashMap<String, String> = assets
        .iter()
        .map(|a| (a.id.clone(), a.id.clone()))
        .collect();

    fn find(parent: &mut HashMap<String, String>, id: &str) -> String {
        let mut root = id.to_string();
        while parent[&root] != root {
            root = parent[&root].clone();
        }
        // path compression
        let mut current = id.to_string();
        while parent[&current] != current {
            let next = parent[&current].clone();
            parent.insert(current, root.clone());
            current = next;
        }
        root
    }

    for edge in &edges {
        let (left, right) = (edge.source_asset_id.clone(), edge.target_asset_id.clone());
        if !parent.contains_key(&left) || !parent.contains_key(&right) {
            continue;
        }
        let (root_left, root_right) = (find(&mut parent, &left), find(&mut parent, &right));
        if root_left != root_right {
            // union by lexicographic order for determinism
            let (winner, loser) = if root_left <= root_right {
                (root_left, root_right)
            } else {
                (root_right, root_left)
            };
            parent.insert(loser, winner);
        }
    }

    // Collect components.
    let mut components: HashMap<String, Vec<String>> = HashMap::new();
    for asset in assets {
        let root = find(&mut parent, &asset.id);
        components.entry(root).or_default().push(asset.id.clone());
    }

    let edge_count = |members: &[String]| -> usize {
        edges
            .iter()
            .filter(|e| {
                members.contains(&e.source_asset_id) && members.contains(&e.target_asset_id)
            })
            .count()
    };

    let mut groups: Vec<(Vec<String>, usize)> = components
        .into_values()
        .filter(|members| members.len() >= 2)
        .map(|mut members| {
            members.sort();
            let count = edge_count(&members);
            (members, count)
        })
        .collect();

    groups.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));

    groups
        .into_iter()
        .enumerate()
        .map(|(i, (asset_ids, edge_count))| ApplicationGroup {
            id: format!("app-{}", i + 1),
            asset_ids,
            edge_count,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Dependency;
    use chrono::Utc;

    fn asset(id: &str) -> Asset {
        Asset {
            id: id.into(),
            ip: "10.0.0.1".parse().unwrap(),
            hostname: None,
            device_class: None,
            os_name: None,
            os_version: None,
            environment: None,
            owner: None,
            criticality: None,
            tags: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    fn edge(source: &str, target: &str, evidence: &str) -> Dependency {
        Dependency {
            source_asset_id: source.into(),
            target_asset_id: target.into(),
            proto: "tcp".into(),
            port: 5432,
            evidence_source: evidence.into(),
            confidence: 0.9,
            confirmed: false,
        }
    }

    #[test]
    fn connected_assets_form_one_group() {
        let assets = vec![asset("web"), asset("api"), asset("db")];
        let deps = vec![
            edge("web", "api", "active-connections"),
            edge("api", "db", "manual"),
        ];
        let groups = application_groups(&assets, &deps);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].id, "app-1");
        assert_eq!(groups[0].asset_ids, vec!["api", "db", "web"]);
        assert_eq!(groups[0].edge_count, 2);
    }

    #[test]
    fn separate_components_stay_separate() {
        let assets = vec![asset("a"), asset("b"), asset("c"), asset("d")];
        let deps = vec![
            edge("a", "b", "active-connections"),
            edge("c", "d", "manual"),
        ];
        let groups = application_groups(&assets, &deps);
        assert_eq!(groups.len(), 2);
        // largest first; equal size -> lexicographic
        assert_eq!(groups[0].asset_ids, vec!["a", "b"]);
        assert_eq!(groups[1].asset_ids, vec!["c", "d"]);
    }

    #[test]
    fn dns_edges_do_not_group() {
        let assets = vec![asset("a"), asset("b")];
        let deps = vec![edge("a", "b", "dns")];
        assert!(application_groups(&assets, &deps).is_empty());
    }

    #[test]
    fn singletons_are_not_groups() {
        let assets = vec![asset("a"), asset("b")];
        assert!(application_groups(&assets, &[]).is_empty());
    }
}
