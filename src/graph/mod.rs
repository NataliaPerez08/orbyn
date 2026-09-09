//! Dependency graph.
//!
//! Assets, services and observed relationships form a directed graph where an
//! edge means "source depends on target":
//!
//! ```text
//! Asset A --tcp/5432--> Asset B
//! ```
//!
//! Every edge retains its evidence source and a confidence value. Guesses must
//! look like guesses.

use std::collections::HashMap;

use crate::domain::Dependency;

/// In-memory view of the dependency graph built from persisted edges.
#[derive(Debug, Default, Clone)]
pub struct Graph {
    edges: Vec<Dependency>,
    by_source: HashMap<String, Vec<usize>>,
    by_target: HashMap<String, Vec<usize>>,
}

impl Graph {
    pub fn build(edges: Vec<Dependency>) -> Self {
        let mut by_source: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_target: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, edge) in edges.iter().enumerate() {
            by_source
                .entry(edge.source_asset_id.clone())
                .or_default()
                .push(i);
            by_target
                .entry(edge.target_asset_id.clone())
                .or_default()
                .push(i);
        }
        Self {
            edges,
            by_source,
            by_target,
        }
    }

    /// Everything that asset `id` depends on.
    pub fn dependents_of(&self, id: &str) -> Vec<&Dependency> {
        self.by_source
            .get(id)
            .into_iter()
            .flatten()
            .map(|&i| &self.edges[i])
            .collect()
    }

    /// Everything that depends on asset `id`.
    pub fn dependants_upon(&self, id: &str) -> Vec<&Dependency> {
        self.by_target
            .get(id)
            .into_iter()
            .flatten()
            .map(|&i| &self.edges[i])
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep(source: &str, target: &str, port: u16) -> Dependency {
        Dependency {
            source_asset_id: source.into(),
            target_asset_id: target.into(),
            proto: "tcp".into(),
            port,
            evidence_source: "active-connections".into(),
            confidence: 0.9,
            confirmed: false,
        }
    }

    #[test]
    fn forward_and_reverse_lookups() {
        let graph = Graph::build(vec![
            dep("web", "api", 443),
            dep("api", "db", 5432),
            dep("worker", "db", 5432),
        ]);

        let dependents = graph.dependents_of("api");
        assert_eq!(dependents.len(), 1);
        assert_eq!(dependents[0].target_asset_id, "db");

        let dependants = graph.dependants_upon("db");
        assert_eq!(dependants.len(), 2);
        let mut sources: Vec<&str> = dependants
            .iter()
            .map(|d| d.source_asset_id.as_str())
            .collect();
        sources.sort();
        assert_eq!(sources, vec!["api", "worker"]);
    }

    #[test]
    fn unknown_asset_has_no_neighbours() {
        let graph = Graph::build(vec![dep("a", "b", 1)]);
        assert!(graph.dependents_of("missing").is_empty());
        assert!(graph.dependants_upon("missing").is_empty());
    }

    #[test]
    fn empty_graph() {
        let graph = Graph::build(vec![]);
        assert!(graph.dependents_of("x").is_empty());
        assert!(graph.dependants_upon("x").is_empty());
    }
}
