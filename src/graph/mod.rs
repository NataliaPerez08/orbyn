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
