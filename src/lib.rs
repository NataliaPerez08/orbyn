//! Orbyn — infrastructure discovery, dependency mapping, and migration assessment.
//!
//! Orbyn is organized as a library plus a thin binary wrapper so that every
//! capability can also be embedded or reused by other tooling.

pub mod api;
pub mod assessment;
pub mod collectors;
pub mod config;
pub mod domain;
pub mod graph;
pub mod metrics;
pub mod store;
