//! Versioned inference weights (`application-inference/v1`).
//!
//! Every weight is part of the inference model: changing one is a model
//! change and must bump [`super::INFERENCE_VERSION`]. Weights follow the
//! roadmap's conceptual table:
//!
//! ```text
//! Manual dependency              very strong
//! Observed runtime dependency    strong
//! Repeated connection evidence   strong (observation counts surface in
//!                                 the evidence description)
//! Shared backend                 medium
//! Known service combination      medium
//! Matching owner                 medium
//! Matching tag                   weak-medium
//! Matching environment           weak
//! DNS alias                      weak
//! Same subnet                    very weak
//! ```

/// Weight of a manual dependency edge between two members.
pub const MANUAL_EDGE: f32 = 1.0;
/// Weight of an observed runtime connection between two members.
pub const RUNTIME_EDGE: f32 = 0.9;
/// Weight of an edge of unknown provenance.
pub const OTHER_EDGE: f32 = 0.5;
/// Weight of a known service combination: an edge onto a known database
/// or broker port.
pub const SERVICE_COMBO: f32 = 0.6;
/// Weight of a shared in-group backend (this member and another member
/// both depend on the same target).
pub const SHARED_BACKEND: f32 = 0.6;
/// Weight of a matching owner across the group.
pub const MATCHING_OWNER: f32 = 0.5;
/// Weight of a tag shared by at least two members.
pub const MATCHING_TAG: f32 = 0.3;
/// Weight of a matching environment across the group.
pub const MATCHING_ENVIRONMENT: f32 = 0.2;
/// Weight of a DNS-derived edge (identity evidence, not runtime
/// coupling).
pub const DNS_EDGE: f32 = 0.4;
/// Weight of all members sitting in the same subnet.
pub const SAME_SUBNET: f32 = 0.1;
