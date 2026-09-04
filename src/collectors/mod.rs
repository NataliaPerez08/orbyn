//! Collector framework.
//!
//! Collectors transform external observations into the normalized domain
//! model ([`crate::domain::Observation`]). They never write to the database
//! directly — they return typed observations and the store handles persistence.
//!
//! Read-only by default: collectors must not modify the systems they inspect.

pub mod nmap;
pub mod types;

pub use types::{Collector, ScanTarget, ScanTargetError};

/// Validate a discovery target expression (IPv4, IPv6, or CIDR).
///
/// Rejects accidental unrestricted scans by default.
pub fn validate_target(raw: &str) -> Result<ScanTarget, ScanTargetError> {
    types::validate_target(raw)
}
