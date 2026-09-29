//! Collector framework.
//!
//! Collectors transform external observations into the normalized domain
//! model ([`crate::domain::Observation`]). They never write to the database
//! directly — they return typed observations and the store handles persistence.
//!
//! Read-only by default: collectors must not modify the systems they inspect.

pub mod classify;
pub mod credentials;
pub mod dns;
pub mod nmap;
pub mod snmp;
pub mod ssh;
pub mod types;
pub mod windows;
pub mod winrm;

pub use credentials::CredentialProfile;
pub use types::{
    validate_target_with_policy, Collector, ScanTarget, ScanTargetError, MIN_IPV4_PREFIX,
    MIN_IPV6_PREFIX,
};

/// Validate a discovery target expression (IPv4, IPv6, or CIDR).
///
/// Rejects accidental unrestricted scans by default.
pub fn validate_target(raw: &str) -> Result<ScanTarget, ScanTargetError> {
    types::validate_target(raw)
}
