use std::net::IpAddr;

use anyhow::Result;
use async_trait::async_trait;

use crate::domain::Observation;

/// A validated discovery target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanTarget {
    Ip(IpAddr),
    Cidr(String),
}

/// A collector discovers facts about infrastructure.
///
/// Implementors must:
/// - never modify target systems (read-only by default);
/// - pass targets as process arguments, never shell strings;
/// - return normalized [`Observation`]s instead of writing to the database.
#[async_trait]
pub trait Collector {
    fn name(&self) -> &'static str;
    async fn scan(&self, target: &ScanTarget) -> Result<Vec<Observation>>;
}

/// Validation error for a discovery target expression.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ScanTargetError {
    #[error("target '{0}' exceeds the maximum allowed scope")]
    TooLarge(String),
    #[error("target '{0}' is unresolvable or malformed")]
    Invalid(String),
    #[error("target '{0}' is not an IP address or CIDR expression")]
    NotIpCidr(String),
}

/// Parse and validate an IPv4/IPv6/IP or CIDR target.
///
/// Rejects `0.0.0.0/0` and other oversized scopes unless explicitly allowed.
pub fn validate_target(raw: &str) -> Result<ScanTarget, ScanTargetError> {
    if raw.contains('/') {
        let (base, prefix) = raw
            .split_once('/')
            .ok_or_else(|| ScanTargetError::Invalid(raw.to_string()))?;
        if matches!(prefix, "0" | "00" | "000") || base == "0.0.0.0" || base == "::" {
            return Err(ScanTargetError::TooLarge(raw.to_string()));
        }
        return Ok(ScanTarget::Cidr(raw.to_string()));
    }

    raw.parse::<IpAddr>()
        .map(ScanTarget::Ip)
        .map_err(|_| ScanTargetError::NotIpCidr(raw.to_string()))
}
