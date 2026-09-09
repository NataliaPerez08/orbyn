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

/// CPU capacity facts normalized from `lscpu`, `/proc/cpuinfo` or
/// `Win32_Processor` before becoming a domain [`crate::domain::Capacity`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpuFacts {
    pub model: Option<String>,
    pub sockets: Option<u32>,
    pub cores: Option<u32>,
    pub threads: Option<u32>,
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
/// Rejects `0.0.0.0/0` and other oversized/unrestricted scopes by default,
/// and requires a real IP base plus a numeric in-range prefix for CIDR form.
pub fn validate_target(raw: &str) -> Result<ScanTarget, ScanTargetError> {
    if let Some((base, prefix)) = raw.split_once('/') {
        if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_digit()) {
            return Err(ScanTargetError::Invalid(raw.to_string()));
        }
        if base == "0.0.0.0" || base == "::" {
            return Err(ScanTargetError::TooLarge(raw.to_string()));
        }
        let addr = base
            .parse::<IpAddr>()
            .map_err(|_| ScanTargetError::Invalid(raw.to_string()))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| ScanTargetError::Invalid(raw.to_string()))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(ScanTargetError::Invalid(raw.to_string()));
        }
        if prefix == 0 {
            return Err(ScanTargetError::TooLarge(raw.to_string()));
        }
        return Ok(ScanTarget::Cidr(raw.to_string()));
    }

    raw.parse::<IpAddr>()
        .map(ScanTarget::Ip)
        .map_err(|_| ScanTargetError::NotIpCidr(raw.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn accepts_plain_ipv4_and_ipv6() {
        assert_eq!(
            validate_target("10.0.0.1").unwrap(),
            ScanTarget::Ip("10.0.0.1".parse().unwrap())
        );
        assert_eq!(
            validate_target("2001:db8::1").unwrap(),
            ScanTarget::Ip("2001:db8::1".parse().unwrap())
        );
    }

    #[test]
    fn accepts_reasonable_cidr() {
        assert_eq!(
            validate_target("10.0.0.0/24").unwrap(),
            ScanTarget::Cidr("10.0.0.0/24".to_string())
        );
        assert_eq!(
            validate_target("2001:db8::/64").unwrap(),
            ScanTarget::Cidr("2001:db8::/64".to_string())
        );
    }

    #[test]
    fn rejects_unrestricted_scopes() {
        for target in [
            "0.0.0.0/0",
            "::/0",
            "10.0.0.0/0",
            "10.0.0.0/00",
            "10.0.0.0/000",
        ] {
            assert_eq!(
                validate_target(target),
                Err(ScanTargetError::TooLarge(target.to_string())),
                "target {target} must be rejected"
            );
        }
        assert_eq!(
            validate_target("0.0.0.0/8"),
            Err(ScanTargetError::TooLarge("0.0.0.0/8".to_string()))
        );
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(
            validate_target("not-an-ip"),
            Err(ScanTargetError::NotIpCidr("not-an-ip".to_string()))
        );
        assert_eq!(
            validate_target("example.com"),
            Err(ScanTargetError::NotIpCidr("example.com".to_string()))
        );
        assert_eq!(
            validate_target("999.1.1.1"),
            Err(ScanTargetError::NotIpCidr("999.1.1.1".to_string()))
        );
    }

    #[test]
    fn rejects_empty_and_garbage() {
        assert!(validate_target("").is_err());
        assert!(validate_target("//").is_err());
        assert!(matches!(
            validate_target("/24"),
            Err(ScanTargetError::TooLarge(_)) | Err(ScanTargetError::Invalid(_))
        ));
    }

    #[test]
    fn valid_targets_round_trip_ip_addr_type() {
        match validate_target("10.0.0.1").unwrap() {
            ScanTarget::Ip(IpAddr::V4(_)) => {}
            other => panic!("expected IPv4, got {other:?}"),
        }
    }
}
