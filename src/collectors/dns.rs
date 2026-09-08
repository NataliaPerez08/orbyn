//! DNS relationship evidence (v0.4 milestone).
//!
//! Forward-resolves asset hostnames and records a low-confidence
//! relationship edge whenever a hostname of one asset resolves to the IP of
//! a *different* asset — evidence that two inventory records refer to related
//! infrastructure (aliases, shared names, stale records). This is identity
//! evidence, not a runtime dependency, so it carries low confidence and the
//! `dns` evidence source.
//!
//! Resolution uses the system resolver through `getaddrinfo` (blocking), so
//! it runs on the blocking thread pool.

use std::net::IpAddr;
use std::net::ToSocketAddrs;

use anyhow::Result;

use crate::domain::{Asset, Dependency};

/// Confidence attached to DNS-derived relationship evidence.
pub const DNS_CONFIDENCE: f32 = 0.4;

/// Forward-resolve a hostname to its addresses using the system resolver.
pub async fn resolve_host(host: &str) -> Result<Vec<IpAddr>> {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || resolve_blocking(&host))
        .await
        .map_err(|e| anyhow::anyhow!("DNS resolution task failed: {e}"))?
}

fn resolve_blocking(host: &str) -> Result<Vec<IpAddr>> {
    let addrs: Vec<IpAddr> = (host, 0).to_socket_addrs()?.map(|a| a.ip()).collect();
    Ok(addrs)
}

/// Pure matching step: turn `(hostname, resolved IPs)` pairs plus the asset
/// inventory into relationship edges. Kept separate from resolution so it
/// can be tested without network access.
pub fn dns_edges(assets: &[Asset], resolutions: &[(String, Vec<IpAddr>)]) -> Vec<Dependency> {
    let mut edges = Vec::new();
    for (hostname, ips) in resolutions {
        let Some(source) = assets.iter().find(|a| {
            a.hostname
                .as_deref()
                .map(|h| h.eq_ignore_ascii_case(hostname))
                .unwrap_or(false)
        }) else {
            continue;
        };
        for ip in ips {
            if ip.is_loopback() || *ip == source.ip {
                continue;
            }
            if let Some(target) = assets.iter().find(|a| a.ip == *ip && a.id != source.id) {
                edges.push(Dependency {
                    source_asset_id: source.id.clone(),
                    target_asset_id: target.id.clone(),
                    proto: "dns".into(),
                    port: 0,
                    evidence_source: "dns".into(),
                    confidence: DNS_CONFIDENCE,
                    confirmed: false,
                });
            }
        }
    }
    edges
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn asset(id: &str, ip: &str, hostname: Option<&str>) -> Asset {
        Asset {
            id: id.into(),
            ip: ip.parse().unwrap(),
            hostname: hostname.map(str::to_string),
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

    #[test]
    fn hostname_resolving_to_other_asset_creates_edge() {
        let assets = vec![
            asset("a1", "10.0.0.5", Some("web-01.example.com")),
            asset("a2", "10.0.0.9", Some("db-01.example.com")),
        ];
        let resolutions = vec![(
            "web-01.example.com".to_string(),
            vec!["10.0.0.9".parse::<IpAddr>().unwrap()],
        )];
        let edges = dns_edges(&assets, &resolutions);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].source_asset_id, "a1");
        assert_eq!(edges[0].target_asset_id, "a2");
        assert_eq!(edges[0].evidence_source, "dns");
        assert_eq!(edges[0].confidence, DNS_CONFIDENCE);
        assert!(!edges[0].confirmed);
    }

    #[test]
    fn self_and_loopback_results_are_ignored() {
        let assets = vec![asset("a1", "10.0.0.5", Some("web-01"))];
        let resolutions = vec![(
            "web-01".to_string(),
            vec![
                "10.0.0.5".parse::<IpAddr>().unwrap(),
                "127.0.0.1".parse::<IpAddr>().unwrap(),
            ],
        )];
        assert!(dns_edges(&assets, &resolutions).is_empty());
    }

    #[test]
    fn unknown_hostnames_are_skipped() {
        let assets = vec![asset("a1", "10.0.0.5", Some("web-01"))];
        let resolutions = vec![(
            "other-host".to_string(),
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()],
        )];
        assert!(dns_edges(&assets, &resolutions).is_empty());
    }

    #[test]
    fn resolution_to_unmanaged_ip_creates_no_edge() {
        let assets = vec![asset("a1", "10.0.0.5", Some("web-01"))];
        let resolutions = vec![(
            "web-01".to_string(),
            vec!["203.0.113.7".parse::<IpAddr>().unwrap()],
        )];
        assert!(dns_edges(&assets, &resolutions).is_empty());
    }
}
