//! DNS relationship evidence (v0.4 milestone).
//!
//! Forward-resolves asset hostnames and records a low-confidence
//! relationship edge whenever a hostname of one asset resolves to the IP of
//! a *different* asset — evidence that two inventory records refer to related
//! infrastructure (aliases, shared names, stale records). This is identity
//! evidence, not a runtime dependency, so it carries low confidence and the
//! `dns` evidence source.
//!
//! Evidence comes from three matching steps, all exact and case-insensitive:
//!
//! - forward IP matching: a hostname resolving to another asset's IP;
//! - CNAME-chain matching: a hostname whose CNAME chain names another
//!   asset's hostname (alias evidence even when the final addresses are not
//!   managed);
//! - reverse (PTR) matching: an asset IP whose PTR record names another
//!   asset's hostname.
//!
//! When `dig` is available the CNAME chain is captured with
//! `dig +short <host>` (answer records in order: alias targets, then
//! addresses) and PTR names with `dig +short -x <ip>`. Without `dig`, or for
//! hostnames that only exist in local sources like `/etc/hosts`, resolution
//! falls back to the system resolver through `getaddrinfo` (blocking pool),
//! which follows CNAMEs transparently but cannot expose them.

use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::process::Stdio;

use anyhow::Result;
use tokio::process::Command;
use tokio::time::{timeout, Duration};

use crate::domain::{Asset, Dependency, EvidenceKind};
use crate::process::{run_captured, MAX_STDERR_CAPTURE_BYTES};

/// Confidence attached to DNS-derived relationship evidence.
pub const DNS_CONFIDENCE: f32 = 0.4;
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_ADDRESSES: usize = 64;
const MAX_CNAME_CHAIN: usize = 8;
const MAX_PTR_NAMES: usize = 8;
const DIG_STDOUT_CAP: u64 = 64 * 1024;

/// Result of forward-resolving one hostname.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolution {
    /// A/AAAA records the hostname resolves to (deduplicated, bounded).
    pub addresses: Vec<IpAddr>,
    /// CNAME chain targets in answer order, trailing dots stripped.
    pub cname_chain: Vec<String>,
}

/// Forward-resolve a hostname, capturing the CNAME chain when `dig` is
/// available. Falls back to the system resolver (`getaddrinfo`) when `dig`
/// is missing, fails, or yields neither addresses nor chain entries (e.g.
/// hostnames that only exist in `/etc/hosts`).
pub async fn resolve_host(host: &str) -> Result<Resolution> {
    if dig_safe_hostname(host) {
        if let Some(out) = dig_short(&[host]).await {
            let resolution = parse_dig_short(&out);
            if !resolution.addresses.is_empty() || !resolution.cname_chain.is_empty() {
                return Ok(resolution);
            }
        }
    }
    let addresses = resolve_system(host).await?;
    Ok(Resolution {
        addresses,
        cname_chain: Vec::new(),
    })
}

/// Reverse-resolve an IP to its PTR names via `dig +short -x`. Returns an
/// empty list when `dig` is unavailable or the address has no PTR record.
pub async fn resolve_ptr(ip: IpAddr) -> Result<Vec<String>> {
    let ip = ip.to_string();
    match dig_short(&["-x", &ip]).await {
        Some(out) => Ok(parse_ptr_names(&out)),
        None => Ok(Vec::new()),
    }
}

/// Run `dig +short <args...>` under the shared subprocess bounds. Returns
/// `None` when `dig` is not installed, exits non-zero or times out — DNS
/// evidence degrades to the system resolver instead of failing the run.
async fn dig_short(args: &[&str]) -> Option<String> {
    let binary = std::env::var("ORBYN_DIG_BIN").unwrap_or_else(|_| "dig".to_string());
    let mut cmd = Command::new(&binary);
    cmd.arg("+short")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = cmd.spawn().ok()?;
    let captured = run_captured(
        child,
        None,
        DIG_STDOUT_CAP,
        MAX_STDERR_CAPTURE_BYTES,
        DNS_TIMEOUT,
        format!("dig timed out resolving {args:?}"),
    )
    .await
    .ok()?;

    if captured.status.success() {
        Some(captured.stdout)
    } else {
        None
    }
}

/// A hostname may be passed to `dig` as an argv element only when it cannot
/// be mistaken for a command-line option; anything else goes straight to
/// the system resolver.
fn dig_safe_hostname(host: &str) -> bool {
    !host.is_empty()
        && !host.starts_with('-')
        && !host.starts_with('+')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Resolve through the system resolver on the blocking pool.
async fn resolve_system(host: &str) -> Result<Vec<IpAddr>> {
    let host = host.to_string();
    let resolution = tokio::task::spawn_blocking(move || resolve_blocking(&host));
    timeout(DNS_TIMEOUT, resolution)
        .await
        .map_err(|_| anyhow::anyhow!("DNS resolution timed out"))?
        .map_err(|e| anyhow::anyhow!("DNS resolution task failed: {e}"))?
}

fn resolve_blocking(host: &str) -> Result<Vec<IpAddr>> {
    let mut addrs = Vec::new();
    for addr in (host, 0).to_socket_addrs()?.map(|a| a.ip()) {
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
        if addrs.len() == MAX_DNS_ADDRESSES {
            break;
        }
    }
    Ok(addrs)
}

/// Parse `dig +short <host>` output: answer records in order, where IP lines
/// are A/AAAA records and name lines (trailing dot stripped) are CNAME
/// chain targets. Deduplicated and bounded.
pub fn parse_dig_short(out: &str) -> Resolution {
    let mut resolution = Resolution::default();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(ip) = line.parse::<IpAddr>() {
            if !resolution.addresses.contains(&ip) && resolution.addresses.len() < MAX_DNS_ADDRESSES
            {
                resolution.addresses.push(ip);
            }
        } else {
            let name = line.strip_suffix('.').unwrap_or(line);
            if name.is_empty()
                || resolution
                    .cname_chain
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(name))
                || resolution.cname_chain.len() >= MAX_CNAME_CHAIN
            {
                continue;
            }
            resolution.cname_chain.push(name.to_string());
        }
    }
    resolution
}

/// Parse `dig +short -x <ip>` output into PTR names (trailing dots
/// stripped, deduplicated, bounded).
pub fn parse_ptr_names(out: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in out.lines() {
        let name = line.trim().strip_suffix('.').unwrap_or(line.trim());
        if name.is_empty()
            || names.iter().any(|n: &String| n.eq_ignore_ascii_case(name))
            || names.len() >= MAX_PTR_NAMES
        {
            continue;
        }
        names.push(name.to_string());
    }
    names
}

/// Pure forward matching step: turn `(hostname, resolution)` pairs plus the
/// asset inventory into relationship edges — by resolved IP and by CNAME
/// chain target. Kept separate from resolution so it can be tested without
/// network access.
pub fn dns_edges(assets: &[Asset], resolutions: &[(String, Resolution)]) -> Vec<Dependency> {
    let mut edges = Vec::new();
    for (hostname, resolution) in resolutions {
        let Some(source) = assets.iter().find(|a| {
            a.hostname
                .as_deref()
                .map(|h| h.eq_ignore_ascii_case(hostname))
                .unwrap_or(false)
        }) else {
            continue;
        };
        let mut targets: Vec<&Asset> = Vec::new();
        for ip in &resolution.addresses {
            if ip.is_loopback() || *ip == source.ip {
                continue;
            }
            if let Some(target) = assets.iter().find(|a| a.ip == *ip && a.id != source.id) {
                push_unique(&mut targets, target);
            }
        }
        for cname in &resolution.cname_chain {
            if let Some(target) = assets.iter().find(|a| {
                a.id != source.id
                    && a.hostname
                        .as_deref()
                        .map(|h| h.eq_ignore_ascii_case(cname))
                        .unwrap_or(false)
            }) {
                push_unique(&mut targets, target);
            }
        }
        for target in targets {
            edges.push(dns_edge(source, target));
        }
    }
    edges
}

/// Pure reverse matching step: an asset whose IP PTR-resolves to the
/// hostname of a *different* asset produces an alias edge.
pub fn dns_edges_ptr(assets: &[Asset], ptrs: &[(IpAddr, Vec<String>)]) -> Vec<Dependency> {
    let mut edges = Vec::new();
    for (ip, names) in ptrs {
        let Some(source) = assets.iter().find(|a| a.ip == *ip) else {
            continue;
        };
        let mut targets: Vec<&Asset> = Vec::new();
        for name in names {
            if let Some(target) = assets.iter().find(|a| {
                a.id != source.id
                    && a.hostname
                        .as_deref()
                        .map(|h| h.eq_ignore_ascii_case(name))
                        .unwrap_or(false)
            }) {
                push_unique(&mut targets, target);
            }
        }
        for target in targets {
            edges.push(dns_edge(source, target));
        }
    }
    edges
}

fn dns_edge(source: &Asset, target: &Asset) -> Dependency {
    Dependency {
        source_asset_id: source.id.clone(),
        target_asset_id: target.id.clone(),
        proto: "dns".into(),
        port: 0,
        evidence_source: EvidenceKind::Dns.as_str().into(),
        confidence: DNS_CONFIDENCE,
        confirmed: false,
    }
}

fn push_unique<'a>(targets: &mut Vec<&'a Asset>, candidate: &'a Asset) {
    if !targets.iter().any(|a| a.id == candidate.id) {
        targets.push(candidate);
    }
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
            sys_descr: None,
            environment: None,
            owner: None,
            criticality: None,
            tags: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    fn resolution(ips: &[&str], chain: &[&str]) -> (String, Resolution) {
        (
            "web-01".to_string(),
            Resolution {
                addresses: ips.iter().map(|i| i.parse::<IpAddr>().unwrap()).collect(),
                cname_chain: chain.iter().map(|c| c.to_string()).collect(),
            },
        )
    }

    #[test]
    fn hostname_resolving_to_other_asset_creates_edge() {
        let assets = vec![
            asset("a1", "10.0.0.5", Some("web-01.example.com")),
            asset("a2", "10.0.0.9", Some("db-01.example.com")),
        ];
        let resolutions = vec![(
            "web-01.example.com".to_string(),
            Resolution {
                addresses: vec!["10.0.0.9".parse().unwrap()],
                cname_chain: Vec::new(),
            },
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
        let resolutions = vec![resolution(&["10.0.0.5", "127.0.0.1"], &[])];
        assert!(dns_edges(&assets, &resolutions).is_empty());
    }

    #[test]
    fn unknown_hostnames_are_skipped() {
        let assets = vec![asset("a1", "10.0.0.5", Some("web-01"))];
        let resolutions = vec![(
            "other-host".to_string(),
            Resolution {
                addresses: vec!["10.0.0.5".parse().unwrap()],
                cname_chain: Vec::new(),
            },
        )];
        assert!(dns_edges(&assets, &resolutions).is_empty());
    }

    #[test]
    fn resolution_to_unmanaged_ip_creates_no_edge() {
        let assets = vec![asset("a1", "10.0.0.5", Some("web-01"))];
        let resolutions = vec![resolution(&["203.0.113.7"], &[])];
        assert!(dns_edges(&assets, &resolutions).is_empty());
    }

    #[test]
    fn cname_chain_targeting_asset_hostname_creates_edge() {
        let assets = vec![
            asset("a1", "10.0.0.5", Some("web-01")),
            asset("a2", "10.0.0.9", Some("db-01")),
        ];
        // The chain names db-01 but the final address is unmanaged: the
        // alias evidence must still link the two records.
        let resolutions = vec![resolution(&["203.0.113.7"], &["db-01"])];
        let edges = dns_edges(&assets, &resolutions);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].source_asset_id, "a1");
        assert_eq!(edges[0].target_asset_id, "a2");
    }

    #[test]
    fn cname_chain_ignores_self_and_unknown_targets() {
        let assets = vec![
            asset("a1", "10.0.0.5", Some("web-01")),
            asset("a2", "10.0.0.9", Some("db-01")),
        ];
        let resolutions = vec![resolution(&[], &["web-01", "unmanaged.example.com"])];
        assert!(dns_edges(&assets, &resolutions).is_empty());
    }

    #[test]
    fn cname_and_ip_matches_dedup_to_one_edge() {
        let assets = vec![
            asset("a1", "10.0.0.5", Some("web-01")),
            asset("a2", "10.0.0.9", Some("db-01")),
        ];
        // The chain names db-01 AND the addresses resolve to db-01's IP.
        let resolutions = vec![resolution(&["10.0.0.9"], &["db-01"])];
        let edges = dns_edges(&assets, &resolutions);
        assert_eq!(edges.len(), 1, "one edge per asset pair");
    }

    #[test]
    fn ptr_name_matching_other_asset_hostname_creates_edge() {
        let assets = vec![
            asset("a1", "10.0.0.5", Some("web-01")),
            asset("a2", "10.0.0.9", Some("db-01")),
        ];
        let ptrs = vec![("10.0.0.5".parse::<IpAddr>().unwrap(), vec!["db-01".into()])];
        let edges = dns_edges_ptr(&assets, &ptrs);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].source_asset_id, "a1");
        assert_eq!(edges[0].target_asset_id, "a2");
        assert_eq!(edges[0].evidence_source, "dns");
        assert_eq!(edges[0].confidence, DNS_CONFIDENCE);
    }

    #[test]
    fn ptr_name_matching_own_hostname_is_not_an_edge() {
        let assets = vec![asset("a1", "10.0.0.5", Some("web-01"))];
        let ptrs = vec![("10.0.0.5".parse::<IpAddr>().unwrap(), vec!["web-01".into()])];
        assert!(dns_edges_ptr(&assets, &ptrs).is_empty());
    }

    #[test]
    fn ptr_names_dedup_per_pair() {
        let assets = vec![
            asset("a1", "10.0.0.5", Some("web-01")),
            asset("a2", "10.0.0.9", Some("db-01")),
        ];
        let ptrs = vec![(
            "10.0.0.5".parse::<IpAddr>().unwrap(),
            vec!["db-01".into(), "DB-01".into()],
        )];
        let edges = dns_edges_ptr(&assets, &ptrs);
        assert_eq!(edges.len(), 1, "case-insensitive duplicates collapse");
    }

    #[test]
    fn parse_dig_short_separates_chain_and_addresses() {
        let out = "db-01.example.com.\n10.0.0.9\n10.0.0.9\nDB-01.EXAMPLE.COM\n2001:db8::9\n";
        let resolution = parse_dig_short(out);
        assert_eq!(
            resolution.addresses,
            vec![
                "10.0.0.9".parse::<IpAddr>().unwrap(),
                "2001:db8::9".parse::<IpAddr>().unwrap()
            ]
        );
        assert_eq!(resolution.cname_chain, vec!["db-01.example.com"]);
    }

    #[test]
    fn parse_ptr_names_strips_dots_and_dedups() {
        let out = "web-01.example.com.\nWEB-01.EXAMPLE.COM.\nother.example.com.\n\n";
        assert_eq!(
            parse_ptr_names(out),
            vec!["web-01.example.com", "other.example.com"]
        );
    }

    #[test]
    fn dig_rejects_option_like_hostnames() {
        assert!(dig_safe_hostname("web-01.example.com"));
        assert!(dig_safe_hostname("10.0.0.5"));
        assert!(!dig_safe_hostname("-x"));
        assert!(!dig_safe_hostname("+short"));
        assert!(!dig_safe_hostname("web 01"));
        assert!(!dig_safe_hostname(""));
    }
}
