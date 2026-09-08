//! Assessment rule catalog (v0.5).
//!
//! Rules are small pure functions over [`AssessmentInput`] that append
//! [`Finding`]s. They never read the store and never see collector output —
//! only normalized domain facts — so the same rules run against any backend.
//!
//! Severity weights drive the complexity score: Info 2, Warning 10, High 25
//! (capped at 100 per asset).

use std::collections::HashSet;
use std::net::IpAddr;

use super::{AssessmentInput, Finding, Severity};
use crate::domain::{Dependency, Filesystem, Service};

/// A rule in the catalog: stable id, human description, and its evaluator.
pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    pub evaluate: fn(&AssessmentInput, &mut Vec<Finding>),
}

/// The full v0.5 rule catalog.
pub fn catalog() -> &'static [Rule] {
    &[
        Rule {
            id: "os.missing",
            description: "No operating system details discovered for the asset",
            evaluate: rule_os_missing,
        },
        Rule {
            id: "os.eol",
            description: "Operating system is at or near end of vendor support",
            evaluate: rule_os_eol,
        },
        Rule {
            id: "svc.insecure-protocol",
            description: "Insecure cleartext service exposed (telnet/ftp)",
            evaluate: rule_svc_insecure,
        },
        Rule {
            id: "svc.management-exposure",
            description: "Remote management service exposed (SMB/RDP/VNC/WinRM-HTTP)",
            evaluate: rule_svc_management,
        },
        Rule {
            id: "dep.hub",
            description: "Many assets depend on this asset (high blast radius)",
            evaluate: rule_dep_hub,
        },
        Rule {
            id: "dep.external",
            description: "Active connections target endpoints outside the managed inventory",
            evaluate: rule_dep_external,
        },
        Rule {
            id: "dep.unconfirmed",
            description: "Dependency edges observed but not yet confirmed",
            evaluate: rule_dep_unconfirmed,
        },
        Rule {
            id: "capacity.missing",
            description: "No CPU/RAM capacity recorded (host-level collection not run)",
            evaluate: rule_capacity_missing,
        },
        Rule {
            id: "disk.near-full",
            description: "Filesystem is nearly full (data transfer / target sizing risk)",
            evaluate: rule_disk_near_full,
        },
    ]
}

/// End-of-life OS patterns. First case-insensitive substring match wins.
///
/// (pattern, severity, vendor-support note)
const EOL_OS: &[(&str, Severity, &str)] = &[
    (
        "ubuntu 14.04",
        Severity::High,
        "Ubuntu 14.04 LTS reached end of life in 2019",
    ),
    (
        "ubuntu 16.04",
        Severity::High,
        "Ubuntu 16.04 LTS standard support ended in 2021",
    ),
    (
        "ubuntu 18.04",
        Severity::High,
        "Ubuntu 18.04 LTS standard support ended in 2023",
    ),
    (
        "centos 6",
        Severity::High,
        "CentOS 6 reached end of life in 2020",
    ),
    (
        "centos 7",
        Severity::High,
        "CentOS 7 reached end of life in June 2024",
    ),
    (
        "centos 8",
        Severity::High,
        "CentOS 8 reached end of life in 2021",
    ),
    (
        "red hat enterprise linux 6",
        Severity::High,
        "RHEL 6 support ended in 2020",
    ),
    (
        "red hat enterprise linux 7",
        Severity::High,
        "RHEL 7 support ended in 2024",
    ),
    ("rhel 6", Severity::High, "RHEL 6 support ended in 2020"),
    ("rhel 7", Severity::High, "RHEL 7 support ended in 2024"),
    ("debian 9", Severity::High, "Debian 9 LTS ended in 2022"),
    ("debian 10", Severity::High, "Debian 10 LTS ended in 2024"),
    (
        "sles 11",
        Severity::High,
        "SUSE Linux Enterprise Server 11 support ended in 2019",
    ),
    (
        "windows server 2008",
        Severity::High,
        "Windows Server 2008 extended support ended in 2020",
    ),
    (
        "windows server 2012",
        Severity::High,
        "Windows Server 2012 extended support ended in 2023",
    ),
    (
        "windows server 2016",
        Severity::Warning,
        "Windows Server 2016 extended support ends in 2027",
    ),
    (
        "sles 12",
        Severity::Warning,
        "SUSE Linux Enterprise Server 12 LTSS ends in 2027",
    ),
];

/// Cleartext protocols that should not exist in a modern estate.
const INSECURE_PORTS: &[u16] = &[21, 23];
/// Remote management surfaces exposed to the network.
const MANAGEMENT_PORTS: &[u16] = &[445, 3389, 5900, 5985];
/// Filesystem fill level that risks migration data transfer planning.
const DISK_NEAR_FULL_PCT: u32 = 85;
/// Dependents that make an asset a coordination point.
const HUB_WARNING_THRESHOLD: usize = 2;
/// Dependents that make an asset a hard blast-radius problem.
const HUB_HIGH_THRESHOLD: usize = 4;

fn rule_os_missing(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for asset in &input.assets {
        if asset.os_name.is_none() {
            findings.push(Finding {
                rule_id: "os.missing".into(),
                severity: Severity::Info,
                message: "no operating system details discovered; \
                          OS-based migration checks cannot run for this asset"
                    .into(),
                evidence: vec![format!("asset {} has no recorded OS", asset.ip)],
                asset_id: Some(asset.id.clone()),
            });
        }
    }
}

fn rule_os_eol(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for asset in &input.assets {
        let Some(os_name) = &asset.os_name else {
            continue;
        };
        let os_lower = os_name.to_lowercase();
        if let Some((_, severity, note)) = EOL_OS
            .iter()
            .find(|(pattern, _, _)| os_lower.contains(pattern))
        {
            findings.push(Finding {
                rule_id: "os.eol".into(),
                severity: *severity,
                message: "operating system is at or near end of vendor support; \
                          in-place upgrade or re-platforming is likely required before migration"
                    .into(),
                evidence: vec![format!("reported OS: {os_name}"), note.to_string()],
                asset_id: Some(asset.id.clone()),
            });
        }
    }
}

fn rule_svc_insecure(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for asset in &input.assets {
        let matched: Vec<&Service> = input
            .services
            .iter()
            .filter(|s| s.asset_id == asset.id && s.state == "open")
            .filter(|s| INSECURE_PORTS.contains(&s.port))
            .collect();
        if matched.is_empty() {
            continue;
        }
        let evidence = matched
            .iter()
            .map(|s| service_evidence(s.proto.as_str(), s.port, s.name.as_deref()))
            .collect();
        findings.push(Finding {
            rule_id: "svc.insecure-protocol".into(),
            severity: Severity::High,
            message: "insecure cleartext service exposed; must be decommissioned or \
                      replaced as part of migration"
                .into(),
            evidence,
            asset_id: Some(asset.id.clone()),
        });
    }
}

fn rule_svc_management(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for asset in &input.assets {
        let matched: Vec<&Service> = input
            .services
            .iter()
            .filter(|s| s.asset_id == asset.id && s.state == "open")
            .filter(|s| MANAGEMENT_PORTS.contains(&s.port))
            .collect();
        if matched.is_empty() {
            continue;
        }
        let evidence = matched
            .iter()
            .map(|s| service_evidence(s.proto.as_str(), s.port, s.name.as_deref()))
            .collect();
        findings.push(Finding {
            rule_id: "svc.management-exposure".into(),
            severity: Severity::Warning,
            message: "remote management service exposed to the scanned network; \
                      verify intended exposure and plan credentials for the target environment"
                .into(),
            evidence,
            asset_id: Some(asset.id.clone()),
        });
    }
}

fn rule_dep_hub(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for asset in &input.assets {
        // DNS alias edges are identity evidence, not runtime coupling.
        let dependants: Vec<&Dependency> = input
            .dependencies
            .iter()
            .filter(|d| d.target_asset_id == asset.id && d.evidence_source != "dns")
            .collect();
        if dependants.len() < HUB_WARNING_THRESHOLD {
            continue;
        }
        let severity = if dependants.len() >= HUB_HIGH_THRESHOLD {
            Severity::High
        } else {
            Severity::Warning
        };
        let evidence = dependants
            .iter()
            .map(|d| {
                let source = asset_label(input, &d.source_asset_id);
                format!("{source} -> {}/{}", d.proto, d.port)
            })
            .collect();
        findings.push(Finding {
            rule_id: "dep.hub".into(),
            severity,
            message: format!(
                "{} assets depend on this asset; migration requires coordinated planning \
                 and a verified blast radius",
                dependants.len()
            ),
            evidence,
            asset_id: Some(asset.id.clone()),
        });
    }
}

fn rule_dep_external(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    let known: HashSet<IpAddr> = input.assets.iter().map(|a| a.ip).collect();
    for asset in &input.assets {
        let mut external: Vec<String> = Vec::new();
        for conn in input.connections.iter().filter(|c| c.asset_id == asset.id) {
            if conn.remote_ip.is_loopback() || known.contains(&conn.remote_ip) {
                continue;
            }
            let endpoint = format!("{}:{}", conn.remote_ip, conn.remote_port);
            if !external.contains(&endpoint) {
                external.push(endpoint);
            }
        }
        if external.is_empty() {
            continue;
        }
        findings.push(Finding {
            rule_id: "dep.external".into(),
            severity: Severity::Warning,
            message: "active connections target endpoints outside the managed \
                      inventory; unknown coupling complicates migration planning"
                .into(),
            evidence: external,
            asset_id: Some(asset.id.clone()),
        });
    }
}

fn rule_dep_unconfirmed(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    let unconfirmed: Vec<&Dependency> = input
        .dependencies
        .iter()
        .filter(|d| !d.confirmed && d.evidence_source != "dns")
        .collect();
    if unconfirmed.is_empty() {
        return;
    }
    findings.push(Finding {
        rule_id: "dep.unconfirmed".into(),
        severity: Severity::Info,
        message: "dependency edges are observed but not yet confirmed; confirm them \
                  (`orbyn deps confirm`) before wave planning"
            .into(),
        evidence: vec![format!(
            "{} of {} runtime/manual edges unconfirmed",
            unconfirmed.len(),
            input
                .dependencies
                .iter()
                .filter(|d| d.evidence_source != "dns")
                .count()
        )],
        asset_id: None,
    });
}

fn rule_capacity_missing(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for asset in &input.assets {
        let has_capacity = input.capacities.iter().any(|c| c.asset_id == asset.id);
        if !has_capacity {
            findings.push(Finding {
                rule_id: "capacity.missing".into(),
                severity: Severity::Info,
                message: "no CPU/RAM capacity recorded; right-sizing is impossible \
                          until host-level collection runs"
                    .into(),
                evidence: vec![format!(
                    "run `orbyn discover --target {} --collector ssh` (or windows)",
                    asset.ip
                )],
                asset_id: Some(asset.id.clone()),
            });
        }
    }
}

fn rule_disk_near_full(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for asset in &input.assets {
        let near_full: Vec<&Filesystem> = input
            .filesystems
            .iter()
            .filter(|f| f.asset_id == asset.id)
            .filter(|f| f.used_pct.unwrap_or(0) >= DISK_NEAR_FULL_PCT)
            .collect();
        if near_full.is_empty() {
            continue;
        }
        let evidence = near_full
            .iter()
            .map(|f| {
                format!(
                    "{}: {}% used ({}/{} KB)",
                    f.mount,
                    f.used_pct.unwrap_or(0),
                    f.used_kb.unwrap_or(0),
                    f.size_kb
                )
            })
            .collect();
        findings.push(Finding {
            rule_id: "disk.near-full".into(),
            severity: Severity::Warning,
            message: "filesystem is nearly full; data transfer windows and target \
                      sizing need review before migration"
                .into(),
            evidence,
            asset_id: Some(asset.id.clone()),
        });
    }
}

/// Evidence line for an exposed service.
fn service_evidence(proto: &str, port: u16, name: Option<&str>) -> String {
    match name {
        Some(name) => format!("{proto}/{port} open ({name})"),
        None => format!("{proto}/{port} open"),
    }
}

/// Hostname-or-IP label for an asset id, falling back to the id.
fn asset_label(input: &AssessmentInput, id: &str) -> String {
    match input.assets.iter().find(|a| a.id == id) {
        Some(asset) => asset
            .hostname
            .clone()
            .unwrap_or_else(|| asset.ip.to_string()),
        None => id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Asset, Connection, Dependency, Filesystem, Service};
    use chrono::Utc;

    fn asset(id: &str, ip: &str, os_name: Option<&str>) -> Asset {
        Asset {
            id: id.into(),
            ip: ip.parse().unwrap(),
            hostname: None,
            device_class: None,
            os_name: os_name.map(str::to_string),
            os_version: None,
            environment: None,
            owner: None,
            criticality: None,
            tags: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    fn service(asset_id: &str, port: u16) -> Service {
        Service {
            asset_id: asset_id.into(),
            proto: "tcp".into(),
            port,
            name: None,
            state: "open".into(),
            banner: None,
        }
    }

    fn dep(source: &str, target: &str, port: u16, confirmed: bool) -> Dependency {
        Dependency {
            source_asset_id: source.into(),
            target_asset_id: target.into(),
            proto: "tcp".into(),
            port,
            evidence_source: "active-connections".into(),
            confidence: 0.9,
            confirmed,
        }
    }

    fn run(input: &AssessmentInput, rule_id: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for rule in catalog() {
            (rule.evaluate)(input, &mut findings);
        }
        findings.retain(|f| f.rule_id == rule_id);
        findings
    }

    #[test]
    fn os_missing_fires_without_os() {
        let input = AssessmentInput {
            assets: vec![asset("a1", "10.0.0.1", None)],
            ..Default::default()
        };
        let findings = run(&input, "os.missing");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(!findings[0].evidence.is_empty());
    }

    #[test]
    fn eol_os_detected_with_note() {
        let input = AssessmentInput {
            assets: vec![
                asset("a1", "10.0.0.1", Some("Ubuntu 18.04.6 LTS")),
                asset("a2", "10.0.0.2", Some("Microsoft Windows Server 2012 R2")),
                asset(
                    "a3",
                    "10.0.0.3",
                    Some("Microsoft Windows Server 2016 Standard"),
                ),
                asset("a4", "10.0.0.4", Some("Ubuntu 22.04.4 LTS")),
            ],
            ..Default::default()
        };
        let findings = run(&input, "os.eol");
        assert_eq!(findings.len(), 3, "supported OS must not fire");
        let by_asset: Vec<&str> = findings
            .iter()
            .map(|f| f.asset_id.as_deref().unwrap())
            .collect();
        assert!(by_asset.contains(&"a1"));
        assert!(by_asset.contains(&"a2"));
        assert!(by_asset.contains(&"a3"));
        assert_eq!(findings[0].severity, Severity::High);
        let win16 = findings
            .iter()
            .find(|f| f.asset_id.as_deref() == Some("a3"))
            .unwrap();
        assert_eq!(win16.severity, Severity::Warning, "2016 is near-EOL only");
        assert!(
            findings.iter().all(|f| f.evidence.len() >= 2),
            "OS + vendor note evidence"
        );
    }

    #[test]
    fn insecure_and_management_ports_flagged() {
        let input = AssessmentInput {
            assets: vec![asset("a1", "10.0.0.1", Some("Linux"))],
            services: vec![service("a1", 23), service("a1", 443), service("a1", 3389)],
            ..Default::default()
        };
        let insecure = run(&input, "svc.insecure-protocol");
        assert_eq!(insecure.len(), 1);
        assert_eq!(insecure[0].severity, Severity::High);
        assert!(insecure[0].evidence[0].contains("tcp/23"));

        let mgmt = run(&input, "svc.management-exposure");
        assert_eq!(mgmt.len(), 1);
        assert_eq!(mgmt[0].severity, Severity::Warning);
        assert!(mgmt[0].evidence[0].contains("tcp/3389"));
    }

    #[test]
    fn closed_ports_are_not_exposure() {
        let mut svc = service("a1", 23);
        svc.state = "closed".into();
        let input = AssessmentInput {
            assets: vec![asset("a1", "10.0.0.1", None)],
            services: vec![svc],
            ..Default::default()
        };
        assert!(run(&input, "svc.insecure-protocol").is_empty());
    }

    #[test]
    fn hub_escalates_with_dependants() {
        let base = AssessmentInput {
            assets: vec![
                asset("hub", "10.0.0.9", None),
                asset("c1", "10.0.0.1", None),
                asset("c2", "10.0.0.2", None),
                asset("c3", "10.0.0.3", None),
                asset("c4", "10.0.0.4", None),
            ],
            ..Default::default()
        };

        let two = AssessmentInput {
            dependencies: vec![dep("c1", "hub", 5432, false), dep("c2", "hub", 5432, false)],
            ..base.clone()
        };
        let findings = run(&two, "dep.hub");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);

        let four = AssessmentInput {
            dependencies: vec![
                dep("c1", "hub", 5432, false),
                dep("c2", "hub", 5432, false),
                dep("c3", "hub", 5432, false),
                dep("c4", "hub", 5432, false),
            ],
            ..base
        };
        let findings = run(&four, "dep.hub");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].evidence.len(), 4);
    }

    #[test]
    fn external_connections_flagged_once_per_endpoint() {
        let input = AssessmentInput {
            assets: vec![asset("a1", "10.0.0.1", None)],
            connections: vec![
                Connection {
                    asset_id: "a1".into(),
                    proto: "tcp".into(),
                    local_ip: None,
                    local_port: None,
                    remote_ip: "203.0.113.9".parse().unwrap(),
                    remote_port: 443,
                    process: None,
                },
                Connection {
                    asset_id: "a1".into(),
                    proto: "tcp".into(),
                    local_ip: None,
                    local_port: None,
                    remote_ip: "203.0.113.9".parse().unwrap(),
                    remote_port: 443,
                    process: None,
                },
                Connection {
                    asset_id: "a1".into(),
                    proto: "tcp".into(),
                    local_ip: None,
                    local_port: None,
                    remote_ip: "127.0.0.1".parse().unwrap(),
                    remote_port: 8080,
                    process: None,
                },
            ],
            ..Default::default()
        };
        let findings = run(&input, "dep.external");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, vec!["203.0.113.9:443".to_string()]);
    }

    #[test]
    fn unconfirmed_summary_is_aggregate() {
        let input = AssessmentInput {
            dependencies: vec![dep("c1", "hub", 5432, false), dep("c2", "hub", 5432, true)],
            ..Default::default()
        };
        let findings = run(&input, "dep.unconfirmed");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].asset_id, None);
        assert!(findings[0].evidence[0].contains("1 of 2"));
    }

    #[test]
    fn capacity_and_disk_rules() {
        let input = AssessmentInput {
            assets: vec![asset("a1", "10.0.0.1", None), asset("a2", "10.0.0.2", None)],
            capacities: vec![crate::domain::Capacity {
                asset_id: "a2".into(),
                cpu_model: None,
                cpu_sockets: None,
                cpu_cores: None,
                cpu_threads: Some(4),
                ram_total_mb: Some(8192),
                collected_at: Utc::now(),
            }],
            filesystems: vec![Filesystem {
                asset_id: "a1".into(),
                device: None,
                mount: "/".into(),
                fs_type: None,
                size_kb: 100,
                used_kb: Some(92),
                available_kb: Some(8),
                used_pct: Some(92),
            }],
            ..Default::default()
        };
        let missing = run(&input, "capacity.missing");
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].asset_id.as_deref(), Some("a1"));
        assert!(missing[0].evidence[0].contains("orbyn discover"));

        let disk = run(&input, "disk.near-full");
        assert_eq!(disk.len(), 1);
        assert_eq!(disk[0].severity, Severity::Warning);
        assert!(disk[0].evidence[0].contains("92% used"));
    }

    #[test]
    fn catalog_ids_are_unique() {
        let catalog = catalog();
        let mut ids: Vec<&str> = catalog.iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), catalog.len());
    }
}
