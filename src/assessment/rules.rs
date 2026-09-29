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
use std::sync::OnceLock;

use super::{AssessmentInput, AssetWindow, Finding, Severity};
use crate::domain::{Dependency, EvidenceKind, Filesystem, Service};

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
        Rule {
            id: "rs.window-insufficient",
            description: "Utilization samples exist but the window is too short or too \
                          noisy for right-sizing",
            evaluate: rule_rs_window_insufficient,
        },
        Rule {
            id: "rs.cpu-overprovisioned",
            description: "CPU allocation is oversized for the observed utilization \
                          (p99 + 50% headroom fits half the cores)",
            evaluate: rule_rs_cpu_overprovisioned,
        },
        Rule {
            id: "rs.ram-overprovisioned",
            description: "RAM allocation is oversized for the observed utilization \
                          (p99 + 50% headroom fits 60% of the total)",
            evaluate: rule_rs_ram_overprovisioned,
        },
        Rule {
            id: "rs.cpu-saturated",
            description: "Observed CPU utilization is saturated (p95 >= 90%)",
            evaluate: rule_rs_cpu_saturated,
        },
        Rule {
            id: "rs.ram-saturated",
            description: "Observed RAM utilization is saturated (p95 >= 90% of total)",
            evaluate: rule_rs_ram_saturated,
        },
    ]
}

/// End-of-life OS table, embedded from `eol_os.csv` next to this module.
///
/// The table is data, not code: maintainers review it quarterly and bump its
/// `version` line (see the file header and CONTRIBUTING.md). A unit test
/// fails when the version is more than six months old so a stale table
/// cannot ship silently.
const EOL_OS_CSV: &str = include_str!("eol_os.csv");

/// One row of the end-of-life OS table.
struct EolEntry {
    /// Case-insensitive substring matched against the asset's `os_name`.
    pattern: String,
    severity: Severity,
    /// Vendor-support note surfaced as finding evidence.
    note: String,
}

/// The parsed end-of-life table: a dated version plus ordered entries.
/// First case-insensitive substring match against `os_name` wins.
struct EolTable {
    version: String,
    entries: Vec<EolEntry>,
}

/// The embedded EOL table, parsed once on first use. A malformed embedded
/// file is a programming error and panics loudly instead of silently
/// disabling `os.eol` findings.
fn eol_table() -> &'static EolTable {
    static TABLE: OnceLock<EolTable> = OnceLock::new();
    TABLE.get_or_init(|| parse_eol_csv(EOL_OS_CSV).expect("embedded EOL table must be valid"))
}

/// Parse the documented CSV dialect: `#` comments, a `version <YYYY-MM>`
/// line, a `pattern,severity,note` header, then one entry per line.
fn parse_eol_csv(src: &str) -> Result<EolTable, String> {
    let mut version: Option<String> = None;
    let mut saw_header = false;
    let mut entries = Vec::new();

    for (idx, raw) in src.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let loc = format!("line {}: ", idx + 1);

        if version.is_none() {
            let (key, value) = line
                .split_once(' ')
                .ok_or_else(|| format!("{loc}expected `version <YYYY-MM>`"))?;
            if key != "version" {
                return Err(format!("{loc}expected `version <YYYY-MM>`"));
            }
            if parse_ym(value).is_none() {
                return Err(format!("{loc}version must be YYYY-MM, got `{value}`"));
            }
            version = Some(value.to_string());
            continue;
        }

        if !saw_header {
            if line != "pattern,severity,note" {
                return Err(format!("{loc}expected `pattern,severity,note` header"));
            }
            saw_header = true;
            continue;
        }

        let fields = csv_row(line).map_err(|e| format!("{loc}{e}"))?;
        if fields.len() != 3 {
            return Err(format!(
                "{loc}expected 3 fields (pattern,severity,note), got {}",
                fields.len()
            ));
        }
        let pattern = fields[0].trim().to_lowercase();
        if pattern.is_empty() {
            return Err(format!("{loc}empty pattern"));
        }
        let severity = parse_severity(fields[1].trim()).map_err(|e| format!("{loc}{e}"))?;
        let note = fields[2].trim().to_string();
        if note.is_empty() {
            return Err(format!("{loc}empty note"));
        }
        entries.push(EolEntry {
            pattern,
            severity,
            note,
        });
    }

    let version = version.ok_or("missing `version <YYYY-MM>` line")?;
    if !saw_header {
        return Err("missing `pattern,severity,note` header".into());
    }
    if entries.is_empty() {
        return Err("EOL table has no entries; os.eol would be silently disabled".into());
    }
    Ok(EolTable { version, entries })
}

/// Split one CSV line into fields, honoring double-quoted fields with `""`
/// escapes so notes may contain commas.
fn csv_row(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => fields.push(std::mem::take(&mut field)),
            _ => field.push(c),
        }
    }
    if in_quotes {
        return Err("unterminated quoted field".into());
    }
    fields.push(field);
    Ok(fields)
}

/// Parse a `YYYY-MM` calendar version.
fn parse_ym(s: &str) -> Option<(i32, u32)> {
    let (year, month) = s.split_once('-')?;
    if year.len() != 4 || month.len() != 2 {
        return None;
    }
    let year: i32 = year.parse().ok()?;
    let month: u32 = month.parse().ok()?;
    if (1..=12).contains(&month) {
        Some((year, month))
    } else {
        None
    }
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    match s {
        "info" => Ok(Severity::Info),
        "warning" => Ok(Severity::Warning),
        "high" => Ok(Severity::High),
        other => Err(format!("unknown severity `{other}` (info|warning|high)")),
    }
}

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
    let table = eol_table();
    for asset in &input.assets {
        let Some(os_name) = &asset.os_name else {
            continue;
        };
        let os_lower = os_name.to_lowercase();
        if let Some(entry) = table.entries.iter().find(|e| os_lower.contains(&e.pattern)) {
            findings.push(Finding {
                rule_id: "os.eol".into(),
                severity: entry.severity,
                message: "operating system is at or near end of vendor support; \
                          in-place upgrade or re-platforming is likely required before migration"
                    .into(),
                evidence: vec![
                    format!("reported OS: {os_name}"),
                    format!("EOL table version: {}", table.version),
                    entry.note.clone(),
                ],
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
            .filter(|d| d.target_asset_id == asset.id && d.evidence_kind() != EvidenceKind::Dns)
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
        .filter(|d| !d.confirmed && d.evidence_kind() != EvidenceKind::Dns)
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
                .filter(|d| d.evidence_kind() != EvidenceKind::Dns)
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
                    "run `orbyn discover --target {} --collector ssh` (or windows/winrm)",
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

/// Headroom applied to the observed p99 when a right-sizing rule proposes a
/// smaller allocation. 1.5 keeps 50% above the observed peak-of-peaks.
pub const RIGHT_SIZING_HEADROOM: f64 = 1.5;

/// p95 utilization at which an allocation counts as saturated.
const SATURATION_P95_PERCENT: f64 = 90.0;

/// A CPU allocation is only reported as oversized when the p99 suggestion
/// (with headroom) fits within this share of the current cores.
const CPU_OVERPROVISIONED_SHARE: f64 = 0.5;

/// A RAM allocation is only reported as oversized when the p99 suggestion
/// (with headroom) fits within this share of the current total.
const RAM_OVERPROVISIONED_SHARE: f64 = 0.6;

/// Floor for a suggested RAM allocation: never propose less than 1 GiB.
const RAM_SUGGESTION_FLOOR_MB: f64 = 1024.0;

fn rule_rs_window_insufficient(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for window in &input.metric_windows {
        if window.stats.right_sizing_ready() {
            continue;
        }
        findings.push(Finding {
            rule_id: "rs.window-insufficient".into(),
            severity: Severity::Info,
            message: "utilization evidence is insufficient for right-sizing; keep \
                      collecting (or import history) before sizing decisions"
                .into(),
            evidence: vec![
                format!(
                    "{} samples over {:.1}h with {} confidence",
                    window.stats.sample_count,
                    window.stats.span_hours.unwrap_or(0.0),
                    window.stats.confidence
                ),
                format!(
                    "right-sizing needs >= {:.0}h of history with high confidence \
                     (`orbyn prometheus import` pulls a week in one run)",
                    crate::metrics::MIN_WINDOW_HOURS_FOR_RIGHT_SIZING
                ),
            ],
            asset_id: Some(window.asset_id.clone()),
        });
    }
}

fn rule_rs_cpu_overprovisioned(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for window in ready_windows(input) {
        let Some(cores) = input
            .capacities
            .iter()
            .find(|c| c.asset_id == window.asset_id)
            .and_then(|c| c.cpu_cores)
        else {
            continue;
        };
        let Some(p99) = window.stats.cpu_p99_percent else {
            continue;
        };
        let suggested = ((cores as f64 * p99 / 100.0 * RIGHT_SIZING_HEADROOM)
            .ceil()
            .max(1.0)) as u32;
        if (suggested as f64) > cores as f64 * CPU_OVERPROVISIONED_SHARE {
            continue;
        }
        findings.push(Finding {
            rule_id: "rs.cpu-overprovisioned".into(),
            severity: Severity::Info,
            message: format!(
                "CPU allocation is oversized: {cores} cores could shrink to \
                 {suggested} (p99 {p99:.1}% with {:.0}% headroom)",
                RIGHT_SIZING_HEADROOM * 100.0 - 100.0
            ),
            evidence: vec![
                format!(
                    "observed CPU: p95 {:.1}%  p99 {:.1}%  peak {:.1}%",
                    window.stats.cpu_p95_percent.unwrap_or(0.0),
                    p99,
                    window.stats.cpu_peak_percent.unwrap_or(0.0)
                ),
                format!(
                    "suggestion: ceil({cores} cores x p99 {:.1}% x {RIGHT_SIZING_HEADROOM}) \
                     = {suggested} cores",
                    p99
                ),
                window_evidence(&window.stats),
            ],
            asset_id: Some(window.asset_id.clone()),
        });
    }
}

fn rule_rs_ram_overprovisioned(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for window in ready_windows(input) {
        let Some(total_mb) = input
            .capacities
            .iter()
            .find(|c| c.asset_id == window.asset_id)
            .and_then(|c| c.ram_total_mb)
        else {
            continue;
        };
        let Some(p99_mb) = window.stats.ram_p99_mb else {
            continue;
        };
        let suggested_mb = (p99_mb * RIGHT_SIZING_HEADROOM)
            .ceil()
            .max(RAM_SUGGESTION_FLOOR_MB);
        if suggested_mb > total_mb as f64 * RAM_OVERPROVISIONED_SHARE {
            continue;
        }
        findings.push(Finding {
            rule_id: "rs.ram-overprovisioned".into(),
            severity: Severity::Info,
            message: format!(
                "RAM allocation is oversized: {} MB could shrink to {suggested_mb:.0} MB \
                 (p99 {:.1}% of total with {:.0}% headroom)",
                total_mb,
                p99_mb / total_mb as f64 * 100.0,
                RIGHT_SIZING_HEADROOM * 100.0 - 100.0
            ),
            evidence: vec![
                format!(
                    "observed RAM: p95 {:.0} MB  p99 {p99_mb:.0} MB  peak {:.0} MB",
                    window.stats.ram_p95_mb.unwrap_or(0.0),
                    window.stats.ram_peak_mb.unwrap_or(0.0)
                ),
                format!(
                    "suggestion: ceil(p99 {p99_mb:.0} MB x {RIGHT_SIZING_HEADROOM}) \
                     = {suggested_mb:.0} MB (floor {:.0} MB)",
                    RAM_SUGGESTION_FLOOR_MB
                ),
                window_evidence(&window.stats),
            ],
            asset_id: Some(window.asset_id.clone()),
        });
    }
}

fn rule_rs_cpu_saturated(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for window in ready_windows(input) {
        let Some(p95) = window.stats.cpu_p95_percent else {
            continue;
        };
        if p95 < SATURATION_P95_PERCENT {
            continue;
        }
        findings.push(Finding {
            rule_id: "rs.cpu-saturated".into(),
            severity: Severity::Warning,
            message: format!(
                "CPU utilization is saturated (p95 {p95:.1}% >= {SATURATION_P95_PERCENT:.0}%); \
                 the workload needs more capacity or tuning before migration"
            ),
            evidence: vec![
                format!(
                    "observed CPU: p95 {p95:.1}%  p99 {:.1}%  peak {:.1}%",
                    window.stats.cpu_p99_percent.unwrap_or(0.0),
                    window.stats.cpu_peak_percent.unwrap_or(0.0)
                ),
                window_evidence(&window.stats),
            ],
            asset_id: Some(window.asset_id.clone()),
        });
    }
}

fn rule_rs_ram_saturated(input: &AssessmentInput, findings: &mut Vec<Finding>) {
    for window in ready_windows(input) {
        let Some(total_mb) = input
            .capacities
            .iter()
            .find(|c| c.asset_id == window.asset_id)
            .and_then(|c| c.ram_total_mb)
        else {
            continue;
        };
        let Some(p95_mb) = window.stats.ram_p95_mb else {
            continue;
        };
        let p95_pct = p95_mb / total_mb as f64 * 100.0;
        if p95_pct < SATURATION_P95_PERCENT {
            continue;
        }
        findings.push(Finding {
            rule_id: "rs.ram-saturated".into(),
            severity: Severity::Warning,
            message: format!(
                "RAM utilization is saturated (p95 {p95_pct:.1}% of {total_mb} MB \
                 >= {SATURATION_P95_PERCENT:.0}%); the workload risks swapping or OOM \
                 during migration"
            ),
            evidence: vec![
                format!(
                    "observed RAM: p95 {p95_mb:.0} MB  p99 {:.0} MB  peak {:.0} MB",
                    window.stats.ram_p99_mb.unwrap_or(0.0),
                    window.stats.ram_peak_mb.unwrap_or(0.0)
                ),
                window_evidence(&window.stats),
            ],
            asset_id: Some(window.asset_id.clone()),
        });
    }
}

/// Right-sizing rules only trust windows that are ready for it: high
/// sample confidence over at least a meeting week of history.
fn ready_windows(input: &AssessmentInput) -> impl Iterator<Item = &AssetWindow> {
    input
        .metric_windows
        .iter()
        .filter(|w| w.stats.right_sizing_ready())
}

/// Shared evidence line: the observation window behind a right-sizing
/// finding, so every recommendation shows the data it rests on.
fn window_evidence(stats: &crate::metrics::WindowStats) -> String {
    format!(
        "window: {} samples over {:.1}h ({} confidence)",
        stats.sample_count,
        stats.span_hours.unwrap_or(0.0),
        stats.confidence
    )
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
    use chrono::{Datelike, Utc};

    fn asset(id: &str, ip: &str, os_name: Option<&str>) -> Asset {
        Asset {
            id: id.into(),
            ip: ip.parse().unwrap(),
            hostname: None,
            device_class: None,
            os_name: os_name.map(str::to_string),
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
    fn eol_table_parses_embedded_file() {
        let table = eol_table();
        assert!(parse_ym(&table.version).is_some(), "version is YYYY-MM");
        assert!(table.entries.len() >= 17, "known OS families present");
        assert!(table
            .entries
            .iter()
            .all(|e| !e.pattern.is_empty() && e.pattern.chars().all(|c| !c.is_uppercase())));
        for pattern in ["ubuntu 18.04", "centos 7", "windows server 2012"] {
            assert!(
                table.entries.iter().any(|e| e.pattern == pattern),
                "missing `{pattern}`"
            );
        }
    }

    #[test]
    fn eol_table_version_is_recent() {
        // Documented cadence: quarterly review, so allow six months of slack
        // before the table counts as stale and fails the build loudly.
        let table = eol_table();
        let (year, month) = parse_ym(&table.version).expect("version must be YYYY-MM");
        let now = Utc::now();
        let age_months = (now.year() - year) * 12 + now.month() as i32 - month as i32;
        assert!(
            age_months <= 6,
            "EOL table version {} is stale; review eol_os.csv and bump the version",
            table.version
        );
    }

    #[test]
    fn parse_eol_csv_synthetic_table() {
        let src = "# comment\nversion 2026-01\npattern,severity,note\n\
                   \"Legacy OS\",high,\"Ended in 2020, vendor\"\n\
                   newer,warning,\"Ends soon\"\n";
        let table = parse_eol_csv(src).expect("parses");
        assert_eq!(table.version, "2026-01");
        assert_eq!(table.entries.len(), 2);
        assert_eq!(table.entries[0].pattern, "legacy os", "pattern lowercased");
        assert_eq!(table.entries[0].severity, Severity::High);
        assert_eq!(table.entries[0].note, "Ended in 2020, vendor");
        assert_eq!(table.entries[1].severity, Severity::Warning);
    }

    #[test]
    fn parse_eol_csv_rejects_malformed_tables() {
        let bad = [
            "pattern,severity,note\nlegacy,high,ended\n", // no version line
            "version 2026-13\npattern,severity,note\nlegacy,high,ended\n", // bad month
            "version 2026-1\npattern,severity,note\nlegacy,high,ended\n", // bad format
            "version 2026-01\nlegacy,high,ended\n",       // no header row
            "version 2026-01\npattern,severity,note\n",   // no entries
            "version 2026-01\npattern,severity,note\nlegacy,critical,ended\n", // severity
            "version 2026-01\npattern,severity,note\nlegacy,high\n", // field count
            "version 2026-01\npattern,severity,note\nlegacy,high,\"open\n", // quote
            "version 2026-01\npattern,severity,note\n,high,ended\n", // empty pattern
            "version 2026-01\npattern,severity,note\nlegacy,high,\n", // empty note
        ];
        for src in bad {
            assert!(parse_eol_csv(src).is_err(), "must reject: {src}");
        }
    }

    #[test]
    fn csv_row_handles_quoted_fields() {
        assert_eq!(csv_row("a,b,\"c, d\"").unwrap(), vec!["a", "b", "c, d"]);
        assert_eq!(
            csv_row("\"he said \"\"hi\"\"\",x").unwrap(),
            vec!["he said \"hi\"", "x"]
        );
        assert!(csv_row("\"unterminated").is_err());
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

    /// A high-confidence utilization window spanning a full week.
    fn ready_window(asset_id: &str, cpu_p99: f64, ram_p99_mb: f64) -> AssetWindow {
        let start = Utc::now() - chrono::Duration::hours(200);
        let samples: Vec<crate::domain::MetricSample> = (0..24)
            .map(|i| crate::domain::MetricSample {
                asset_id: asset_id.into(),
                sampled_at: start + chrono::Duration::hours(i * 8),
                cpu_usage_percent: Some(cpu_p99 as f32),
                ram_used_mb: Some(ram_p99_mb as u64),
                ram_available_mb: None,
                swap_used_mb: None,
                load_1m: None,
                load_5m: None,
                load_15m: None,
            })
            .collect();
        let stats = crate::metrics::summarize(&samples).expect("window summarizes");
        assert!(stats.right_sizing_ready(), "fixture must be ready");
        AssetWindow {
            asset_id: asset_id.into(),
            stats,
        }
    }

    fn capacity_for(asset_id: &str, cores: u32, ram_total_mb: u64) -> crate::domain::Capacity {
        crate::domain::Capacity {
            asset_id: asset_id.into(),
            cpu_model: None,
            cpu_sockets: None,
            cpu_cores: Some(cores),
            cpu_threads: None,
            ram_total_mb: Some(ram_total_mb),
            collected_at: Utc::now(),
        }
    }

    #[test]
    fn insufficient_window_fires_and_suggests_import() {
        let mut window = ready_window("a1", 10.0, 1024.0);
        window.stats.span_hours = Some(2.0); // high confidence, tiny span
        let input = AssessmentInput {
            metric_windows: vec![window],
            ..Default::default()
        };
        let findings = run(&input, "rs.window-insufficient");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].evidence[1].contains("prometheus import"));

        // A ready window produces no insufficiency finding.
        let input = AssessmentInput {
            metric_windows: vec![ready_window("a1", 10.0, 1024.0)],
            ..Default::default()
        };
        assert!(run(&input, "rs.window-insufficient").is_empty());
    }

    #[test]
    fn overprovisioned_cpu_and_ram_are_flagged_with_math() {
        // 16 cores, p99 10% -> ceil(16 x 0.10 x 1.5) = 3 <= 8 (half).
        // 16384 MB, p99 4096 -> ceil(4096 x 1.5) = 6144 <= 9830 (60%).
        let input = AssessmentInput {
            assets: vec![asset("a1", "10.0.0.1", None)],
            capacities: vec![capacity_for("a1", 16, 16384)],
            metric_windows: vec![ready_window("a1", 10.0, 4096.0)],
            ..Default::default()
        };
        let cpu = run(&input, "rs.cpu-overprovisioned");
        assert_eq!(cpu.len(), 1);
        assert_eq!(cpu[0].severity, Severity::Info);
        assert!(cpu[0].message.contains("16 cores"), "{}", cpu[0].message);
        assert!(cpu[0].message.contains("3"), "{}", cpu[0].message);
        assert!(cpu[0].evidence[1].contains("= 3 cores"));

        let ram = run(&input, "rs.ram-overprovisioned");
        assert_eq!(ram.len(), 1);
        assert!(ram[0].message.contains("16384 MB"), "{}", ram[0].message);
        assert!(ram[0].evidence[1].contains("= 6144 MB"));
    }

    #[test]
    fn well_used_allocations_are_not_flagged() {
        // p99 60% of 8 cores -> ceil(8 x 0.6 x 1.5) = 8 > 4: no finding.
        // p99 12288 of 16384 MB -> 18432 > 9830: no finding.
        let input = AssessmentInput {
            assets: vec![asset("a1", "10.0.0.1", None)],
            capacities: vec![capacity_for("a1", 8, 16384)],
            metric_windows: vec![ready_window("a1", 60.0, 12288.0)],
            ..Default::default()
        };
        assert!(run(&input, "rs.cpu-overprovisioned").is_empty());
        assert!(run(&input, "rs.ram-overprovisioned").is_empty());
        assert!(run(&input, "rs.cpu-saturated").is_empty());
        assert!(run(&input, "rs.ram-saturated").is_empty());
    }

    #[test]
    fn saturated_cpu_and_ram_warn() {
        let input = AssessmentInput {
            assets: vec![asset("a1", "10.0.0.1", None)],
            capacities: vec![capacity_for("a1", 8, 16384)],
            metric_windows: vec![ready_window("a1", 95.0, 15872.0)],
            ..Default::default()
        };
        let cpu = run(&input, "rs.cpu-saturated");
        assert_eq!(cpu.len(), 1);
        assert_eq!(cpu[0].severity, Severity::Warning);
        assert!(cpu[0].message.contains("p95 95.0%"), "{}", cpu[0].message);

        let ram = run(&input, "rs.ram-saturated");
        assert_eq!(ram.len(), 1);
        assert_eq!(ram[0].severity, Severity::Warning);
        // 15872/16384 = 96.9% >= 90%.
        assert!(ram[0].message.contains("96.9%"), "{}", ram[0].message);
    }

    #[test]
    fn snapshots_never_drive_right_sizing() {
        // High sample count but zero span (three discovery snapshots): the
        // critical rule holds — no recommendation, only the insufficiency
        // guidance.
        let snapshots: Vec<crate::domain::MetricSample> = (0..12)
            .map(|i| crate::domain::MetricSample {
                asset_id: "a1".into(),
                sampled_at: Utc::now() + chrono::Duration::seconds(i),
                cpu_usage_percent: Some(2.0),
                ram_used_mb: Some(512),
                ram_available_mb: None,
                swap_used_mb: None,
                load_1m: None,
                load_5m: None,
                load_15m: None,
            })
            .collect();
        let stats = crate::metrics::summarize(&snapshots).expect("window summarizes");
        let input = AssessmentInput {
            assets: vec![asset("a1", "10.0.0.1", None)],
            capacities: vec![capacity_for("a1", 32, 65536)],
            metric_windows: vec![AssetWindow {
                asset_id: "a1".into(),
                stats,
            }],
            ..Default::default()
        };
        assert!(run(&input, "rs.cpu-overprovisioned").is_empty());
        assert!(run(&input, "rs.ram-overprovisioned").is_empty());
        assert_eq!(run(&input, "rs.window-insufficient").len(), 1);
    }
}
