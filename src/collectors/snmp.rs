//! SNMP collector (v0.2 milestone).
//!
//! Walks the `system` and `ifTable` MIB subtrees of a single host through the
//! `snmpwalk` binary (net-snmp-utils) and normalizes the text output into
//! [`crate::domain::Observation`]s.
//!
//! Security rules:
//! - targets are passed as process arguments, never shell-interpolated;
//! - the walk is read-only against MIB subtrees that expose metadata only;
//! - community strings are never logged or echoed to stdout;
//! - config directories left behind by abruptly terminated runs are removed
//!   (best effort) on the first walk of a process.

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use tokio::process::Command;
use uuid::Uuid;

use crate::domain::{asset_id, Asset, Interface, Observation};
use crate::process::{run_captured, MAX_STDERR_CAPTURE_BYTES, MAX_STDOUT_CAPTURE_BYTES};

use super::classify::classify_device;
use super::types::{Collector, ScanTarget};

/// Version of the SNMP protocol used for the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    V1,
    V2c,
}

impl fmt::Display for SnmpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnmpVersion::V1 => write!(f, "1"),
            SnmpVersion::V2c => write!(f, "2c"),
        }
    }
}

impl FromStr for SnmpVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "1" | "v1" => Ok(SnmpVersion::V1),
            "2c" | "v2c" | "2" | "v2" => Ok(SnmpVersion::V2c),
            other => Err(format!(
                "unsupported SNMP version '{other}' (expected 1 or 2c)"
            )),
        }
    }
}

pub struct SnmpCollector {
    binary: String,
    community: String,
    version: SnmpVersion,
    port: u16,
}

impl SnmpCollector {
    pub fn new(community: &str, version: SnmpVersion, port: u16) -> Self {
        let community = if community.is_empty() {
            std::env::var("ORBYN_SNMP_COMMUNITY").unwrap_or_else(|_| "public".to_string())
        } else {
            community.to_string()
        };
        Self {
            binary: std::env::var("ORBYN_SNMP_BIN").unwrap_or_else(|_| "snmpwalk".to_string()),
            community,
            version,
            port,
        }
    }

    /// Normalize `snmpwalk -On` text output into typed facts without invoking
    /// the binary (kept public so it can be tested against recorded fixtures).
    pub fn parse_walk(&self, output: &str) -> SnmpFacts {
        parse_walk(output)
    }

    /// Build normalized observations from parsed facts for a single target.
    pub fn observations_from_facts(
        &self,
        target: &ScanTarget,
        facts: &SnmpFacts,
    ) -> Result<Vec<Observation>> {
        let ip = match target {
            ScanTarget::Ip(ip) => *ip,
            ScanTarget::Cidr(cidr) => {
                bail!("SNMP walks a single host; target must be an IP address (got '{cidr}')")
            }
        };

        let now = Utc::now();
        let id = asset_id(ip);
        let vendor = vendor_from_object_id(facts.sys_object_id.as_deref());
        let device_class =
            classify_device(None, vendor.as_deref(), &[], facts.sys_descr.as_deref());

        let mut observations = vec![Observation::Asset(Asset {
            id: id.clone(),
            ip,
            hostname: facts.sys_name.clone(),
            device_class,
            os_name: derive_os_from_sysdescr(facts.sys_descr.as_deref()),
            os_version: None,
            sys_descr: facts.sys_descr.clone(),
            environment: None,
            owner: None,
            criticality: None,
            tags: Vec::new(),
            first_seen: now,
            last_seen: now,
        })];

        for entry in &facts.interfaces {
            let mac = entry.phys.as_deref().and_then(parse_snmp_phys);
            if entry.descr.is_none() && mac.is_none() {
                continue;
            }
            let mut iface = Interface::new(&id, entry.descr.as_deref(), mac.as_deref(), None);
            iface.if_index = Some(entry.index);
            iface.mtu = entry.mtu;
            iface.is_up = entry.oper_state.map(|s| s == 1);
            observations.push(Observation::Interface(iface));
        }

        Ok(observations)
    }
}

impl Default for SnmpCollector {
    fn default() -> Self {
        Self::new("", SnmpVersion::V2c, 161)
    }
}

#[async_trait]
impl Collector for SnmpCollector {
    fn name(&self) -> &'static str {
        "snmp"
    }

    async fn scan(&self, target: &ScanTarget) -> Result<Vec<Observation>> {
        STALE_CLEANUP.call_once(|| {
            cleanup_stale_snmp_dirs_in(&std::env::temp_dir(), STALE_SNMP_DIR_MAX_AGE);
        });

        let ip = match target {
            ScanTarget::Ip(ip) => *ip,
            ScanTarget::Cidr(cidr) => {
                bail!("SNMP walks a single host; target must be an IP address (got '{cidr}')")
            }
        };

        let agent = format!("{}:{}", ip, self.port);
        let system = self
            .run_walk(&agent, "1.3.6.1.2.1.1")
            .await
            .with_context(|| format!("snmpwalk of the system subtree on {ip}"))?;
        let interfaces = self
            .run_walk(&agent, "1.3.6.1.2.1.2.2.1")
            .await
            .with_context(|| format!("snmpwalk of the interface table on {ip}"))?;

        let mut facts = parse_walk(&system);
        let ifaces = parse_walk(&interfaces);
        facts.interfaces = ifaces.interfaces;
        self.observations_from_facts(target, &facts)
    }
}

/// Whole-process timeout for a single SNMP walk.
const SNMP_WALK_TIMEOUT: Duration = Duration::from_secs(30);

impl SnmpCollector {
    async fn run_walk(&self, agent: &str, oid: &str) -> Result<String> {
        let config_dir = write_community_config(&self.community)?;
        let result = self.run_walk_with_config(agent, oid, &config_dir).await;
        let _ = std::fs::remove_dir_all(&config_dir);
        result
    }

    async fn run_walk_with_config(
        &self,
        agent: &str,
        oid: &str,
        config_dir: &Path,
    ) -> Result<String> {
        let child = Command::new(&self.binary)
            .arg("-v")
            .arg(self.version.to_string())
            .arg("-On")
            .arg("-t")
            .arg("3")
            .arg("-r")
            .arg("1")
            .arg(agent)
            .arg(oid)
            .env("SNMPCONFPATH", config_dir)
            // Secret-bearing variables never reach the child environment
            // (audit OY-02): a hijacked binary must not be able to read the
            // community, the NetBox token, the WinRM password or the
            // database URL password.
            .env_remove("ORBYN_SNMP_COMMUNITY")
            .env_remove("ORBYN_NETBOX_TOKEN")
            .env_remove("ORBYN_WINRM_PASSWORD")
            .env_remove("ORBYN_PROMETHEUS_TOKEN")
            .env_remove("ORBYN_DB")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("failed to start snmpwalk; is net-snmp-utils installed?")?;

        let captured = run_captured(
            child,
            None,
            MAX_STDOUT_CAPTURE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
            SNMP_WALK_TIMEOUT,
            format!("snmpwalk timed out against {agent}"),
        )
        .await?;

        if !captured.status.success() {
            return Err(anyhow!(
                "snmpwalk exited with {} against {agent}: {}",
                captured.status,
                captured.stderr.trim()
            ));
        }
        if captured.stdout_truncated {
            return Err(anyhow!(
                "snmpwalk output against {agent} exceeded the {} byte \
                 capture limit; the walk result is incomplete",
                MAX_STDOUT_CAPTURE_BYTES
            ));
        }
        Ok(captured.stdout)
    }
}

fn write_community_config(community: &str) -> Result<PathBuf> {
    if community.contains(['\n', '\r', '\0']) {
        bail!("SNMP community cannot contain newlines or NUL bytes")
    }

    let dir = std::env::temp_dir().join(format!("orbyn-snmp-{}", Uuid::new_v4()));
    std::fs::create_dir(&dir)
        .with_context(|| format!("creating temporary SNMP config directory {}", dir.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(error).context("restricting temporary SNMP config directory");
        }
    }

    let path = dir.join("snmp.conf");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("creating temporary SNMP community file {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .context("restricting temporary SNMP community file permissions")?;
    }

    file.write_all(format!("defCommunity {community}\n").as_bytes())
        .context("writing temporary SNMP community file")?;
    Ok(dir)
}

/// SNMP config directories untouched for at least this long are considered
/// stale. The value sits far above the 30 s walk timeout so a concurrently
/// running Orbyn process never has its live config removed.
const STALE_SNMP_DIR_MAX_AGE: Duration = Duration::from_secs(3600);

/// Ensures the stale-config cleanup runs at most once per process.
static STALE_CLEANUP: std::sync::Once = std::sync::Once::new();

/// Best-effort removal of SNMP config directories left behind by abrupt
/// termination (e.g. SIGKILL, which skips the post-walk cleanup). Only
/// directories named exactly `orbyn-snmp-<uuid>`, owned by the current user
/// on Unix, and untouched for at least `max_age` are removed; every error is
/// logged at debug level and otherwise ignored.
fn cleanup_stale_snmp_dirs_in(base: &Path, max_age: Duration) {
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };

    #[cfg(unix)]
    let current_uid = current_uid();

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_snmp_config_dir(name) {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !current_uid.is_some_and(|uid| meta.uid() == uid) {
                continue;
            }
        }

        // A missing or future-dated mtime counts as fresh: never risk
        // removing the config of a concurrently running process.
        let stale = meta
            .modified()
            .ok()
            .and_then(|mtime| mtime.elapsed().ok())
            .is_some_and(|age| age >= max_age);
        if !stale {
            continue;
        }

        let path = entry.path();
        if let Err(error) = std::fs::remove_dir_all(&path) {
            tracing::debug!(?error, path = %path.display(), "cannot remove stale SNMP config directory");
        }
    }
}

/// Recognize the exact `orbyn-snmp-<uuid>` naming scheme produced by
/// [`write_community_config`]; anything else in the temp dir is left alone.
fn is_snmp_config_dir(name: &str) -> bool {
    name.strip_prefix("orbyn-snmp-")
        .is_some_and(|suffix| Uuid::parse_str(suffix).is_ok())
}

/// Best-effort uid of the current process on Unix, learned by stat-ing a
/// freshly created probe file (Orbyn carries no uid crate).
#[cfg(unix)]
fn current_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let probe = std::env::temp_dir().join(format!(".orbyn-uid-probe-{}", Uuid::new_v4()));
    std::fs::write(&probe, b"").ok()?;
    let uid = std::fs::metadata(&probe).ok().map(|meta| meta.uid());
    let _ = std::fs::remove_file(&probe);
    uid
}

/// Derive a concise, human-readable OS name from a raw SNMP `sysDescr`
/// string. Returns `None` when the description is empty or unrecognizable.
///
/// Known vendor/OS families are matched case-insensitively; the first match
/// wins. Unrecognized descriptions fall back to the first comma-separated
/// segment (trimmed, capped at 80 characters) so `os_name` is never the full
/// noisy banner.
fn derive_os_from_sysdescr(descr: Option<&str>) -> Option<String> {
    let descr = descr?.trim();
    if descr.is_empty() {
        return None;
    }
    let lower = descr.to_lowercase();

    const KNOWN: &[(&str, &str)] = &[
        ("cisco ios", "Cisco IOS"),
        ("ios xe", "Cisco IOS-XE"),
        ("nx-os", "Cisco NX-OS"),
        ("junos", "Juniper Junos"),
        ("junos", "Juniper Junos"),
        ("fortigate", "FortiOS"),
        ("fortios", "FortiOS"),
        ("palo alto", "PAN-OS"),
        ("vmware esx", "VMware ESXi"),
        ("esxi", "VMware ESXi"),
        ("netapp", "NetApp ONTAP"),
        ("linux", "Linux"),
        ("windows", "Windows"),
        ("freebsd", "FreeBSD"),
    ];
    for (needle, os) in KNOWN {
        if lower.contains(needle) {
            return Some(os.to_string());
        }
    }

    // Fallback: first comma-separated segment, trimmed and length-bounded.
    let segment = descr.split(',').next().unwrap_or(descr).trim();
    if segment.chars().count() > 80 {
        // Truncate by characters, never by bytes: byte slicing at a
        // multibyte boundary would panic on hostile sysDescr values
        // (audit OY-15).
        Some(format!("{}…", segment.chars().take(79).collect::<String>()))
    } else if segment.is_empty() {
        None
    } else {
        Some(segment.to_string())
    }
}

/// Facts collected from `snmpwalk -On` text output.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SnmpFacts {
    pub sys_descr: Option<String>,
    pub sys_name: Option<String>,
    pub sys_object_id: Option<String>,
    pub interfaces: Vec<IfEntry>,
}

/// A single interface row from the `ifTable`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct IfEntry {
    pub index: u32,
    pub descr: Option<String>,
    /// Raw `ifPhysAddress` value (NULL/empty for interfaces without a MAC).
    pub phys: Option<String>,
    pub mtu: Option<u32>,
    /// `ifOperStatus`: 1 = up.
    pub oper_state: Option<u32>,
}

/// Parse net-snmp `-On` walk output into [`SnmpFacts`].
fn parse_walk(output: &str) -> SnmpFacts {
    let mut facts = SnmpFacts::default();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((oid, raw_value)) = line.split_once(" = ") else {
            continue;
        };
        let oid = oid.trim().trim_start_matches('.');
        let (_typ, value) = split_value(raw_value.trim());

        if let Some(n) = strip_prefix(oid, "1.3.6.1.2.1.2.2.1.2.") {
            entry_for(&mut facts, n).descr = value.clone();
        } else if let Some(n) = strip_prefix(oid, "1.3.6.1.2.1.2.2.1.6.") {
            entry_for(&mut facts, n).phys = value.clone().filter(|v| !v.is_empty());
        } else if let Some(n) = strip_prefix(oid, "1.3.6.1.2.1.2.2.1.4.") {
            entry_for(&mut facts, n).mtu = value.clone().and_then(|v| v.parse().ok());
        } else if let Some(n) = strip_prefix(oid, "1.3.6.1.2.1.2.2.1.8.") {
            entry_for(&mut facts, n).oper_state = value.clone().and_then(|v| v.parse().ok());
        }

        match oid {
            "1.3.6.1.2.1.1.1.0" => facts.sys_descr = facts.sys_descr.or(value),
            "1.3.6.1.2.1.1.5.0" => facts.sys_name = facts.sys_name.or(value),
            "1.3.6.1.2.1.1.2.0" => facts.sys_object_id = facts.sys_object_id.or(value),
            _ => {}
        }
    }
    facts
}

/// Map a `sysObjectID` to a vendor hint, when the enterprise number is known.
fn vendor_from_object_id(oid: Option<&str>) -> Option<String> {
    let oid = oid?;
    let enterprise = oid
        .trim_start_matches('.')
        .split('.')
        .nth(6)
        .and_then(|n| n.parse::<u32>().ok())?;
    let vendor = match enterprise {
        9 => "Cisco",
        2636 => "Juniper",
        11 | 4405 => "Hewlett Packard",
        2011 => "Huawei",
        12356 => "Fortinet",
        171 => "Avaya",
        11638 => "Riverbed",
        236 => "IBM",
        _ => return None,
    };
    Some(vendor.to_string())
}

/// Split `TYPE: value` into the (type, optional payload).
fn split_value(raw: &str) -> (&str, Option<String>) {
    let Some((typ, rest)) = raw.split_once(':') else {
        return (raw, None);
    };
    (typ.trim(), Some(rest.trim().to_string()))
}

/// Parse the final instance number from a dotted OID prefix.
fn strip_prefix(oid: &str, prefix: &str) -> Option<u32> {
    oid.strip_prefix(prefix).and_then(|tail| tail.parse().ok())
}

fn entry_for(facts: &mut SnmpFacts, index: u32) -> &mut IfEntry {
    if facts.interfaces.iter().any(|e| e.index == index) {
        return facts
            .interfaces
            .iter_mut()
            .find(|e| e.index == index)
            .expect("checked above");
    }
    facts.interfaces.push(IfEntry {
        index,
        ..Default::default()
    });
    facts.interfaces.last_mut().expect("just pushed")
}

/// Convert an SNMP `ifPhysAddress` payload into a normalized MAC address.
///
/// Handles `Hex-STRING` (space separated) and colon-separated hex or decimal
/// byte values as produced by different agents. Returns `None` for an empty or
/// non-MAC value.
fn parse_snmp_phys(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }

    let parts: Vec<&str> = if trimmed.contains(' ') {
        trimmed.split_whitespace().collect()
    } else {
        trimmed.split(':').collect()
    };

    if parts.len() != 6 {
        return None;
    }

    let mut bytes = Vec::with_capacity(6);
    for part in parts {
        let part = part.trim();
        let byte = u8::from_str_radix(part, 16)
            .or_else(|_| part.parse::<u8>())
            .ok()?;
        bytes.push(byte);
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSTEM_WALK: &str = r#".1.3.6.1.2.1.1.1.0 = STRING: Linux host 5.15.0-91-generic example
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.8072.3.2.10
.1.3.6.1.2.1.1.5.0 = STRING: switch-a
"#;

    const IF_WALK: &str = r#".1.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.2.1 = STRING: lo
.1.3.6.1.2.1.2.2.1.4.1 = INTEGER: 65536
.1.3.6.1.2.1.2.2.1.6.1 = STRING:
.1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1
.1.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2
.1.3.6.1.2.1.2.2.1.2.2 = STRING: eth0
.1.3.6.1.2.1.2.2.1.4.2 = Gauge32: 1500
.1.3.6.1.2.1.2.2.1.6.2 = Hex-STRING: 00 11 22 33 44 55
.1.3.6.1.2.1.2.2.1.8.2 = INTEGER: 1
"#;

    #[test]
    fn parses_system_and_interfaces() {
        let mut facts = parse_walk(SYSTEM_WALK);
        facts.interfaces = parse_walk(IF_WALK).interfaces;

        assert_eq!(
            facts.sys_descr.as_deref(),
            Some("Linux host 5.15.0-91-generic example")
        );
        assert_eq!(facts.sys_name.as_deref(), Some("switch-a"));
        assert_eq!(facts.interfaces.len(), 2);

        let lo = facts.interfaces.iter().find(|e| e.index == 1).unwrap();
        assert_eq!(lo.descr.as_deref(), Some("lo"));
        assert_eq!(lo.phys, None);
        assert_eq!(lo.mtu, Some(65536));
        assert_eq!(lo.oper_state, Some(1));

        let eth = facts.interfaces.iter().find(|e| e.index == 2).unwrap();
        assert_eq!(eth.descr.as_deref(), Some("eth0"));
        assert_eq!(eth.phys.as_deref(), Some("00 11 22 33 44 55"));
        assert_eq!(eth.mtu, Some(1500));
    }

    #[test]
    fn builds_observations_from_facts() {
        let mut facts = parse_walk(SYSTEM_WALK);
        facts.interfaces = parse_walk(IF_WALK).interfaces;
        let collector = SnmpCollector::default();
        let target = ScanTarget::Ip("10.0.0.7".parse().unwrap());
        let observations = collector
            .observations_from_facts(&target, &facts)
            .expect("observations");

        let assets: Vec<&Asset> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::Asset(a) => Some(a),
                _ => None,
            })
            .collect();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].hostname.as_deref(), Some("switch-a"));
        assert_eq!(assets[0].os_name.as_deref(), Some("Linux"));
        assert_eq!(
            assets[0].sys_descr.as_deref(),
            Some("Linux host 5.15.0-91-generic example")
        );

        let interfaces: Vec<&Interface> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::Interface(i) => Some(i),
                _ => None,
            })
            .collect();
        assert_eq!(interfaces.len(), 2);
        let eth = interfaces
            .iter()
            .find(|i| i.name.as_deref() == Some("eth0"))
            .unwrap();
        assert_eq!(eth.mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(eth.mtu, Some(1500));
        assert_eq!(eth.if_index, Some(2));
        assert_eq!(eth.is_up, Some(true));
    }

    #[test]
    fn cidr_targets_are_rejected() {
        let collector = SnmpCollector::default();
        let target = ScanTarget::Cidr("10.0.0.0/24".into());
        let facts = SnmpFacts::default();
        assert!(collector.observations_from_facts(&target, &facts).is_err());
    }

    #[test]
    fn parse_phys_formats() {
        assert_eq!(
            parse_snmp_phys("00 11 22 33 44 55"),
            Some("00:11:22:33:44:55".into())
        );
        assert_eq!(
            parse_snmp_phys("0:2:2d:a1:b2:c3"),
            Some("00:02:2d:a1:b2:c3".into())
        );
        assert_eq!(parse_snmp_phys(""), None);
        assert_eq!(parse_snmp_phys("not a mac"), None);
    }

    #[test]
    fn community_config_does_not_put_secret_in_path() {
        let dir = write_community_config("super-secret").expect("community config");
        assert!(!dir.to_string_lossy().contains("super-secret"));
        assert_eq!(
            std::fs::read_to_string(dir.join("snmp.conf")).unwrap(),
            "defCommunity super-secret\n"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn community_file_rejects_config_injection_characters() {
        assert!(write_community_config("bad\nsecret").is_err());
        assert!(write_community_config("bad\0secret").is_err());
    }

    fn cleanup_test_base(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("orbyn-snmp-cleanup-test-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create cleanup test base dir");
        dir
    }

    #[test]
    fn cleanup_removes_stale_dirs_and_keeps_unrelated_names() {
        let base = cleanup_test_base("stale");
        let stale = base.join(format!("orbyn-snmp-{}", Uuid::new_v4()));
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("snmp.conf"), "defCommunity secret\n").unwrap();
        let unrelated = base.join("orbyn-snmp-not-a-uuid");
        std::fs::create_dir(&unrelated).unwrap();

        cleanup_stale_snmp_dirs_in(&base, Duration::ZERO);

        assert!(!stale.exists(), "stale config dir must be removed");
        assert!(unrelated.exists(), "unrelated names must be kept");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn cleanup_keeps_fresh_dirs() {
        let base = cleanup_test_base("fresh");
        let fresh = base.join(format!("orbyn-snmp-{}", Uuid::new_v4()));
        std::fs::create_dir(&fresh).unwrap();

        cleanup_stale_snmp_dirs_in(&base, STALE_SNMP_DIR_MAX_AGE);

        assert!(fresh.exists(), "fresh config dir must survive cleanup");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn recognizes_only_exact_snmp_config_names() {
        assert!(is_snmp_config_dir(&format!(
            "orbyn-snmp-{}",
            Uuid::new_v4()
        )));
        assert!(!is_snmp_config_dir("orbyn-snmp-"));
        assert!(!is_snmp_config_dir("orbyn-snmp-not-a-uuid"));
        assert!(!is_snmp_config_dir("orbyn-snmp-../../etc"));
        assert!(!is_snmp_config_dir(
            "other-orbyn-snmp-00000000-0000-0000-0000-000000000000"
        ));
    }

    #[test]
    fn object_id_maps_to_vendor() {
        assert_eq!(
            vendor_from_object_id(Some(".1.3.6.1.4.1.9.1.1230")),
            Some("Cisco".into())
        );
        assert_eq!(
            vendor_from_object_id(Some(".1.3.6.1.4.1.8072.3.2.10")),
            None
        );
        assert_eq!(vendor_from_object_id(None), None);
    }

    #[test]
    fn derive_os_from_known_sysdescr() {
        assert_eq!(
            derive_os_from_sysdescr(Some("Cisco IOS Software, IOSv")),
            Some("Cisco IOS".into())
        );
        assert_eq!(
            derive_os_from_sysdescr(Some("Juniper Networks Junos 23.4R1")),
            Some("Juniper Junos".into())
        );
        assert_eq!(
            derive_os_from_sysdescr(Some("Linux host 5.15.0-91-generic example")),
            Some("Linux".into())
        );
        assert_eq!(
            derive_os_from_sysdescr(Some("VMware ESXi 8.0 U2")),
            Some("VMware ESXi".into())
        );
        assert_eq!(
            derive_os_from_sysdescr(Some("FortiGate-60F v7.0")),
            Some("FortiOS".into())
        );
    }

    #[test]
    fn derive_os_falls_back_to_first_segment() {
        assert_eq!(
            derive_os_from_sysdescr(Some("SomeVendor OS 3.0, Build 12345, (c) 2024")),
            Some("SomeVendor OS 3.0".into())
        );
        assert_eq!(derive_os_from_sysdescr(None), None);
        assert_eq!(derive_os_from_sysdescr(Some("")), None);
        assert_eq!(derive_os_from_sysdescr(Some("   ")), None);
    }

    #[test]
    fn derive_os_truncates_multibyte_without_panicking() {
        // 100 two-byte chars: the old byte slicing (`&segment[..79]`) cut a
        // multibyte boundary and panicked; character-based truncation must
        // produce exactly 79 chars plus the ellipsis.
        let descr = "é".repeat(100);
        let os = derive_os_from_sysdescr(Some(&descr)).expect("truncated os name");
        assert_eq!(os.chars().count(), 80, "79 chars + ellipsis");
        assert!(os.ends_with('…'));
    }
}
