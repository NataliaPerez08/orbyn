//! Inventory import parsing (shared by the CLI `orbyn import` command).
//!
//! The CSV path parses the worksheets of an Orbyn export: the `#assets`
//! section (accepting both the full 12-column export form and a compact
//! 7-column import form), plus the `#interfaces` and `#services` sections so
//! an export/import round-trip keeps interfaces and services instead of
//! silently dropping them.

use anyhow::{bail, Context, Result};

use crate::parsing::{normalize_ip, split_csv_line};
/// An asset row accepted by `orbyn import` (JSON or CSV).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct ImportedAsset {
    pub ip: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub device_class: Option<String>,
    #[serde(default)]
    pub os_name: Option<String>,
    #[serde(default)]
    pub os_version: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub criticality: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// An interface row accepted by `orbyn import` (JSON or CSV `#interfaces`).
///
/// Mirrors the `#interfaces` worksheet of an Orbyn export; the `id` column
/// emitted by exports is re-derived on persist, so it is not imported.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct ImportedInterface {
    pub asset_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub ip: Option<std::net::IpAddr>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub if_index: Option<u32>,
    #[serde(default)]
    pub is_up: Option<bool>,
}

/// A service row accepted by `orbyn import` (JSON or CSV `#services`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct ImportedService {
    pub asset_id: String,
    pub proto: String,
    pub port: u16,
    #[serde(default)]
    pub name: Option<String>,
    pub state: String,
    #[serde(default)]
    pub banner: Option<String>,
}

/// A full inventory accepted by `orbyn import`: assets plus the interfaces
/// and services emitted by `orbyn export`. Every section is optional so a
/// bare asset list keeps working.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct ImportedInventory {
    #[serde(default)]
    pub assets: Vec<ImportedAsset>,
    #[serde(default)]
    pub interfaces: Vec<ImportedInterface>,
    #[serde(default)]
    pub services: Vec<ImportedService>,
}

/// Counts of what an import actually persisted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportedStats {
    pub assets: usize,
    pub interfaces: usize,
    pub services: usize,
}

/// Resolve an `asset_id` reference from an import file to the canonical
/// Orbyn asset id: IP-shaped references (hand-written files) map to the id
/// form derived from the IP, while ids (as emitted by exports) pass through.
pub fn resolve_asset_id(raw: &str) -> String {
    match normalize_ip(raw) {
        Some(ip) => crate::domain::asset_id(ip),
        None => raw.to_string(),
    }
}

/// Parse an Orbyn CSV export into import rows.
///
/// A CSV without any `#section` header (e.g. a hand-written compact import)
/// is treated as being entirely in the `assets` section. Sections Orbyn does
/// not import are skipped.
pub fn parse_import_csv(input: &str) -> Result<ImportedInventory> {
    let mut inventory = ImportedInventory::default();
    let mut section = String::from("assets");
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('#') {
            section = name.trim().to_lowercase();
            continue;
        }
        match section.as_str() {
            "assets" => {
                if line.starts_with("id,ip") {
                    continue; // column header
                }
                inventory.assets.push(parse_asset_line(line)?);
            }
            "interfaces" => {
                if line.starts_with("asset_id,name") {
                    continue; // column header
                }
                inventory.interfaces.push(parse_interface_line(line)?);
            }
            "services" => {
                if line.starts_with("asset_id,proto") {
                    continue; // column header
                }
                inventory.services.push(parse_service_line(line)?);
            }
            _ => {} // a section Orbyn does not import (yet)
        }
    }
    Ok(inventory)
}

/// Parse one `#assets` row, accepting both the 12-column export form and a
/// compact 7-column import form.
fn parse_asset_line(line: &str) -> Result<ImportedAsset> {
    let fields = split_csv_line(line);
    let (ip, hostname, device_class, os_name, os_version, environment, owner, criticality, tags) =
        match fields.len() {
            12 => {
                let mut it = fields.into_iter();
                let _id = it.next().unwrap();
                let ip = it.next().unwrap();
                let hostname = it.next().unwrap();
                let device_class = it.next().unwrap();
                let os_name = it.next().unwrap();
                let os_version = it.next().unwrap();
                let environment = it.next().unwrap();
                let owner = it.next().unwrap();
                let criticality = it.next().unwrap();
                let tags = it.next().unwrap();
                let _first_seen = it.next().unwrap();
                let _last_seen = it.next().unwrap();
                (
                    ip,
                    opt(hostname),
                    opt(device_class),
                    opt(os_name),
                    opt(os_version),
                    opt(environment),
                    opt(owner),
                    opt(criticality),
                    tags,
                )
            }
            7 => {
                let mut it = fields.into_iter();
                let ip = it.next().unwrap();
                let hostname = it.next().unwrap();
                let device_class = it.next().unwrap();
                let environment = it.next().unwrap();
                let owner = it.next().unwrap();
                let criticality = it.next().unwrap();
                let tags = it.next().unwrap();
                (
                    ip,
                    opt(hostname),
                    opt(device_class),
                    None,
                    None,
                    opt(environment),
                    opt(owner),
                    opt(criticality),
                    tags,
                )
            }
            other => bail!("unexpected CSV column count {other} in import line"),
        };
    let tags = tags
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect();
    Ok(ImportedAsset {
        ip,
        hostname,
        device_class,
        os_name,
        os_version,
        environment,
        owner,
        criticality,
        tags,
    })
}

/// Parse one `#interfaces` row: `asset_id,name,mac,ip,vendor,mtu,if_index,up`.
fn parse_interface_line(line: &str) -> Result<ImportedInterface> {
    let fields = split_csv_line(line);
    if fields.len() != 8 {
        bail!(
            "unexpected CSV column count {} in interfaces line",
            fields.len()
        );
    }
    let mut it = fields.into_iter();
    let asset_id = it.next().unwrap();
    let name = opt(it.next().unwrap());
    let mac = opt(it.next().unwrap());
    let ip = match opt(it.next().unwrap()) {
        Some(raw) => Some(
            normalize_ip(&raw)
                .with_context(|| format!("invalid IP '{raw}' in interfaces import line"))?,
        ),
        None => None,
    };
    let vendor = opt(it.next().unwrap());
    let mtu = opt_num(it.next().unwrap(), "interface MTU")?;
    let if_index = opt_num(it.next().unwrap(), "interface index")?;
    let is_up = parse_up_state(it.next().unwrap())?;
    if asset_id.is_empty() {
        bail!("interfaces import line is missing its asset_id");
    }
    Ok(ImportedInterface {
        asset_id,
        name,
        mac,
        ip,
        vendor,
        mtu,
        if_index,
        is_up,
    })
}

/// Parse one `#services` row: `asset_id,proto,port,name,state,banner`.
fn parse_service_line(line: &str) -> Result<ImportedService> {
    let fields = split_csv_line(line);
    if fields.len() != 6 {
        bail!(
            "unexpected CSV column count {} in services line",
            fields.len()
        );
    }
    let mut it = fields.into_iter();
    let asset_id = it.next().unwrap();
    let proto = it.next().unwrap();
    let port: u16 = it
        .next()
        .unwrap()
        .parse()
        .with_context(|| format!("invalid port in services import line '{line}'"))?;
    let name = opt(it.next().unwrap());
    let state = it.next().unwrap();
    let banner = opt(it.next().unwrap());
    if asset_id.is_empty() {
        bail!("services import line is missing its asset_id");
    }
    if proto.is_empty() {
        bail!("services import line is missing its protocol");
    }
    if state.is_empty() {
        bail!("services import line is missing its state");
    }
    Ok(ImportedService {
        asset_id,
        proto,
        port,
        name,
        state,
        banner,
    })
}

/// Map an empty or placeholder CSV field to `None`.
fn opt(value: String) -> Option<String> {
    if value.is_empty() || value == "-" {
        None
    } else {
        Some(value)
    }
}

/// Parse an optional numeric CSV field (`-`/empty means unknown).
fn opt_num<T: std::str::FromStr>(value: String, what: &str) -> Result<Option<T>> {
    match opt(value) {
        None => Ok(None),
        Some(raw) => match raw.parse::<T>() {
            Ok(parsed) => Ok(Some(parsed)),
            Err(_) => bail!("invalid {what} '{raw}' in interfaces import line"),
        },
    }
}

/// Parse the `up` column: `up`/`down`, `-` or empty when unknown.
fn parse_up_state(value: String) -> Result<Option<bool>> {
    match opt(value) {
        None => Ok(None),
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "up" => Ok(Some(true)),
            "down" => Ok(Some(false)),
            other => bail!("invalid interface state '{other}' (expected up or down)"),
        },
    }
}

/// Deduplicate import rows by IP, keeping the first occurrence and counting
/// how many duplicates were dropped. Rows whose IP does not parse are kept so
/// the caller can surface a clear error instead of silently discarding them.
pub fn deduplicate(rows: Vec<ImportedAsset>) -> (Vec<ImportedAsset>, usize) {
    use std::collections::HashSet;
    use std::net::IpAddr;

    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut kept = Vec::with_capacity(rows.len());
    let mut duplicates = 0usize;
    for row in rows {
        match crate::parsing::normalize_ip(&row.ip) {
            Some(ip) if seen.insert(ip) => kept.push(row),
            Some(_) => duplicates += 1,
            None => kept.push(row),
        }
    }
    (kept, duplicates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_12_column_export() {
        let csv = "#assets\nid,ip,hostname,device_class,os_name,os_version,environment,owner,criticality,tags,first_seen,last_seen\n\
10-0-0-1,10.0.0.1,web-01,server,Ubuntu 22.04,,prod,platform,high,\"core,api\",2024-01-01T00:00:00+00:00,2024-01-02T00:00:00+00:00\n";
        let inv = parse_import_csv(csv).expect("parse");
        assert_eq!(inv.assets.len(), 1);
        let r = &inv.assets[0];
        assert_eq!(r.ip, "10.0.0.1");
        assert_eq!(r.hostname.as_deref(), Some("web-01"));
        assert_eq!(r.device_class.as_deref(), Some("server"));
        assert_eq!(r.os_name.as_deref(), Some("Ubuntu 22.04"));
        assert_eq!(r.os_version, None);
        assert_eq!(r.environment.as_deref(), Some("prod"));
        assert_eq!(r.owner.as_deref(), Some("platform"));
        assert_eq!(r.criticality.as_deref(), Some("high"));
        // tags is a single (comma-joined, quoted) field split on commas
        assert_eq!(r.tags, vec!["core".to_string(), "api".to_string()]);
    }

    #[test]
    fn parses_7_column_compact_form() {
        let csv = "10.0.0.2,db-01,server,prod,dba,critical,\"database,dr\"\n";
        let inv = parse_import_csv(csv).expect("parse");
        assert_eq!(inv.assets.len(), 1);
        let r = &inv.assets[0];
        assert_eq!(r.ip, "10.0.0.2");
        assert_eq!(r.hostname.as_deref(), Some("db-01"));
        assert_eq!(r.criticality.as_deref(), Some("critical"));
        assert_eq!(r.tags, vec!["database".to_string(), "dr".to_string()]);
        assert_eq!(r.os_name, None);
    }

    #[test]
    fn parses_interfaces_and_services_sections() {
        let csv = "#assets\nid,ip,hostname,device_class,os_name,os_version,environment,owner,criticality,tags,first_seen,last_seen\n\
10-0-0-1,10.0.0.1,web-01,server,,,,,,,,\n\
\n#interfaces\nasset_id,name,mac,ip,vendor,mtu,if_index,up\n\
10-0-0-1,eth0,00:11:22:33:44:55,10.0.0.1,Intel,1500,2,up\n\
10-0-0-1,eth1,-,-,-,-,-,down\n\
\n#services\nasset_id,proto,port,name,state,banner\n\
10-0-0-1,tcp,443,https,open,nginx\n\
10-0-0-1,tcp,22,ssh,open,\n";
        let inv = parse_import_csv(csv).expect("parse");
        assert_eq!(inv.assets.len(), 1);
        assert_eq!(inv.interfaces.len(), 2);
        assert_eq!(inv.services.len(), 2);

        let eth0 = &inv.interfaces[0];
        assert_eq!(eth0.asset_id, "10-0-0-1");
        assert_eq!(eth0.name.as_deref(), Some("eth0"));
        assert_eq!(eth0.mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(eth0.ip, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(eth0.vendor.as_deref(), Some("Intel"));
        assert_eq!(eth0.mtu, Some(1500));
        assert_eq!(eth0.if_index, Some(2));
        assert_eq!(eth0.is_up, Some(true));

        let eth1 = &inv.interfaces[1];
        assert_eq!(eth1.name.as_deref(), Some("eth1"));
        assert_eq!(eth1.mac, None);
        assert_eq!(eth1.ip, None);
        assert_eq!(eth1.mtu, None);
        assert_eq!(eth1.if_index, None);
        assert_eq!(eth1.is_up, Some(false));

        let https = &inv.services[0];
        assert_eq!(https.asset_id, "10-0-0-1");
        assert_eq!(https.proto, "tcp");
        assert_eq!(https.port, 443);
        assert_eq!(https.name.as_deref(), Some("https"));
        assert_eq!(https.state, "open");
        assert_eq!(https.banner.as_deref(), Some("nginx"));
        assert_eq!(inv.services[1].banner, None);
    }

    #[test]
    fn unknown_sections_are_skipped() {
        let csv = "#filesystems\nasset_id,mount,size_kb\nx,/,1000\n\n#assets\nid,ip,hostname,device_class,os_name,os_version,environment,owner,criticality,tags,first_seen,last_seen\n\
10-0-0-1,10.0.0.1,web-01,,,,,,,,,\n";
        let inv = parse_import_csv(csv).expect("parse");
        assert_eq!(inv.assets.len(), 1, "unknown sections are skipped");
        assert_eq!(inv.assets[0].hostname.as_deref(), Some("web-01"));
        assert!(inv.interfaces.is_empty());
    }

    #[test]
    fn empty_placeholders_map_to_none() {
        assert_eq!(opt("".into()), None);
        assert_eq!(opt("-".into()), None);
        assert_eq!(opt("x".into()), Some("x".into()));
    }

    #[test]
    fn bad_column_count_errors() {
        let csv = "10.0.0.1,web-01\n";
        assert!(parse_import_csv(csv).is_err());
    }

    #[test]
    fn bad_interface_row_errors() {
        for line in [
            "10-0-0-1,eth0,00:11:22:33:44:55,10.0.0.1,Intel,1500,2", // 7 columns
            "10-0-0-1,eth0,-,not-an-ip,-,-,-,-",
            "10-0-0-1,eth0,-,-,-,big,-,-",
            "10-0-0-1,eth0,-,-,-,-,-,sideways",
            ",eth0,-,-,-,-,-,-",
        ] {
            let csv = format!("#interfaces\nasset_id,name,mac,ip,vendor,mtu,if_index,up\n{line}\n");
            assert!(
                parse_import_csv(&csv).is_err(),
                "expected an error for interfaces line: {line}"
            );
        }
    }

    #[test]
    fn bad_service_row_errors() {
        for line in [
            "10-0-0-1,tcp,443,https,open", // 5 columns
            "10-0-0-1,tcp,not-a-port,https,open,",
            "10-0-0-1,,443,https,open,",
            "10-0-0-1,tcp,443,https,,",
            ",tcp,443,https,open,",
        ] {
            let csv = format!("#services\nasset_id,proto,port,name,state,banner\n{line}\n");
            assert!(
                parse_import_csv(&csv).is_err(),
                "expected an error for services line: {line}"
            );
        }
    }

    #[test]
    fn up_column_accepts_known_states_only() {
        assert_eq!(parse_up_state("up".into()).unwrap(), Some(true));
        assert_eq!(parse_up_state("DOWN".into()).unwrap(), Some(false));
        assert_eq!(parse_up_state("-".into()).unwrap(), None);
        assert_eq!(parse_up_state("".into()).unwrap(), None);
        assert!(parse_up_state("maybe".into()).is_err());
    }

    #[test]
    fn quoted_fields_with_commas_are_preserved() {
        let csv = "10.0.0.3,\"mail,backup\",server,prod,platform,high,\"a,b\"\n";
        let inv = parse_import_csv(csv).expect("parse");
        assert_eq!(inv.assets[0].hostname.as_deref(), Some("mail,backup"));
        assert_eq!(inv.assets[0].tags, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn resolves_ip_shaped_and_plain_asset_ids() {
        assert_eq!(resolve_asset_id("10.0.0.1"), "10-0-0-1");
        assert_eq!(resolve_asset_id("::ffff:10.0.0.1"), "10-0-0-1");
        assert_eq!(
            resolve_asset_id("2001:db8::1"),
            "2001-db8--1",
            "colons become dashes like every asset id"
        );
        assert_eq!(resolve_asset_id("10-0-0-1"), "10-0-0-1", "ids pass through");
        assert_eq!(resolve_asset_id("web-01"), "web-01", "non-IPs pass through");
    }

    fn row(ip: &str) -> ImportedAsset {
        ImportedAsset {
            ip: ip.into(),
            hostname: None,
            device_class: None,
            os_name: None,
            os_version: None,
            environment: None,
            owner: None,
            criticality: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn deduplicate_keeps_first_and_counts_duplicates() {
        let (kept, dup) = deduplicate(vec![
            row("10.0.0.1"),
            row("10.0.0.2"),
            row("10.0.0.1"), // duplicate
            row("10.0.0.1"), // duplicate
        ]);
        assert_eq!(dup, 2);
        let ips: Vec<&str> = kept.iter().map(|r| r.ip.as_str()).collect();
        assert_eq!(ips, vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn deduplicate_preserves_invalid_ips_for_later_error() {
        let (kept, dup) = deduplicate(vec![row("not-an-ip"), row("10.0.0.1")]);
        assert_eq!(dup, 0);
        assert_eq!(kept.len(), 2, "invalid IP must not be silently dropped");
    }

    #[test]
    fn deduplicate_normalizes_ip_forms() {
        // IPv4-mapped IPv6 normalizes to the same IPv4 address.
        let (kept, dup) = deduplicate(vec![row("10.0.0.1"), row("::ffff:10.0.0.1")]);
        assert_eq!(dup, 1);
        assert_eq!(kept.len(), 1);
    }
}
