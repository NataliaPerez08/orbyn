//! Inventory import parsing (shared by the CLI `orbyn import` command).
//!
//! The CSV path parses the `#assets` worksheet of an Orbyn export, accepting
//! both the full 12-column export form and a compact 7-column import form.

use anyhow::{bail, Result};

use crate::parsing::split_csv_line;

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

/// Parse the `#assets` worksheet of an Orbyn CSV export into import rows.
///
/// A CSV without any `#section` header (e.g. a hand-written compact import)
/// is treated as being entirely in the `assets` section.
pub fn parse_import_csv(input: &str) -> Result<Vec<ImportedAsset>> {
    let mut rows = Vec::new();
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
        if section != "assets" {
            continue;
        }
        if line.starts_with("id,ip") {
            continue; // column header
        }
        let fields = split_csv_line(line);
        // Accept both the 12-column export and a compact 7-column import form.
        let (
            ip,
            hostname,
            device_class,
            os_name,
            os_version,
            environment,
            owner,
            criticality,
            tags,
        ) = match fields.len() {
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
        rows.push(ImportedAsset {
            ip,
            hostname,
            device_class,
            os_name,
            os_version,
            environment,
            owner,
            criticality,
            tags,
        });
    }
    Ok(rows)
}

/// Map an empty or placeholder CSV field to `None`.
fn opt(value: String) -> Option<String> {
    if value.is_empty() || value == "-" {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_12_column_export() {
        let csv = "#assets\nid,ip,hostname,device_class,os_name,os_version,environment,owner,criticality,tags,first_seen,last_seen\n\
10-0-0-1,10.0.0.1,web-01,server,Ubuntu 22.04,,prod,platform,high,\"core,api\",2024-01-01T00:00:00+00:00,2024-01-02T00:00:00+00:00\n";
        let rows = parse_import_csv(csv).expect("parse");
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
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
        let rows = parse_import_csv(csv).expect("parse");
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.ip, "10.0.0.2");
        assert_eq!(r.hostname.as_deref(), Some("db-01"));
        assert_eq!(r.criticality.as_deref(), Some("critical"));
        assert_eq!(r.tags, vec!["database".to_string(), "dr".to_string()]);
        assert_eq!(r.os_name, None);
    }

    #[test]
    fn ignores_non_asset_sections_and_headers() {
        let csv = "#interfaces\nasset_id,name\nx,eth0\n\n#assets\nid,ip,hostname,device_class,os_name,os_version,environment,owner,criticality,tags,first_seen,last_seen\n\
10-0-0-1,10.0.0.1,web-01,,,,,,,,,\n";
        let rows = parse_import_csv(csv).expect("parse");
        assert_eq!(rows.len(), 1, "only the #assets section is parsed");
        assert_eq!(rows[0].hostname.as_deref(), Some("web-01"));
        assert_eq!(rows[0].tags, Vec::<String>::new());
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
    fn quoted_fields_with_commas_are_preserved() {
        let csv = "10.0.0.3,\"mail,backup\",server,prod,platform,high,\"a,b\"\n";
        let rows = parse_import_csv(csv).expect("parse");
        assert_eq!(rows[0].hostname.as_deref(), Some("mail,backup"));
        assert_eq!(rows[0].tags, vec!["a".to_string(), "b".to_string()]);
    }
}
