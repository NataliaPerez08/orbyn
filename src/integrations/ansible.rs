//! Ansible inventory exporter (v1.1).
//!
//! Renders the asset inventory as an Ansible INI inventory: one `[group]`
//! section per grouping key, each host carrying `ansible_host` plus the
//! Orbyn annotations as host variables.

use std::collections::BTreeMap;

use crate::domain::Asset;

/// How assets are grouped into Ansible inventory groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum GroupBy {
    /// Group by device class (fallback `ungrouped`).
    DeviceClass,
    /// Group by environment (fallback `ungrouped`).
    Environment,
    /// Group by tag; an asset belongs to every group matching one of its tags.
    Tags,
}

/// Render an Ansible INI inventory.
pub fn render_ansible_inventory(assets: &[Asset], group_by: GroupBy) -> String {
    let mut groups: BTreeMap<String, Vec<&Asset>> = BTreeMap::new();

    for asset in assets {
        match group_by {
            GroupBy::DeviceClass => {
                groups
                    .entry(
                        asset
                            .device_class
                            .clone()
                            .unwrap_or_else(|| "ungrouped".into()),
                    )
                    .or_default()
                    .push(asset);
            }
            GroupBy::Environment => {
                groups
                    .entry(
                        asset
                            .environment
                            .clone()
                            .unwrap_or_else(|| "ungrouped".into()),
                    )
                    .or_default()
                    .push(asset);
            }
            GroupBy::Tags => {
                if asset.tags.is_empty() {
                    groups.entry("ungrouped".into()).or_default().push(asset);
                } else {
                    for tag in &asset.tags {
                        groups.entry(tag.clone()).or_default().push(asset);
                    }
                }
            }
        }
    }

    let mut out = String::new();
    for (group, members) in &groups {
        let mut members = members.to_vec();
        members.sort_by_key(|a| host_name(a));
        out.push_str(&format!("[{}]\n", sanitize_name(group)));
        for asset in members {
            out.push_str(&format!("{} {}\n", host_name(asset), host_vars(asset)));
        }
        out.push('\n');
    }
    out
}

fn host_name(asset: &Asset) -> String {
    asset
        .hostname
        .clone()
        .unwrap_or_else(|| asset.ip.to_string())
}

/// INI `key=value` host variables derived from the normalized asset.
fn host_vars(asset: &Asset) -> String {
    let mut vars = vec![format!("ansible_host={}", asset.ip)];
    if let Some(env) = &asset.environment {
        vars.push(format!("orbyn_environment={env}"));
    }
    if let Some(owner) = &asset.owner {
        vars.push(format!("orbyn_owner={owner}"));
    }
    if let Some(criticality) = asset.criticality {
        vars.push(format!("orbyn_criticality={criticality}"));
    }
    if !asset.tags.is_empty() {
        vars.push(format!("orbyn_tags={}", asset.tags.join(",")));
    }
    vars.join(" ")
}

/// Group names in INI inventories must not contain whitespace.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_whitespace() { '-' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Criticality;
    use chrono::Utc;

    fn asset(
        id: &str,
        ip: &str,
        hostname: Option<&str>,
        device_class: Option<&str>,
        environment: Option<&str>,
        tags: &[&str],
    ) -> Asset {
        Asset {
            id: id.into(),
            ip: ip.parse().unwrap(),
            hostname: hostname.map(str::to_string),
            device_class: device_class.map(str::to_string),
            os_name: None,
            os_version: None,
            environment: environment.map(str::to_string),
            owner: None,
            criticality: Some(Criticality::High),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn groups_by_device_class() {
        let assets = vec![
            asset(
                "a",
                "10.0.0.1",
                Some("web-01"),
                Some("server"),
                Some("prod"),
                &["core"],
            ),
            asset(
                "b",
                "10.0.0.2",
                Some("db-01"),
                Some("server"),
                Some("prod"),
                &[],
            ),
            asset("c", "10.0.0.3", None, None, None, &[]),
        ];
        let out = render_ansible_inventory(&assets, GroupBy::DeviceClass);
        assert!(out.contains("[server]"));
        assert!(out.contains("[ungrouped]"));
        assert!(out.contains("web-01 ansible_host=10.0.0.1"));
        assert!(out.contains("10.0.0.3 ansible_host=10.0.0.3"));
    }

    #[test]
    fn groups_by_environment() {
        let assets = vec![
            asset("a", "10.0.0.1", Some("web-01"), None, Some("prod"), &[]),
            asset("b", "10.0.0.2", Some("db-01"), None, Some("staging"), &[]),
        ];
        let out = render_ansible_inventory(&assets, GroupBy::Environment);
        assert!(out.contains("[prod]"));
        assert!(out.contains("[staging]"));
    }

    #[test]
    fn groups_by_tags_places_asset_in_each_tag_group() {
        let assets = vec![asset(
            "a",
            "10.0.0.1",
            Some("web-01"),
            None,
            None,
            &["core", "api"],
        )];
        let out = render_ansible_inventory(&assets, GroupBy::Tags);
        assert!(out.contains("[core]"));
        assert!(out.contains("[api]"));
        assert_eq!(out.matches("web-01").count(), 2, "one line per tag group");
    }

    #[test]
    fn host_vars_include_annotations() {
        let assets = vec![asset(
            "a",
            "10.0.0.1",
            Some("web-01"),
            None,
            Some("prod"),
            &["core", "api"],
        )];
        let out = render_ansible_inventory(&assets, GroupBy::DeviceClass);
        assert!(out.contains("orbyn_environment=prod"));
        assert!(out.contains("orbyn_criticality=high"));
        assert!(out.contains("orbyn_tags=core,api"));
    }

    #[test]
    fn empty_inventory() {
        assert_eq!(render_ansible_inventory(&[], GroupBy::DeviceClass), "");
    }

    #[test]
    fn group_names_sanitize_whitespace() {
        let assets = vec![asset(
            "a",
            "10.0.0.1",
            Some("web-01"),
            Some("network device"),
            None,
            &[],
        )];
        let out = render_ansible_inventory(&assets, GroupBy::DeviceClass);
        assert!(out.contains("[network-device]"));
    }
}
