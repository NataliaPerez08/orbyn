//! Ansible inventory exporter (v1.1).
//!
//! Renders the asset inventory as an Ansible inventory in two formats: the
//! classic INI layout (one `[group]` section per grouping key) and the YAML
//! layout (`all.children.<group>.hosts`). Both carry `ansible_host` plus the
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

/// Group assets into named inventory groups, members sorted by host name.
/// Shared by the INI and YAML renderers so both stay in lockstep.
fn groups(assets: &[Asset], group_by: GroupBy) -> BTreeMap<String, Vec<&Asset>> {
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

    for members in groups.values_mut() {
        members.sort_by_key(|a| host_name(a));
    }
    groups
}

/// Render an Ansible INI inventory.
pub fn render_ansible_inventory(assets: &[Asset], group_by: GroupBy) -> String {
    let mut out = String::new();
    for (group, members) in &groups(assets, group_by) {
        out.push_str(&format!("[{}]\n", sanitize_name(group)));
        for asset in members {
            out.push_str(&format!("{} {}\n", host_name(asset), host_vars(asset)));
        }
        out.push('\n');
    }
    out
}

/// Render an Ansible YAML inventory (`all: children: <group>: hosts:`).
pub fn render_ansible_yaml(assets: &[Asset], group_by: GroupBy) -> String {
    let grouped = groups(assets, group_by);
    if grouped.is_empty() {
        return "all:\n  children: {}\n".into();
    }

    let mut out = String::from("all:\n  children:\n");
    for (group, members) in &grouped {
        out.push_str(&format!("    {}:\n      hosts:\n", yaml_key(group)));
        for asset in members {
            out.push_str(&format!("        {}:\n", yaml_key(&host_name(asset))));
            out.push_str(&format!(
                "          ansible_host: {}\n",
                yaml_scalar(&asset.ip.to_string())
            ));
            if let Some(env) = &asset.environment {
                out.push_str(&format!(
                    "          orbyn_environment: {}\n",
                    yaml_scalar(env)
                ));
            }
            if let Some(owner) = &asset.owner {
                out.push_str(&format!("          orbyn_owner: {}\n", yaml_scalar(owner)));
            }
            if let Some(criticality) = asset.criticality {
                out.push_str(&format!(
                    "          orbyn_criticality: {}\n",
                    yaml_scalar(&criticality.to_string())
                ));
            }
            if !asset.tags.is_empty() {
                out.push_str("          orbyn_tags:\n");
                for tag in &asset.tags {
                    out.push_str(&format!("            - {}\n", yaml_scalar(tag)));
                }
            }
        }
    }
    out
}

fn host_name(asset: &Asset) -> String {
    let name = asset
        .hostname
        .clone()
        .unwrap_or_else(|| asset.ip.to_string());
    sanitize_name(&name)
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

/// Group names and host names in inventories must not contain whitespace.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_whitespace() { '-' } else { c })
        .collect()
}

/// A YAML mapping key: sanitized, quoted only when YAML requires it.
fn yaml_key(name: &str) -> String {
    yaml_scalar(&sanitize_name(name))
}

/// Emit a YAML scalar, double-quoting it when plain style would change its
/// meaning (bool/null/number look-alikes, indicator characters, `: `,
/// comments, leading/trailing whitespace, control characters).
fn yaml_scalar(s: &str) -> String {
    if needs_yaml_quotes(s) {
        let escaped = s
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

fn needs_yaml_quotes(s: &str) -> bool {
    if s.is_empty() {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "null" | "~" | "yes" | "no" | "on" | "off"
    ) {
        return true;
    }
    if s.parse::<f64>().is_ok() {
        return true;
    }
    let first = s.chars().next().unwrap();
    if " \t-?:,[]{}#&*!|>'\"%@`".contains(first) {
        return true;
    }
    if s != s.trim() {
        return true;
    }
    s.contains(": ") || s.ends_with(':') || s.contains(" #") || s.chars().any(|c| c.is_control())
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
            sys_descr: None,
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

    #[test]
    fn host_names_sanitize_whitespace() {
        let assets = vec![asset("a", "10.0.0.1", Some("web 01"), None, None, &[])];
        let out = render_ansible_inventory(&assets, GroupBy::DeviceClass);
        assert!(out.contains("web-01 ansible_host=10.0.0.1"));
        assert!(!out.contains("web 01"));
    }

    #[test]
    fn yaml_inventory_nests_groups_under_all_children() {
        let assets = vec![
            asset(
                "a",
                "10.0.0.1",
                Some("web-01"),
                Some("server"),
                Some("prod"),
                &["core", "api"],
            ),
            asset("b", "10.0.0.3", None, None, None, &[]),
        ];
        let out = render_ansible_yaml(&assets, GroupBy::DeviceClass);
        assert!(
            out.contains("all:\n  children:\n    server:\n      hosts:\n"),
            "{out}"
        );
        assert!(out.contains("        web-01:\n"), "{out}");
        assert!(out.contains("          ansible_host: 10.0.0.1\n"), "{out}");
        assert!(out.contains("          orbyn_environment: prod\n"), "{out}");
        assert!(out.contains("          orbyn_criticality: high\n"), "{out}");
        assert!(
            out.contains("          orbyn_tags:\n            - core\n            - api\n"),
            "{out}"
        );
        assert!(
            out.contains("    ungrouped:\n      hosts:\n        10.0.0.3:\n"),
            "{out}"
        );
    }

    #[test]
    fn yaml_inventory_groups_by_environment_and_tags() {
        let assets = vec![
            asset(
                "a",
                "10.0.0.1",
                Some("web-01"),
                None,
                Some("prod"),
                &["core"],
            ),
            asset("b", "10.0.0.2", Some("db-01"), None, Some("staging"), &[]),
        ];
        let out = render_ansible_yaml(&assets, GroupBy::Environment);
        assert!(
            out.contains("    prod:\n") && out.contains("    staging:\n"),
            "{out}"
        );

        let out = render_ansible_yaml(&assets, GroupBy::Tags);
        assert!(out.contains("    core:\n"), "{out}");
        assert!(out.contains("    ungrouped:\n"), "{out}");
    }

    #[test]
    fn yaml_empty_inventory_is_an_empty_children_map() {
        assert_eq!(
            render_ansible_yaml(&[], GroupBy::DeviceClass),
            "all:\n  children: {}\n"
        );
    }

    #[test]
    fn yaml_quotes_values_that_would_change_meaning() {
        let mut a = asset(
            "a",
            "10.0.0.1",
            Some("web-01"),
            None,
            Some("on"),
            &["123", "a: b"],
        );
        a.owner = Some("  padded  ".into());
        let out = render_ansible_yaml(&[a], GroupBy::DeviceClass);
        assert!(out.contains("orbyn_environment: \"on\"\n"), "{out}");
        assert!(out.contains("- \"123\"\n"), "{out}");
        assert!(out.contains("- \"a: b\"\n"), "{out}");
        assert!(out.contains("orbyn_owner: \"  padded  \"\n"), "{out}");
    }

    #[test]
    fn yaml_escapes_values_that_need_quoting() {
        let mut a = asset("a", "10.0.0.1", Some("\"weird"), None, None, &[]);
        a.environment = Some("back\\slash: x".into());
        let out = render_ansible_yaml(&[a], GroupBy::DeviceClass);
        assert!(out.contains("\"\\\"weird\":\n"), "{out}");
        assert!(
            out.contains("orbyn_environment: \"back\\\\slash: x\"\n"),
            "{out}"
        );
    }

    #[test]
    fn yaml_plain_values_stay_unquoted() {
        let mut a = asset("a", "10.0.0.1", Some("web-01"), None, None, &[]);
        a.environment = Some("back\\slash".into());
        a.owner = Some("quote\"inside".into());
        let out = render_ansible_yaml(&[a], GroupBy::DeviceClass);
        assert!(out.contains("orbyn_environment: back\\slash\n"), "{out}");
        assert!(out.contains("orbyn_owner: quote\"inside\n"), "{out}");
    }
}
