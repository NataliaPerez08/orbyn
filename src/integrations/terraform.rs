//! Terraform-friendly exporter (v1.1).
//!
//! Renders the inventory as an HCL `locals` map that any Terraform module can
//! consume (`local.orbyn_inventory["host"].ip`), without assuming a cloud
//! provider or SKU. Machine-editable and provider-agnostic.
//!
//! Optionally scaffolds `import` blocks (Terraform >= 1.5) addressed at a
//! caller-chosen resource type; the provider resource id is not part of the
//! discovered inventory, so it is prefilled with the asset IP as a visible
//! placeholder.

use anyhow::{bail, Result};

use crate::domain::Asset;

/// Render an HCL `locals { orbyn_inventory = { ... } }` block with every
/// supported metadata field.
pub fn render_terraform(assets: &[Asset]) -> String {
    let mut out = String::from("locals {\n  orbyn_inventory = {\n");
    let mut sorted: Vec<&Asset> = assets.iter().collect();
    sorted.sort_by_key(|a| host_name(a));

    for asset in sorted {
        out.push_str(&format!("    \"{}\" = {{\n", hcl_string(&host_name(asset))));
        out.push_str(&field("ip", &format!("\"{}\"", asset.ip)));
        if let Some(hostname) = &asset.hostname {
            out.push_str(&field("hostname", &format!("\"{}\"", hcl_string(hostname))));
        }
        if let Some(class) = &asset.device_class {
            out.push_str(&field(
                "device_class",
                &format!("\"{}\"", hcl_string(class)),
            ));
        }
        if let Some(os) = &asset.os_name {
            out.push_str(&field("os_name", &format!("\"{}\"", hcl_string(os))));
        }
        if let Some(version) = &asset.os_version {
            out.push_str(&field(
                "os_version",
                &format!("\"{}\"", hcl_string(version)),
            ));
        }
        if let Some(env) = &asset.environment {
            out.push_str(&field("environment", &format!("\"{}\"", hcl_string(env))));
        }
        if let Some(owner) = &asset.owner {
            out.push_str(&field("owner", &format!("\"{}\"", hcl_string(owner))));
        }
        if let Some(criticality) = asset.criticality {
            out.push_str(&field("criticality", &format!("\"{criticality}\"")));
        }
        if !asset.tags.is_empty() {
            let tags = asset
                .tags
                .iter()
                .map(|t| format!("\"{}\"", hcl_string(t)))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&field("tags", &format!("[{tags}]")));
        }
        out.push_str(&field(
            "first_seen",
            &format!("\"{}\"", asset.first_seen.to_rfc3339()),
        ));
        out.push_str(&field(
            "last_seen",
            &format!("\"{}\"", asset.last_seen.to_rfc3339()),
        ));
        out.push_str("    }\n");
    }
    out.push_str("  }\n}\n");
    out
}

/// Render one `import` block per asset, addressed
/// `<resource_type>.<sanitized host>`.
///
/// The `id` argument is prefilled with the asset IP and a TODO comment: the
/// cloud provider's resource identifier is not something discovery can know,
/// so the blocks are scaffolding to edit, not a ready-to-apply plan.
pub fn render_import_blocks(assets: &[Asset], resource_type: &str) -> Result<String> {
    validate_resource_type(resource_type)?;

    let mut sorted: Vec<&Asset> = assets.iter().collect();
    sorted.sort_by_key(|a| host_name(a));

    let mut out = String::new();
    for asset in sorted {
        out.push_str(&format!(
            "import {{\n  to = {}.{}\n  id = \"{}\" # TODO: replace with the provider resource id\n}}\n\n",
            resource_type,
            hcl_identifier(&host_name(asset)),
            asset.ip
        ));
    }
    Ok(out)
}

/// Terraform resource types are HCL identifiers, e.g. `aws_instance`.
fn validate_resource_type(resource_type: &str) -> Result<()> {
    let valid = !resource_type.is_empty()
        && resource_type
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && resource_type
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(())
    } else {
        bail!(
            "invalid Terraform resource type '{resource_type}': \
             expected an identifier like aws_instance"
        )
    }
}

/// Sanitize a host name into an HCL resource identifier.
fn hcl_identifier(name: &str) -> String {
    let mut id: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if id.is_empty() || id.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        id.insert(0, '_');
    }
    id
}

/// One `name = value` attribute line, names padded for aligned output.
fn field(name: &str, value: &str) -> String {
    format!("      {name:<12} = {value}\n")
}

fn host_name(asset: &Asset) -> String {
    asset
        .hostname
        .clone()
        .unwrap_or_else(|| asset.ip.to_string())
}

/// Escape a string for inclusion in an HCL double-quoted literal.
fn hcl_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Criticality;
    use chrono::Utc;

    fn asset(id: &str, ip: &str, hostname: Option<&str>, tags: &[&str]) -> Asset {
        Asset {
            id: id.into(),
            ip: ip.parse().unwrap(),
            hostname: hostname.map(str::to_string),
            device_class: Some("server".into()),
            os_name: None,
            os_version: None,
            sys_descr: None,
            environment: Some("prod".into()),
            owner: Some("platform".into()),
            criticality: Some(Criticality::High),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn renders_hcl_locals_map() {
        let assets = vec![asset("a", "10.0.0.1", Some("web-01"), &["core", "api"])];
        let out = render_terraform(&assets);
        assert!(out.contains("locals {"));
        assert!(out.contains("orbyn_inventory = {"));
        assert!(out.contains("\"web-01\" = {"));
        assert!(out.contains("ip           = \"10.0.0.1\""));
        assert!(out.contains("device_class = \"server\""));
        assert!(out.contains("environment  = \"prod\""));
        assert!(out.contains("owner        = \"platform\""));
        assert!(out.contains("criticality  = \"high\""));
        assert!(out.contains("tags         = [\"core\", \"api\"]"));
    }

    #[test]
    fn renders_os_and_sighting_metadata() {
        let mut a = asset("a", "10.0.0.1", Some("web-01"), &[]);
        a.os_name = Some("Ubuntu 22.04".into());
        a.os_version = Some("5.15.0".into());
        a.first_seen = "2026-01-02T03:04:05Z".parse().unwrap();
        a.last_seen = "2026-09-28T10:00:00Z".parse().unwrap();
        let out = render_terraform(&[a]);
        assert!(out.contains("os_name      = \"Ubuntu 22.04\""), "{out}");
        assert!(out.contains("os_version   = \"5.15.0\""), "{out}");
        assert!(
            out.contains("first_seen   = \"2026-01-02T03:04:05+00:00\""),
            "{out}"
        );
        assert!(
            out.contains("last_seen    = \"2026-09-28T10:00:00+00:00\""),
            "{out}"
        );
    }

    #[test]
    fn import_blocks_address_a_resource_type_per_host() {
        let assets = vec![
            asset("a", "10.0.0.1", Some("web-01"), &[]),
            asset("b", "10.0.0.9", None, &[]),
        ];
        let out = render_import_blocks(&assets, "aws_instance").expect("render import blocks");
        assert!(
            out.contains("import {\n  to = aws_instance.web-01\n  id = \"10.0.0.1\""),
            "{out}"
        );
        assert!(
            out.contains("to = aws_instance._10_0_0_9\n"),
            "IP-keyed hosts get a valid identifier: {out}"
        );
        assert!(out.contains("# TODO: replace with the provider resource id"));
    }

    #[test]
    fn import_blocks_reject_invalid_resource_types() {
        let assets = vec![asset("a", "10.0.0.1", Some("web-01"), &[])];
        for bad in ["", "1aws", "aws instance", "aws_instance\"", "a.b"] {
            assert!(
                render_import_blocks(&assets, bad).is_err(),
                "resource type {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn import_blocks_on_empty_inventory_is_empty() {
        let out = render_import_blocks(&[], "aws_instance").expect("render import blocks");
        assert!(out.is_empty());
    }

    #[test]
    fn escapes_hcl_special_characters() {
        let assets = vec![Asset {
            hostname: Some("weird\"name\\x".into()),
            ..asset("a", "10.0.0.1", None, &[])
        }];
        let out = render_terraform(&assets);
        assert!(
            out.contains("weird\\\"name\\\\x"),
            "hostname escaped: {out}"
        );
    }

    #[test]
    fn empty_inventory_still_valid_hcl() {
        let out = render_terraform(&[]);
        assert!(out.contains("orbyn_inventory = {"));
        assert!(out.ends_with("  }\n}\n"));
    }

    #[test]
    fn uses_ip_as_key_when_no_hostname() {
        let assets = vec![asset("a", "10.0.0.9", None, &[])];
        let out = render_terraform(&assets);
        assert!(out.contains("\"10.0.0.9\" = {"));
    }
}
