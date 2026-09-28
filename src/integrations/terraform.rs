//! Terraform-friendly exporter (v1.1).
//!
//! Renders the inventory as an HCL `locals` map that any Terraform module can
//! consume (`local.orbyn_inventory["host"].ip`), without assuming a cloud
//! provider or SKU. Machine-editable and provider-agnostic.

use crate::domain::Asset;

/// Render an HCL `locals { orbyn_inventory = { ... } }` block.
pub fn render_terraform(assets: &[Asset]) -> String {
    let mut out = String::from("locals {\n  orbyn_inventory = {\n");
    let mut sorted: Vec<&Asset> = assets.iter().collect();
    sorted.sort_by_key(|a| host_name(a));

    for asset in sorted {
        out.push_str(&format!("    \"{}\" = {{\n", hcl_string(&host_name(asset))));
        out.push_str(&format!("      ip           = \"{}\"\n", asset.ip));
        if let Some(hostname) = &asset.hostname {
            out.push_str(&format!(
                "      hostname     = \"{}\"\n",
                hcl_string(hostname)
            ));
        }
        if let Some(class) = &asset.device_class {
            out.push_str(&format!("      device_class = \"{}\"\n", hcl_string(class)));
        }
        if let Some(env) = &asset.environment {
            out.push_str(&format!("      environment  = \"{}\"\n", hcl_string(env)));
        }
        if let Some(owner) = &asset.owner {
            out.push_str(&format!("      owner        = \"{}\"\n", hcl_string(owner)));
        }
        if let Some(criticality) = asset.criticality {
            out.push_str(&format!("      criticality  = \"{}\"\n", criticality));
        }
        if !asset.tags.is_empty() {
            let tags = asset
                .tags
                .iter()
                .map(|t| format!("\"{}\"", hcl_string(t)))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("      tags         = [{tags}]\n"));
        }
        out.push_str("    }\n");
    }
    out.push_str("  }\n}\n");
    out
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
