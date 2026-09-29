//! Third-party integrations.
//!
//! NetBox is a source-of-truth importer (read-only); Prometheus and Zabbix
//! are historical utilization importers (read-only); Ansible and Terraform
//! are automation exporters. All exporters are pure functions over the
//! normalized domain, so they render identically regardless of where the
//! data came from.

pub mod ansible;
pub mod netbox;
pub mod prometheus;
pub mod terraform;
pub mod zabbix;

use std::collections::HashMap;

use crate::domain::Asset;

/// An index of the inventory for monitoring series to resolve against:
/// exact IP first, then hostname (case-insensitive).
pub(crate) struct AssetIndex<'a> {
    by_ip: HashMap<String, &'a Asset>,
    by_hostname: HashMap<String, &'a Asset>,
}

impl<'a> AssetIndex<'a> {
    pub(crate) fn new(assets: &'a [Asset]) -> Self {
        let mut by_ip = HashMap::new();
        let mut by_hostname = HashMap::new();
        for asset in assets {
            by_ip.insert(asset.ip.to_string(), asset);
            if let Some(hostname) = &asset.hostname {
                by_hostname.insert(hostname.to_ascii_lowercase(), asset);
            }
        }
        Self { by_ip, by_hostname }
    }

    /// Resolve a monitoring identifier (host part of a Prometheus `instance`
    /// label, a Zabbix interface IP or host name) to a known asset, or
    /// `None` when it matches nothing. Series are never guessed onto an
    /// asset: a wrong match would silently corrupt an assessment.
    pub(crate) fn resolve(&self, id: &str) -> Option<&'a Asset> {
        id.parse::<std::net::IpAddr>()
            .ok()
            .and_then(|ip| self.by_ip.get(&ip.to_string()).copied())
            .or_else(|| self.by_hostname.get(&id.to_ascii_lowercase()).copied())
    }

    /// How many assets the index can resolve to.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_ip.len()
    }
}
