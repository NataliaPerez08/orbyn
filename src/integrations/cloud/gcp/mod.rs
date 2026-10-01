//! Google Cloud Compute Engine inventory adapter.
//!
//! The caller supplies an OAuth bearer token.  This adapter only issues GETs
//! through [`CurlClient`] and never puts the token in process arguments.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use chrono::Utc;
use serde::Deserialize;

use crate::domain::{Capacity, Filesystem, Interface};
use crate::integrations::cloud::{
    cloud_asset, parse_ip_cidr, CloudAsset, CloudInventory, CurlClient,
};
use crate::integrations::netbox::url_origin;

const MAX_PAGES: usize = 200;
const MAX_INSTANCES: usize = 100_000;
const MAX_DISKS: usize = 100_000;

/// A read-only Compute Engine client backed by the `curl` binary.
pub struct GcpClient {
    http: CurlClient,
    token: String,
    project: String,
    endpoint: String,
}

impl GcpClient {
    /// Create a client for `project`. `endpoint_override` replaces the Compute
    /// API base URL, which is useful for private endpoints and tests.
    pub fn new(
        token: String,
        project: &str,
        endpoint_override: Option<&str>,
        insecure: bool,
    ) -> Result<Self> {
        if token.trim().is_empty() {
            bail!("GCP bearer token cannot be empty");
        }
        if project.trim().is_empty() || project.contains('/') || project.contains('?') {
            bail!("invalid GCP project '{project}'");
        }
        let endpoint = endpoint_override
            .map(|value| value.trim_end_matches('/').to_string())
            .unwrap_or_else(|| "https://compute.googleapis.com/compute/v1".to_string());
        if url_origin(&endpoint).is_none() {
            return Err(anyhow!(
                "invalid GCP endpoint '{endpoint}': expected an absolute http(s) URL without embedded credentials"
            ));
        }
        Ok(Self {
            http: CurlClient::new().insecure(insecure),
            token,
            project: project.to_string(),
            endpoint,
        })
    }

    /// Fetch Compute Engine instances and attached persistent disks.
    pub async fn fetch_inventory(&self) -> Result<CloudInventory> {
        let observed_at = Utc::now();
        let mut inventory = CloudInventory::new("gcp", Some(self.project.clone()), None);
        let headers = vec![format!("Authorization: Bearer {}", self.token)];
        let mut instances = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut url = format!(
                "{}/projects/{}/aggregated/instances",
                self.endpoint, self.project
            );
            if let Some(page_token) = &token {
                url.push_str("?pageToken=");
                url.push_str(page_token);
            }
            let page: InstancesPage = serde_json::from_str(&self.http.get(&url, &headers).await?)
                .context("parsing GCP Compute Engine instances")?;
            for scope in page.items.into_values() {
                instances.extend(scope.instances);
            }
            token = clean_token(page.next_page_token);
            if token.is_none() {
                break;
            }
        }
        if token.is_some() {
            bail!("GCP instance listing exceeded the {MAX_PAGES} page limit");
        }
        if instances.len() > MAX_INSTANCES {
            bail!("GCP instance listing exceeded the {MAX_INSTANCES} instance limit");
        }

        let mut assets = HashMap::new();
        let mut machine_types = HashMap::new();
        for instance in &instances {
            let Some(ip) = instance_ip(instance) else {
                inventory.skipped.push(format!(
                    "instance {} has no IP address",
                    instance.name.as_deref().unwrap_or("(unknown)")
                ));
                continue;
            };
            let mut asset = cloud_asset(ip, instance.name.clone(), "virtual-machine", observed_at);
            asset.os_name = instance.os_name();
            let asset_id = asset.id.clone();
            let name = instance.name.as_deref().unwrap_or("(unknown)");
            assets.insert(instance.self_link.clone(), asset_id.clone());
            let mut tags = vec![format!("gcp-instance:{name}")];
            if let Some(zone) = instance.zone_name() {
                tags.push(format!("gcp-zone:{zone}"));
            }
            if let Some(status) = &instance.status {
                tags.push(format!("gcp-state:{status}"));
            }
            tags.extend(labels(&instance.labels));
            inventory.assets.push(CloudAsset {
                asset,
                environment: None,
                owner: None,
                criticality: None,
                tags,
            });
            for nic in &instance.network_interfaces {
                let ip = nic.network_ip.as_deref().and_then(parse_ip_cidr);
                let mut interface = Interface::new(
                    &asset_id,
                    nic.name.as_deref(),
                    nic.mac_address.as_deref(),
                    ip,
                );
                interface.is_up = instance.status.as_deref().map(|s| s == "RUNNING");
                inventory.interfaces.push(interface);
                for access in &nic.access_configs {
                    if let Some(ip) = access.nat_ip.as_deref().and_then(parse_ip_cidr) {
                        inventory.interfaces.push(Interface::new(
                            &asset_id,
                            nic.name.as_deref(),
                            nic.mac_address.as_deref(),
                            Some(ip),
                        ));
                    }
                }
            }
            if let (Some(zone), Some(machine_type)) =
                (instance.zone_name(), instance.machine_type_name())
            {
                let key = format!("{zone}/{machine_type}");
                if !machine_types.contains_key(&key) {
                    let url = format!(
                        "{}/projects/{}/zones/{}/machineTypes/{}",
                        self.endpoint, self.project, zone, machine_type
                    );
                    if let Some(body) = self.http.try_get(&url, &headers).await {
                        if let Ok(machine) = serde_json::from_str::<MachineType>(&body) {
                            machine_types.insert(key.clone(), machine);
                        }
                    }
                }
                if let Some(machine) = machine_types.get(&key) {
                    inventory.capacities.push(Capacity {
                        asset_id,
                        cpu_model: None,
                        cpu_sockets: None,
                        cpu_cores: machine.guest_cpus,
                        cpu_threads: None,
                        ram_total_mb: machine.memory_mb,
                        hypervisor: Some("gce".to_string()),
                        collected_at: observed_at,
                    });
                }
            }
        }

        let mut token: Option<String> = None;
        let mut disks = Vec::new();
        for _ in 0..MAX_PAGES {
            let mut url = format!(
                "{}/projects/{}/aggregated/disks",
                self.endpoint, self.project
            );
            if let Some(page_token) = &token {
                url.push_str("?pageToken=");
                url.push_str(page_token);
            }
            let page: DisksPage = serde_json::from_str(&self.http.get(&url, &headers).await?)
                .context("parsing GCP Compute Engine disks")?;
            for scope in page.items.into_values() {
                disks.extend(scope.disks);
            }
            token = clean_token(page.next_page_token);
            if token.is_none() {
                break;
            }
        }
        if token.is_some() {
            bail!("GCP disk listing exceeded the {MAX_PAGES} page limit");
        }
        if disks.len() > MAX_DISKS {
            bail!("GCP disk listing exceeded the {MAX_DISKS} disk limit");
        }
        for disk in disks {
            let disk_name = disk.name.as_deref().unwrap_or("(unknown)");
            let Some(instance_link) = disk.users.first() else {
                inventory
                    .skipped
                    .push(format!("disk {disk_name} is not attached to an instance"));
                continue;
            };
            let Some(asset_id) = assets.get(instance_link) else {
                inventory.skipped.push(format!(
                    "disk {disk_name} is attached to an unknown instance"
                ));
                continue;
            };
            inventory.filesystems.push(Filesystem {
                asset_id: asset_id.clone(),
                device: Some(disk.self_link.clone()),
                mount: disk_name.to_string(),
                fs_type: Some("persistent-disk".to_string()),
                size_kb: disk.size_gb.unwrap_or(0) * 1024 * 1024,
                used_kb: None,
                available_kb: None,
                used_pct: None,
            });
        }
        Ok(inventory)
    }
}

#[derive(Debug, Deserialize, Default)]
struct InstancesPage {
    #[serde(default)]
    items: HashMap<String, InstanceScope>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct InstanceScope {
    #[serde(default)]
    instances: Vec<Instance>,
}

#[derive(Debug, Deserialize, Default)]
struct DisksPage {
    #[serde(default)]
    items: HashMap<String, DiskScope>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct DiskScope {
    #[serde(default)]
    disks: Vec<Disk>,
}

#[derive(Debug, Deserialize, Default)]
struct Instance {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "selfLink", default)]
    self_link: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(rename = "machineType", default)]
    machine_type: Option<String>,
    #[serde(default)]
    zone: Option<String>,
    #[serde(rename = "networkInterfaces", default)]
    network_interfaces: Vec<NetworkInterface>,
    #[serde(default)]
    labels: HashMap<String, String>,
    #[serde(default)]
    disks: Vec<AttachedDisk>,
}

impl Instance {
    fn zone_name(&self) -> Option<String> {
        self.zone
            .as_deref()
            .and_then(|v| v.rsplit('/').next())
            .map(str::to_string)
    }

    fn machine_type_name(&self) -> Option<String> {
        self.machine_type
            .as_deref()
            .and_then(|v| v.rsplit('/').next())
            .map(str::to_string)
    }

    fn os_name(&self) -> Option<String> {
        self.disks
            .iter()
            .flat_map(|d| d.licenses.iter())
            .find_map(|license| {
                let value = license.rsplit('/').next()?;
                if value.contains("windows") {
                    Some("Windows".to_string())
                } else if value.contains("ubuntu") {
                    Some("Ubuntu".to_string())
                } else {
                    None
                }
            })
    }
}

#[derive(Debug, Deserialize, Default)]
struct NetworkInterface {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "networkIP", default)]
    network_ip: Option<String>,
    #[serde(rename = "macAddress", default)]
    mac_address: Option<String>,
    #[serde(rename = "accessConfigs", default)]
    access_configs: Vec<AccessConfig>,
}

#[derive(Debug, Deserialize, Default)]
struct AccessConfig {
    #[serde(rename = "natIP", default)]
    nat_ip: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct AttachedDisk {
    #[serde(default)]
    licenses: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct Disk {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "selfLink", default)]
    self_link: String,
    #[serde(rename = "sizeGb", default)]
    size_gb: Option<u64>,
    #[serde(default)]
    users: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct MachineType {
    #[serde(rename = "guestCpus", default)]
    guest_cpus: Option<u32>,
    #[serde(rename = "memoryMb", default)]
    memory_mb: Option<u64>,
}

fn instance_ip(instance: &Instance) -> Option<std::net::IpAddr> {
    instance.network_interfaces.iter().find_map(|nic| {
        nic.network_ip
            .as_deref()
            .and_then(parse_ip_cidr)
            .or_else(|| {
                nic.access_configs
                    .iter()
                    .find_map(|c| c.nat_ip.as_deref().and_then(parse_ip_cidr))
            })
    })
}

fn labels(labels: &HashMap<String, String>) -> Vec<String> {
    labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect()
}

fn clean_token(token: Option<String>) -> Option<String> {
    token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_aggregated_instances_and_helpers() {
        let json = r#"{"nextPageToken":"next","items":{"zones/z":{"instances":[{"name":"web","selfLink":"instance/web","zone":"zones/z","machineType":"machineTypes/e2","networkInterfaces":[{"name":"nic0","networkIP":"10.0.0.5","macAddress":"AA:BB:CC:DD:EE:FF","accessConfigs":[{"natIP":"203.0.113.5"}]}],"labels":{"env":"prod"}}]}}}"#;
        let page: InstancesPage = serde_json::from_str(json).unwrap();
        let instance = &page.items["zones/z"].instances[0];
        assert_eq!(page.next_page_token.as_deref(), Some("next"));
        assert_eq!(instance_ip(instance), Some("10.0.0.5".parse().unwrap()));
        assert_eq!(instance.zone_name().as_deref(), Some("z"));
        assert_eq!(instance.machine_type_name().as_deref(), Some("e2"));
        assert_eq!(labels(&instance.labels), vec!["env=prod"]);
    }

    #[test]
    fn validates_token_project_and_endpoint() {
        assert!(GcpClient::new("token".into(), "project", None, false).is_ok());
        assert!(GcpClient::new(String::new(), "project", None, false).is_err());
        assert!(GcpClient::new("token".into(), "project/name", None, false).is_err());
        assert!(GcpClient::new(
            "token".into(),
            "project",
            Some("http://127.0.0.1:9000"),
            false
        )
        .is_ok());
        assert!(GcpClient::new(
            "token".into(),
            "project",
            Some("https://user@evil.example"),
            false
        )
        .is_err());
    }
}
