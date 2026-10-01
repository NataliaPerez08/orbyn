//! Read-only Azure Resource Manager inventory adapter.

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::domain::{Capacity, Filesystem, Interface};
use crate::integrations::cloud::{
    cloud_asset, network_asset_ip, parse_ip_cidr, CloudAsset, CloudInventory, CurlClient,
};
use crate::integrations::netbox::url_origin;

const API_VERSION: &str = "2023-09-01";
const NETWORK_API_VERSION: &str = "2023-11-01";
const MAX_PAGES: usize = 200;

/// A bearer token supplied by the caller. It is streamed to curl via headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureCredentials {
    pub bearer_token: String,
}

/// Read-only Azure Resource Manager client.
pub struct AzureClient {
    http: CurlClient,
    token: String,
    subscription_id: String,
    endpoint: String,
}

impl AzureClient {
    pub fn new(
        credentials: AzureCredentials,
        subscription_id: &str,
        endpoint_override: Option<&str>,
        insecure: bool,
    ) -> Result<Self> {
        if credentials.bearer_token.trim().is_empty() {
            bail!("Azure bearer token must not be empty");
        }
        if subscription_id.trim().is_empty() || subscription_id.contains('/') {
            bail!("invalid Azure subscription id");
        }
        let endpoint = endpoint_override
            .unwrap_or("https://management.azure.com")
            .trim_end_matches('/')
            .to_string();
        if url_origin(&endpoint).is_none() {
            return Err(anyhow!("invalid Azure endpoint '{endpoint}'"));
        }
        Ok(Self {
            http: CurlClient::new().insecure(insecure),
            token: credentials.bearer_token,
            subscription_id: subscription_id.to_string(),
            endpoint,
        })
    }

    pub async fn fetch_inventory(&self) -> Result<CloudInventory> {
        let observed_at = Utc::now();
        let mut inventory = CloudInventory::new("azure", Some(self.subscription_id.clone()), None);
        let sub = &self.subscription_id;
        let vms: Vec<AzureVm> = self
            .list(&format!("{}/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines?api-version={API_VERSION}", self.endpoint))
            .await?;
        let nics: Vec<AzureNic> = self
            .list(&format!("{}/subscriptions/{sub}/providers/Microsoft.Network/networkInterfaces?api-version={NETWORK_API_VERSION}", self.endpoint))
            .await?;
        let disks: Vec<AzureDisk> = self
            .list(&format!("{}/subscriptions/{sub}/providers/Microsoft.Compute/disks?api-version={API_VERSION}", self.endpoint))
            .await?;
        let vnets: Vec<AzureVnet> = self
            .list(&format!("{}/subscriptions/{sub}/providers/Microsoft.Network/virtualNetworks?api-version={NETWORK_API_VERSION}", self.endpoint))
            .await?;

        let nic_by_id = nics
            .into_iter()
            .filter_map(|n| n.id.clone().map(|id| (key(Some(&id)), n)))
            .collect::<HashMap<_, _>>();
        let mut vm_assets = HashMap::new();
        let mut sizes = HashMap::<String, Vec<AzureSize>>::new();
        for vm in &vms {
            if let Some(location) = vm.location.as_deref() {
                if !sizes.contains_key(location) {
                    let url = format!("{}/subscriptions/{sub}/providers/Microsoft.Compute/locations/{location}/vmSizes?api-version={API_VERSION}", self.endpoint);
                    if let Ok(value) = self.list(&url).await {
                        sizes.insert(location.to_string(), value);
                    }
                }
            }
            self.import_vm(vm, &nic_by_id, observed_at, &mut vm_assets, &mut inventory);
            if let (Some(asset_id), Some(location), Some(name)) = (
                vm_assets.get(&key(vm.id.as_deref())),
                vm.location.as_deref(),
                vm.properties.hardware_profile.vm_size.as_deref(),
            ) {
                if let Some(size) = sizes
                    .get(location)
                    .and_then(|items| items.iter().find(|s| s.name.as_deref() == Some(name)))
                {
                    inventory.capacities.push(Capacity {
                        asset_id: asset_id.clone(),
                        cpu_model: None,
                        cpu_sockets: None,
                        cpu_cores: size.number_of_cores,
                        cpu_threads: None,
                        ram_total_mb: size.memory_in_mb,
                        hypervisor: Some("azure".into()),
                        collected_at: observed_at,
                    });
                }
            }
        }
        self.import_disks(&disks, &vm_assets, &mut inventory);
        self.import_vnets(&vnets, observed_at, &mut inventory);
        Ok(inventory)
    }

    async fn list<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<Vec<T>> {
        let mut url = url.to_string();
        let mut values = Vec::new();
        for _ in 0..MAX_PAGES {
            let body = self
                .http
                .get(&url, &[format!("Authorization: Bearer {}", self.token)])
                .await?;
            let page: ListDoc<T> =
                serde_json::from_str(&body).context("parsing Azure ARM list response")?;
            values.extend(page.value);
            let Some(next) = page.next_link.filter(|v| !v.trim().is_empty()) else {
                return Ok(values);
            };
            url = next;
        }
        bail!("Azure ARM listing exceeded the {MAX_PAGES} page limit")
    }

    fn import_vm(
        &self,
        vm: &AzureVm,
        nics: &HashMap<String, AzureNic>,
        observed_at: DateTime<Utc>,
        vm_assets: &mut HashMap<String, String>,
        inventory: &mut CloudInventory,
    ) {
        let id = vm.id.as_deref().unwrap_or("(unknown)");
        let ip = vm
            .properties
            .network_profile
            .network_interfaces
            .iter()
            .find_map(|r| {
                nics.get(&key(r.id.as_deref()))
                    .and_then(AzureNic::primary_ip)
            });
        let Some(ip) = ip else {
            inventory
                .skipped
                .push(format!("VM {id} has no private IP address"));
            return;
        };
        let mut asset = cloud_asset(ip, vm.name.clone(), "virtual-machine", observed_at);
        asset.os_name = vm.properties.storage_profile.os_disk.os_type.clone();
        let asset_id = asset.id.clone();
        vm_assets.insert(key(vm.id.as_deref()), asset_id.clone());
        let mut tags = vec![format!("azure-vm:{id}")];
        if let Some(size) = &vm.properties.hardware_profile.vm_size {
            tags.push(format!("azure-size:{size}"));
        }
        if let Some(location) = &vm.location {
            tags.push(format!("azure-location:{location}"));
        }
        tags.extend(tag_entries(&vm.tags));
        inventory.assets.push(CloudAsset {
            asset,
            environment: None,
            owner: None,
            criticality: None,
            tags,
        });
        for reference in &vm.properties.network_profile.network_interfaces {
            if let Some(nic) = nics.get(&key(reference.id.as_deref())) {
                for config in &nic.properties.ip_configurations {
                    if let Some(ip) = config.private_ip_address.as_deref().and_then(parse_ip_cidr) {
                        let mut interface = Interface::new(
                            &asset_id,
                            config.name.as_deref().or(nic.name.as_deref()),
                            nic.properties.mac_address.as_deref(),
                            Some(ip),
                        );
                        interface.is_up = Some(true);
                        inventory.interfaces.push(interface);
                    }
                }
            }
        }
    }

    fn import_disks(
        &self,
        disks: &[AzureDisk],
        vm_assets: &HashMap<String, String>,
        inventory: &mut CloudInventory,
    ) {
        for disk in disks {
            let id = disk.id.as_deref().unwrap_or("(unknown)");
            let Some(vm_id) = disk.managed_by.as_deref().map(|v| key(Some(v))) else {
                inventory
                    .skipped
                    .push(format!("disk {id} is not attached to an imported VM"));
                continue;
            };
            let Some(asset_id) = vm_assets.get(&vm_id) else {
                inventory
                    .skipped
                    .push(format!("disk {id} is attached to an unknown VM"));
                continue;
            };
            inventory.filesystems.push(Filesystem {
                asset_id: asset_id.clone(),
                device: Some(id.to_string()),
                mount: if disk.properties.os_type.as_deref() == Some("Windows") {
                    "C:".into()
                } else {
                    "azure-disk".into()
                },
                fs_type: disk.sku.name.clone(),
                size_kb: disk.properties.disk_size_gb.unwrap_or(0) * 1024 * 1024,
                used_kb: None,
                available_kb: None,
                used_pct: None,
            });
        }
    }

    fn import_vnets(
        &self,
        vnets: &[AzureVnet],
        observed_at: DateTime<Utc>,
        inventory: &mut CloudInventory,
    ) {
        let mut seen: HashSet<String> = inventory
            .assets
            .iter()
            .map(|a| a.asset.id.clone())
            .collect();
        for vnet in vnets {
            let id = vnet.id.as_deref().unwrap_or("(unknown)");
            let Some(cidr) = vnet.properties.address_space.address_prefixes.first() else {
                inventory
                    .skipped
                    .push(format!("VNet {id} has no CIDR block"));
                continue;
            };
            let Some(address) = network_asset_ip(cidr, &seen) else {
                inventory.skipped.push(format!(
                    "VNet {id} has invalid or unavailable CIDR '{cidr}'"
                ));
                continue;
            };
            seen.insert(crate::domain::asset_id(address));
            let mut tags = vec![format!("azure-vnet:{id}"), format!("azure-cidr:{cidr}")];
            tags.extend(tag_entries(&vnet.tags));
            inventory.assets.push(CloudAsset {
                asset: cloud_asset(address, vnet.name.clone(), "vnet", observed_at),
                environment: None,
                owner: None,
                criticality: None,
                tags,
            });
            for subnet in &vnet.properties.subnets {
                let Some(cidr) = subnet.properties.address_prefix.as_deref() else {
                    inventory.skipped.push(format!(
                        "subnet {} has no CIDR block",
                        subnet.name.as_deref().unwrap_or("(unknown)")
                    ));
                    continue;
                };
                let Some(address) = network_asset_ip(cidr, &seen) else {
                    inventory.skipped.push(format!(
                        "subnet {} has invalid or unavailable CIDR '{cidr}'",
                        subnet.name.as_deref().unwrap_or("(unknown)")
                    ));
                    continue;
                };
                seen.insert(crate::domain::asset_id(address));
                inventory.assets.push(CloudAsset {
                    asset: cloud_asset(address, subnet.name.clone(), "subnet", observed_at),
                    environment: None,
                    owner: None,
                    criticality: None,
                    tags: vec![
                        format!(
                            "azure-subnet:{}",
                            subnet.name.as_deref().unwrap_or("(unknown)")
                        ),
                        format!("azure-vnet:{id}"),
                        format!("azure-cidr:{cidr}"),
                    ],
                });
            }
        }
    }
}

fn key(value: Option<&str>) -> String {
    value.unwrap_or("").to_ascii_lowercase()
}
fn tag_entries(tags: &HashMap<String, String>) -> Vec<String> {
    tags.iter()
        .filter(|(k, _)| !k.is_empty())
        .map(|(k, v)| format!("{k}={v}"))
        .collect()
}

#[derive(Debug, Deserialize)]
struct ListDoc<T> {
    value: Vec<T>,
    #[serde(rename = "nextLink")]
    next_link: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct AzureVm {
    id: Option<String>,
    name: Option<String>,
    location: Option<String>,
    #[serde(default)]
    tags: HashMap<String, String>,
    #[serde(default)]
    properties: VmProperties,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct VmProperties {
    #[serde(rename = "hardwareProfile", default)]
    hardware_profile: HardwareProfile,
    #[serde(rename = "storageProfile", default)]
    storage_profile: StorageProfile,
    #[serde(rename = "networkProfile", default)]
    network_profile: NetworkProfile,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct HardwareProfile {
    #[serde(rename = "vmSize")]
    vm_size: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct StorageProfile {
    #[serde(rename = "osDisk", default)]
    os_disk: OsDisk,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct OsDisk {
    #[serde(rename = "osType")]
    os_type: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct NetworkProfile {
    #[serde(rename = "networkInterfaces", default)]
    network_interfaces: Vec<ResourceRef>,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct ResourceRef {
    id: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct AzureNic {
    id: Option<String>,
    name: Option<String>,
    properties: NicProperties,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct NicProperties {
    #[serde(rename = "macAddress")]
    mac_address: Option<String>,
    #[serde(rename = "ipConfigurations", default)]
    ip_configurations: Vec<IpConfiguration>,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct IpConfiguration {
    name: Option<String>,
    #[serde(rename = "privateIPAddress")]
    private_ip_address: Option<String>,
}
impl AzureNic {
    fn primary_ip(&self) -> Option<std::net::IpAddr> {
        self.properties
            .ip_configurations
            .iter()
            .find_map(|c| c.private_ip_address.as_deref().and_then(parse_ip_cidr))
    }
}
#[derive(Debug, Clone, Deserialize, Default)]
struct AzureDisk {
    id: Option<String>,
    #[serde(rename = "managedBy")]
    managed_by: Option<String>,
    properties: DiskProperties,
    sku: Sku,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct DiskProperties {
    #[serde(rename = "diskSizeGB")]
    disk_size_gb: Option<u64>,
    #[serde(rename = "osType")]
    os_type: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct Sku {
    name: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct AzureVnet {
    id: Option<String>,
    name: Option<String>,
    #[serde(default)]
    tags: HashMap<String, String>,
    properties: VnetProperties,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct VnetProperties {
    #[serde(rename = "addressSpace", default)]
    address_space: AddressSpace,
    #[serde(default)]
    subnets: Vec<AzureSubnet>,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct AddressSpace {
    #[serde(rename = "addressPrefixes", default)]
    address_prefixes: Vec<String>,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct AzureSubnet {
    name: Option<String>,
    properties: SubnetProperties,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct SubnetProperties {
    #[serde(rename = "addressPrefix")]
    address_prefix: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Default)]
struct AzureSize {
    name: Option<String>,
    #[serde(rename = "numberOfCores")]
    number_of_cores: Option<u32>,
    #[serde(rename = "memoryInMB")]
    memory_in_mb: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_next_link_and_tags() {
        let page: ListDoc<AzureVm> = serde_json::from_str(
            r#"{"value":[{"name":"vm","tags":{"env":"prod"}}],"nextLink":"https://arm/next"}"#,
        )
        .unwrap();
        assert_eq!(page.value[0].name.as_deref(), Some("vm"));
        assert_eq!(page.value[0].tags["env"], "prod");
        assert_eq!(page.next_link.as_deref(), Some("https://arm/next"));
    }
}
