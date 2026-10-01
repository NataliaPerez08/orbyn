//! OpenStack adapter.
//!
//! This is deliberately limited to the read-only Nova and Cinder APIs.  The
//! endpoint is the compute service endpoint (and may be overridden for a
//! private cloud or a test server); the token is sent only as a request
//! header.  Servers without an address are reported rather than assigned a
//! made-up identity.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use serde::Deserialize;

use crate::domain::{Capacity, Filesystem, Interface};
use crate::integrations::cloud::{
    cloud_asset, parse_ip_cidr, CloudAsset, CloudInventory, CurlClient,
};
use crate::integrations::netbox::url_origin;

const PAGE_SIZE: usize = 100;
const MAX_PAGES: usize = 200;
const MAX_SERVERS: usize = 100_000;

/// A token for an already-scoped OpenStack project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenStackCredentials {
    pub token: String,
}

#[derive(Debug, Deserialize, Default)]
struct List<T> {
    #[serde(default)]
    servers: Vec<T>,
    #[serde(default)]
    flavors: Vec<T>,
    #[serde(default)]
    volumes: Vec<T>,
    #[serde(default)]
    links: Vec<Link>,
}

#[derive(Debug, Deserialize, Default)]
struct Link {
    #[serde(default)]
    rel: Option<String>,
    #[serde(default)]
    href: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct Server {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    addresses: HashMap<String, Vec<Address>>,
    #[serde(default)]
    flavor: FlavorRef,
    #[serde(default)]
    metadata: HashMap<String, String>,
    #[serde(rename = "OS-EXT-AZ:availability_zone", default)]
    availability_zone: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct Address {
    #[serde(default)]
    addr: Option<String>,
    #[serde(rename = "OS-EXT-IPS:type", default)]
    ip_type: Option<String>,
    #[serde(rename = "OS-EXT-IPS-MAC:mac_addr", default)]
    mac: Option<String>,
    #[serde(rename = "OS-EXT-IPS:port_id", default)]
    port_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct FlavorRef {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct Flavor {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    vcpus: Option<u32>,
    #[serde(default)]
    ram: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct Volume {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(rename = "volume_type", default)]
    volume_type: Option<String>,
    #[serde(default)]
    attachments: Vec<Attachment>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct Attachment {
    #[serde(rename = "server_id", default)]
    server_id: Option<String>,
    #[serde(default)]
    device: Option<String>,
}

/// Read-only OpenStack client using the shared curl boundary.
pub struct OpenStackClient {
    http: CurlClient,
    endpoint: String,
    token_header: String,
    project: Option<String>,
    region: Option<String>,
}

impl OpenStackClient {
    /// `endpoint` is normally the Nova service URL, for example
    /// `https://cloud.example/v2.1/project-id`.
    pub fn new(
        endpoint: &str,
        token: String,
        project: Option<String>,
        region: Option<String>,
        insecure: bool,
    ) -> Result<Self> {
        let endpoint = endpoint.trim_end_matches('/');
        if url_origin(endpoint).is_none() {
            bail!("invalid OpenStack endpoint '{endpoint}': expected an absolute http(s) URL without embedded credentials");
        }
        if token.trim().is_empty() {
            bail!("the OpenStack token must not be empty");
        }
        Ok(Self {
            http: CurlClient::new().insecure(insecure),
            endpoint: endpoint.to_string(),
            token_header: format!("Authorization: Bearer {token}"),
            project: project.filter(|v| !v.trim().is_empty()),
            region: region.filter(|v| !v.trim().is_empty()),
        })
    }

    async fn get(&self, path: &str) -> Result<String> {
        let url = format!("{}{path}", self.endpoint);
        self.http
            .get(
                &url,
                &[self.token_header.clone(), "Accept: application/json".into()],
            )
            .await
    }

    async fn try_get(&self, path: &str) -> Option<String> {
        let url = format!("{}{path}", self.endpoint);
        self.http
            .try_get(
                &url,
                &[self.token_header.clone(), "Accept: application/json".into()],
            )
            .await
    }

    /// Fetch Nova servers/flavors and best-effort Cinder volumes.
    pub async fn fetch_inventory(&self) -> Result<CloudInventory> {
        let observed_at = Utc::now();
        let mut inventory =
            CloudInventory::new("openstack", self.project.clone(), self.region.clone());
        let flavors = self.list_flavors().await?;
        let flavor_by_id: HashMap<_, _> = flavors
            .into_iter()
            .filter_map(|f| f.id.clone().map(|id| (id, f)))
            .collect();
        let mut server_assets = HashMap::new();
        for (count, server) in self.list_servers().await?.into_iter().enumerate() {
            if count >= MAX_SERVERS {
                bail!("OpenStack server listing exceeded the {MAX_SERVERS} server limit");
            }
            self.import_server(
                &server,
                &flavor_by_id,
                observed_at,
                &mut server_assets,
                &mut inventory,
            );
        }
        if let Some(body) = self.try_get("/volumes/detail").await {
            match parse_volumes(&body) {
                Ok(volumes) => import_volumes(&volumes, &server_assets, &mut inventory),
                Err(e) => inventory
                    .skipped
                    .push(format!("Cinder volumes response was skipped: {e}")),
            }
        } else {
            inventory
                .skipped
                .push("Cinder volumes were not available from the endpoint".into());
        }
        Ok(inventory)
    }

    async fn list_servers(&self) -> Result<Vec<Server>> {
        self.list_pages("/servers/detail", "servers", parse_servers)
            .await
    }

    async fn list_flavors(&self) -> Result<Vec<Flavor>> {
        self.list_pages("/flavors/detail", "flavors", parse_flavors)
            .await
    }

    async fn list_pages<T>(
        &self,
        path: &str,
        kind: &str,
        parse: impl Fn(&str) -> Result<(Vec<T>, Option<String>)>,
    ) -> Result<Vec<T>> {
        let mut result = Vec::new();
        let mut next = path.to_string();
        for _ in 0..MAX_PAGES {
            let body = self
                .get(&format!(
                    "{next}{}",
                    if next.contains('?') { "&" } else { "?" }.to_string()
                        + &format!("limit={PAGE_SIZE}")
                ))
                .await?;
            let (page, marker) = parse(&body)?;
            result.extend(page);
            if let Some(marker) = marker {
                next = format!("{path}?marker={marker}");
            } else {
                return Ok(result);
            }
        }
        bail!("OpenStack {kind} listing exceeded the {MAX_PAGES} page limit")
    }

    fn import_server(
        &self,
        server: &Server,
        flavors: &HashMap<String, Flavor>,
        observed_at: chrono::DateTime<Utc>,
        server_assets: &mut HashMap<String, String>,
        inventory: &mut CloudInventory,
    ) {
        let id = server.id.as_deref().unwrap_or("(unknown)");
        let addresses: Vec<&Address> = server.addresses.values().flatten().collect();
        let ip = addresses
            .iter()
            .find(|a| a.ip_type.as_deref() != Some("floating"))
            .and_then(|a| a.addr.as_deref())
            .and_then(parse_ip_cidr)
            .or_else(|| {
                addresses
                    .iter()
                    .find_map(|a| a.addr.as_deref().and_then(parse_ip_cidr))
            });
        let Some(ip) = ip else {
            inventory
                .skipped
                .push(format!("instance {id} has no IP address"));
            return;
        };
        let asset = cloud_asset(
            ip,
            server.name.clone().filter(|v| !v.is_empty()),
            "virtual-machine",
            observed_at,
        );
        let asset_id = asset.id.clone();
        server_assets.insert(id.to_string(), asset_id.clone());
        let mut tags = vec![format!("openstack-server:{id}")];
        if let Some(status) = &server.status {
            tags.push(format!("openstack-status:{status}"));
        }
        if let Some(az) = &server.availability_zone {
            tags.push(format!("openstack-az:{az}"));
        }
        tags.extend(
            server
                .metadata
                .iter()
                .filter(|(k, _)| !k.is_empty())
                .map(|(k, v)| format!("{k}={v}")),
        );
        inventory.assets.push(CloudAsset {
            asset,
            environment: None,
            owner: None,
            criticality: None,
            tags,
        });
        for (network, values) in &server.addresses {
            for (index, address) in values.iter().enumerate() {
                let Some(ip) = address.addr.as_deref().and_then(parse_ip_cidr) else {
                    continue;
                };
                let generated_name = format!("{id}-{network}-{index}");
                let name = address
                    .port_id
                    .as_deref()
                    .or(Some(network.as_str()))
                    .or(Some(generated_name.as_str()));
                let mut iface = Interface::new(&asset_id, name, address.mac.as_deref(), Some(ip));
                iface.is_up = server.status.as_deref().map(|s| s == "ACTIVE");
                inventory.interfaces.push(iface);
            }
        }
        if let Some(flavor) = server.flavor.id.as_ref().and_then(|id| flavors.get(id)) {
            inventory.capacities.push(Capacity {
                asset_id,
                cpu_model: None,
                cpu_sockets: None,
                cpu_cores: flavor.vcpus,
                cpu_threads: None,
                ram_total_mb: flavor.ram,
                hypervisor: Some("kvm".into()),
                collected_at: observed_at,
            });
        }
    }
}

fn parse_servers(json: &str) -> Result<(Vec<Server>, Option<String>)> {
    let doc: List<Server> =
        serde_json::from_str(json).context("parsing OpenStack servers response")?;
    Ok((doc.servers, next_marker(&doc.links)))
}

fn parse_flavors(json: &str) -> Result<(Vec<Flavor>, Option<String>)> {
    let doc: List<Flavor> =
        serde_json::from_str(json).context("parsing OpenStack flavors response")?;
    Ok((doc.flavors, next_marker(&doc.links)))
}

fn parse_volumes(json: &str) -> Result<Vec<Volume>> {
    Ok(serde_json::from_str::<List<Volume>>(json)
        .context("parsing OpenStack volumes response")?
        .volumes)
}

fn next_marker(links: &[Link]) -> Option<String> {
    let href = links
        .iter()
        .find(|link| link.rel.as_deref() == Some("next"))?
        .href
        .as_deref()?;
    href.split('?')
        .nth(1)?
        .split('&')
        .find_map(|part| part.strip_prefix("marker="))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

fn import_volumes(
    volumes: &[Volume],
    server_assets: &HashMap<String, String>,
    inventory: &mut CloudInventory,
) {
    for volume in volumes {
        let id = volume.id.as_deref().unwrap_or("(unknown)");
        let Some(attachment) = volume.attachments.first() else {
            inventory
                .skipped
                .push(format!("volume {id} is not attached to an instance"));
            continue;
        };
        let Some(server_id) = attachment.server_id.as_deref() else {
            inventory
                .skipped
                .push(format!("volume {id} has no server attachment"));
            continue;
        };
        let Some(asset_id) = server_assets.get(server_id) else {
            inventory.skipped.push(format!(
                "volume {id} is attached to unknown instance {server_id}"
            ));
            continue;
        };
        inventory.filesystems.push(Filesystem {
            asset_id: asset_id.clone(),
            device: Some(id.into()),
            mount: attachment.device.clone().unwrap_or_else(|| id.into()),
            fs_type: volume.volume_type.clone(),
            size_kb: volume.size.unwrap_or(0) * 1024 * 1024,
            used_kb: None,
            available_kb: None,
            used_pct: None,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_page_and_next_marker() {
        let json = r#"{"servers":[{"id":"srv-1","name":"web","status":"ACTIVE","addresses":{"net":[{"addr":"10.0.0.5","OS-EXT-IPS:type":"fixed"}]},"flavor":{"id":"small"}}],"links":[{"rel":"next","href":"https://cloud/servers/detail?marker=srv-1"}]}"#;
        let (servers, marker) = parse_servers(json).unwrap();
        assert_eq!(servers[0].name.as_deref(), Some("web"));
        assert_eq!(marker.as_deref(), Some("srv-1"));
    }

    #[test]
    fn parses_volume_attachment() {
        let json = r#"{"volumes":[{"id":"vol-1","size":10,"volume_type":"fast","attachments":[{"server_id":"srv-1","device":"/dev/vdb"}]}]}"#;
        let volumes = parse_volumes(json).unwrap();
        assert_eq!(
            volumes[0].attachments[0].server_id.as_deref(),
            Some("srv-1")
        );
        assert_eq!(volumes[0].size, Some(10));
    }

    #[test]
    fn validates_endpoint_and_token() {
        assert!(
            OpenStackClient::new("https://cloud.example", "token".into(), None, None, false)
                .is_ok()
        );
        assert!(OpenStackClient::new(
            "https://user@evil.example",
            "token".into(),
            None,
            None,
            false
        )
        .is_err());
        assert!(
            OpenStackClient::new("https://cloud.example", "".into(), None, None, false).is_err()
        );
    }
}
