//! Huawei Cloud adapter (Phase 5).
//!
//! Reads Elastic Cloud Server (ECS) instances and their network interfaces,
//! Elastic Volume Service (EVS) volumes, and Virtual Private Cloud (VPC)
//! networks and subnets from the Huawei Cloud APIs and normalizes them into
//! Orbyn assets, interfaces, filesystems and CPU/RAM capacity. Read-only: only
//! `List*` operations and a best-effort IAM `ListProjects` are issued.
//!
//! Requests are signed with the AK/SK `SDK-HMAC-SHA256` scheme ([`sign`]) from
//! credentials supplied by `HUAWEICLOUD_SDK_AK`/`HUAWEICLOUD_SDK_SK` or flags.
//! No credential is persisted; the signature travels to curl on stdin, never
//! in process arguments.
//!
//! An ECS instance is imported when it has a private or floating IP address.
//! Instances without one are skipped with a note. EVS volumes become
//! filesystem rows on the server they are attached to (an unattached volume is
//! skipped with a note). VPCs and subnets become assets keyed by the network
//! address of their CIDR, tagged with their provider id.

pub mod sign;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::domain::{Capacity, Filesystem, Interface};
use crate::integrations::cloud::{
    cloud_asset, network_address, network_asset_ip, parse_ip_cidr, CloudAsset, CloudInventory,
    CurlClient,
};
use crate::integrations::netbox::{url_origin, UrlOrigin};
use sign::sign_request;

/// Maximum list pages followed per resource.
const MAX_PAGES: usize = 200;
/// Servers requested per page.
const PAGE_SIZE: usize = 100;
/// Maximum instances imported in one run.
const MAX_SERVERS: usize = 100_000;
/// Maximum flavors materialized from `ListFlavorsDetails`.
const MAX_FLAVORS: usize = 10_000;
/// Maximum EVS volumes imported in one run.
const MAX_VOLUMES: usize = 100_000;
/// Maximum VPCs imported in one run.
const MAX_VPCS: usize = 10_000;
/// Maximum subnets imported in one run.
const MAX_SUBNETS: usize = 100_000;

/// Huawei Cloud credentials (Access Key / Secret Key) for signing requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HuaweiCredentials {
    pub access_key: String,
    pub secret_key: String,
}

impl HuaweiCredentials {
    /// Resolve credentials from the standard Huawei Cloud SDK environment
    /// variables.
    pub fn from_env() -> Option<Self> {
        let access_key = std::env::var("HUAWEICLOUD_SDK_AK").ok()?;
        let secret_key = std::env::var("HUAWEICLOUD_SDK_SK").ok()?;
        if access_key.is_empty() || secret_key.is_empty() {
            return None;
        }
        Some(Self {
            access_key,
            secret_key,
        })
    }
}

/// A parsed `ListServersDetails` page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ServerPage {
    servers: Vec<HuaweiServer>,
    has_next: bool,
}

/// A read-only Huawei Cloud ECS client backed by the `curl` binary.
pub struct HuaweiClient {
    http: CurlClient,
    credentials: HuaweiCredentials,
    region: String,
    ecs_endpoint: String,
    ecs_host: String,
    evs_endpoint: String,
    evs_host: String,
    vpc_endpoint: String,
    vpc_host: String,
    iam_endpoint: String,
    iam_host: String,
    project_id: Option<String>,
}

impl HuaweiClient {
    /// Create a client for `region`, optionally overriding the ECS endpoint
    /// (useful for tests and private endpoints) and supplying a project id
    /// (otherwise resolved from IAM).
    pub fn new(
        credentials: HuaweiCredentials,
        region: &str,
        project_id: Option<String>,
        endpoint_override: Option<&str>,
        insecure: bool,
    ) -> Result<Self> {
        if region.is_empty()
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            bail!("invalid Huawei Cloud region '{region}'");
        }
        let ecs_endpoint = match endpoint_override {
            Some(endpoint) => endpoint.trim_end_matches('/').to_string(),
            None => format!("https://ecs.{region}.myhuaweicloud.com"),
        };
        let ecs_origin = origin(&ecs_endpoint, "ECS")?;
        let evs_endpoint = format!("https://evs.{region}.myhuaweicloud.com");
        let evs_origin = origin(&evs_endpoint, "EVS")?;
        let vpc_endpoint = format!("https://vpc.{region}.myhuaweicloud.com");
        let vpc_origin = origin(&vpc_endpoint, "VPC")?;
        let iam_endpoint = format!("https://iam.{region}.myhuaweicloud.com");
        let iam_origin = origin(&iam_endpoint, "IAM")?;

        let project_id = project_id.filter(|p| !p.trim().is_empty());
        Ok(Self {
            http: CurlClient::new().insecure(insecure),
            credentials,
            region: region.to_string(),
            ecs_endpoint,
            ecs_host: host_header(&ecs_origin),
            evs_endpoint,
            evs_host: host_header(&evs_origin),
            vpc_endpoint,
            vpc_host: host_header(&vpc_origin),
            iam_endpoint,
            iam_host: host_header(&iam_origin),
            project_id,
        })
    }

    /// Fetch ECS instances and normalize them into a [`CloudInventory`].
    pub async fn fetch_inventory(&self) -> Result<CloudInventory> {
        let observed_at = Utc::now();
        let (project_id, project_name) = self.resolve_project().await?;
        let account = project_name.or_else(|| Some(project_id.clone()));
        let mut inventory = CloudInventory::new("huawei", account, Some(self.region.clone()));

        // Flavor catalogue (best effort): CPU/RAM capacity is only attached
        // when the flavor is answerable.
        let flavors = self.fetch_flavors(&project_id).await;

        let mut offset = 0usize;
        let mut servers_seen = 0usize;
        let mut instance_assets: HashMap<String, String> = HashMap::new();
        let mut servers_done = false;
        for _page in 0..MAX_PAGES {
            let params = vec![
                ("limit".to_string(), PAGE_SIZE.to_string()),
                ("offset".to_string(), offset.to_string()),
            ];
            let path = format!("/v2.1/{project_id}/servers/detail");
            let (url, headers) =
                self.signed_get(&self.ecs_endpoint, &self.ecs_host, &path, &params);
            let body = self.http.get(&url, &headers).await?;
            let page = parse_servers(&body)?;

            for server in &page.servers {
                servers_seen += 1;
                if servers_seen > MAX_SERVERS {
                    bail!(
                        "Huawei Cloud ListServersDetails exceeded the {MAX_SERVERS} server limit"
                    );
                }
                self.import_server(
                    server,
                    &flavors,
                    observed_at,
                    &mut instance_assets,
                    &mut inventory,
                );
            }

            if !page.has_next || page.servers.is_empty() {
                servers_done = true;
                break;
            }
            offset += PAGE_SIZE;
        }
        if !servers_done {
            bail!("Huawei Cloud ListServersDetails exceeded the {MAX_PAGES} page limit");
        }

        self.import_volumes(&project_id, &instance_assets, observed_at, &mut inventory)
            .await?;
        self.import_vpcs(&project_id, observed_at, &mut inventory)
            .await?;
        self.import_subnets(&project_id, observed_at, &mut inventory)
            .await?;
        Ok(inventory)
    }

    /// Normalize one ECS instance into the inventory, or record why it was
    /// skipped.
    fn import_server(
        &self,
        server: &HuaweiServer,
        flavors: &HashMap<String, Flavor>,
        observed_at: DateTime<Utc>,
        instance_assets: &mut HashMap<String, String>,
        inventory: &mut CloudInventory,
    ) {
        let server_id = server.id.as_deref().unwrap_or("(unknown)");
        let Some(ip) = server_ip(server) else {
            inventory
                .skipped
                .push(format!("instance {server_id} has no IP address"));
            return;
        };

        let hostname = server
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(str::to_string);

        let mut asset = cloud_asset(ip, hostname, "virtual-machine", observed_at);
        if let Some(os) = server.metadata.get("os_type") {
            let os = os.trim();
            if !os.is_empty() {
                asset.os_name = Some(os.to_string());
            }
        }

        let asset_id = asset.id.clone();
        instance_assets.insert(server_id.to_string(), asset_id.clone());
        let mut tags = vec![format!("huawei-server:{server_id}")];
        if let Some(kind) = server.flavor.name.as_deref() {
            tags.push(format!("huawei-flavor:{kind}"));
        }
        if let Some(state) = server.status.as_deref() {
            tags.push(format!("huawei-state:{state}"));
        }
        if let Some(az) = server.availability_zone.as_deref() {
            tags.push(format!("huawei-az:{az}"));
        }
        for (key, value) in &server.metadata {
            if !key.is_empty() {
                tags.push(format!("{key}={value}"));
            }
        }
        tags.extend(server.tags.iter().filter(|t| !t.is_empty()).cloned());

        inventory.assets.push(CloudAsset {
            asset,
            environment: None,
            owner: None,
            criticality: None,
            tags,
        });

        // Interfaces: one per address across every attached network.
        for (network, addresses) in &server.addresses {
            for (index, address) in addresses.iter().enumerate() {
                let Some(address_ip) = address.addr.as_deref().and_then(parse_ip_cidr) else {
                    continue;
                };
                let name = address
                    .port_id
                    .clone()
                    .or_else(|| Some(format!("{server_id}-{network}-{index}")));
                let mut interface = Interface::new(
                    &asset_id,
                    name.as_deref(),
                    address.mac.as_deref(),
                    Some(address_ip),
                );
                interface.is_up = server.status.as_deref().map(|s| s == "ACTIVE");
                inventory.interfaces.push(interface);
            }
        }

        // Capacity from the flavor catalogue, when known.
        if let Some(flavor_id) = server.flavor.id.as_deref() {
            if let Some(flavor) = flavors.get(flavor_id) {
                inventory.capacities.push(Capacity {
                    asset_id,
                    cpu_model: None,
                    cpu_sockets: None,
                    cpu_cores: flavor.vcpus,
                    cpu_threads: None,
                    ram_total_mb: flavor.ram_mb(),
                    hypervisor: None,
                    collected_at: observed_at,
                });
            }
        }
    }

    /// Follow a `limit`/`offset` JSON list endpoint until the last page.
    async fn list_all<T>(
        &self,
        endpoint: &str,
        host: &str,
        path: &str,
        parse: impl Fn(&str) -> Result<Vec<T>>,
    ) -> Result<Vec<T>> {
        let mut items = Vec::new();
        let mut offset = 0usize;
        let mut done = false;
        for _page in 0..MAX_PAGES {
            let params = vec![
                ("limit".to_string(), PAGE_SIZE.to_string()),
                ("offset".to_string(), offset.to_string()),
            ];
            let (url, headers) = self.signed_get(endpoint, host, path, &params);
            let body = self.http.get(&url, &headers).await?;
            let page = parse(&body)?;
            let short = page.len() < PAGE_SIZE;
            items.extend(page);
            if short {
                done = true;
                break;
            }
            offset += PAGE_SIZE;
        }
        if !done {
            bail!("Huawei Cloud listing {path} exceeded the {MAX_PAGES} page limit");
        }
        Ok(items)
    }

    /// Normalize EVS volumes into filesystems on their attached server.
    async fn import_volumes(
        &self,
        project_id: &str,
        instance_assets: &HashMap<String, String>,
        _observed_at: DateTime<Utc>,
        inventory: &mut CloudInventory,
    ) -> Result<()> {
        let path = format!("/v2/{project_id}/cloudvolumes/detail");
        let volumes = self
            .list_all(&self.evs_endpoint, &self.evs_host, &path, parse_volumes)
            .await?;
        if volumes.len() > MAX_VOLUMES {
            bail!("Huawei Cloud ListVolumesDetails exceeded the {MAX_VOLUMES} volume limit");
        }
        for volume in &volumes {
            let volume_id = volume.id.as_deref().unwrap_or("(unknown)");
            let Some(attachment) = volume.attachments.first() else {
                inventory
                    .skipped
                    .push(format!("volume {volume_id} is not attached to a server"));
                continue;
            };
            let Some(server_id) = attachment.server_id.as_deref() else {
                inventory
                    .skipped
                    .push(format!("volume {volume_id} has no server attachment"));
                continue;
            };
            let Some(asset_id) = instance_assets.get(server_id) else {
                inventory.skipped.push(format!(
                    "volume {volume_id} is attached to unknown server {server_id}"
                ));
                continue;
            };
            let mount = attachment
                .device
                .clone()
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| volume_id.to_string());
            inventory.filesystems.push(Filesystem {
                asset_id: asset_id.clone(),
                device: Some(volume_id.to_string()),
                mount,
                fs_type: volume.volume_type.clone(),
                size_kb: volume.size_gb.unwrap_or(0) * 1024 * 1024,
                used_kb: None,
                available_kb: None,
                used_pct: None,
            });
            if let Some(asset) = inventory
                .assets
                .iter_mut()
                .find(|a| &a.asset.id == asset_id)
            {
                asset.tags.push(format!("huawei-volume:{volume_id}"));
                if let Some(kind) = &volume.volume_type {
                    asset.tags.push(format!("huawei-volume-type:{kind}"));
                }
            }
        }
        Ok(())
    }

    /// Normalize VPCs into assets keyed by the network address of their CIDR.
    async fn import_vpcs(
        &self,
        project_id: &str,
        observed_at: DateTime<Utc>,
        inventory: &mut CloudInventory,
    ) -> Result<()> {
        let path = format!("/v1/{project_id}/vpcs");
        let vpcs = self
            .list_all(&self.vpc_endpoint, &self.vpc_host, &path, parse_vpcs)
            .await?;
        if vpcs.len() > MAX_VPCS {
            bail!("Huawei Cloud ListVpcs exceeded the {MAX_VPCS} VPC limit");
        }
        let mut seen: HashSet<String> = inventory
            .assets
            .iter()
            .map(|a| a.asset.id.clone())
            .collect();
        for vpc in &vpcs {
            let vpc_id = vpc.id.as_deref().unwrap_or("(unknown)");
            let Some(cidr) = vpc.cidr.as_deref().filter(|c| !c.is_empty()) else {
                inventory
                    .skipped
                    .push(format!("VPC {vpc_id} has no CIDR block"));
                continue;
            };
            let Some(network) = network_address(cidr) else {
                inventory
                    .skipped
                    .push(format!("VPC {vpc_id} has an invalid CIDR block '{cidr}'"));
                continue;
            };
            let Some(address) = network_asset_ip(cidr, &seen) else {
                inventory.skipped.push(format!(
                    "VPC {vpc_id} has no free address in '{cidr}' to represent it"
                ));
                continue;
            };
            seen.insert(crate::domain::asset_id(address));
            let hostname = vpc
                .name
                .clone()
                .filter(|n| !n.is_empty())
                .or_else(|| Some(vpc_id.to_string()));
            let asset = cloud_asset(address, hostname, "vpc", observed_at);
            let mut tags = vec![
                format!("huawei-vpc:{vpc_id}"),
                format!("huawei-cidr:{cidr}"),
            ];
            if address != network {
                tags.push(format!("huawei-netaddr:{network}"));
            }
            if let Some(state) = vpc.status.as_deref() {
                tags.push(format!("huawei-state:{state}"));
            }
            inventory.assets.push(CloudAsset {
                asset,
                environment: None,
                owner: None,
                criticality: None,
                tags,
            });
        }
        Ok(())
    }

    /// Normalize subnets into assets keyed by the network address of their
    /// CIDR.
    async fn import_subnets(
        &self,
        project_id: &str,
        observed_at: DateTime<Utc>,
        inventory: &mut CloudInventory,
    ) -> Result<()> {
        let path = format!("/v1/{project_id}/subnets");
        let subnets = self
            .list_all(&self.vpc_endpoint, &self.vpc_host, &path, parse_subnets)
            .await?;
        if subnets.len() > MAX_SUBNETS {
            bail!("Huawei Cloud ListSubnets exceeded the {MAX_SUBNETS} subnet limit");
        }
        let mut seen: HashSet<String> = inventory
            .assets
            .iter()
            .map(|a| a.asset.id.clone())
            .collect();
        for subnet in &subnets {
            let subnet_id = subnet.id.as_deref().unwrap_or("(unknown)");
            let Some(cidr) = subnet.cidr.as_deref().filter(|c| !c.is_empty()) else {
                inventory
                    .skipped
                    .push(format!("subnet {subnet_id} has no CIDR block"));
                continue;
            };
            let Some(network) = network_address(cidr) else {
                inventory.skipped.push(format!(
                    "subnet {subnet_id} has an invalid CIDR block '{cidr}'"
                ));
                continue;
            };
            let Some(address) = network_asset_ip(cidr, &seen) else {
                inventory.skipped.push(format!(
                    "subnet {subnet_id} has no free address in '{cidr}' to represent it"
                ));
                continue;
            };
            seen.insert(crate::domain::asset_id(address));
            let hostname = subnet
                .name
                .clone()
                .filter(|n| !n.is_empty())
                .or_else(|| Some(subnet_id.to_string()));
            let asset = cloud_asset(address, hostname, "subnet", observed_at);
            let mut tags = vec![
                format!("huawei-subnet:{subnet_id}"),
                format!("huawei-cidr:{cidr}"),
            ];
            if address != network {
                tags.push(format!("huawei-netaddr:{network}"));
            }
            if let Some(vpc_id) = &subnet.vpc_id {
                tags.push(format!("huawei-vpc:{vpc_id}"));
            }
            if let Some(az) = subnet
                .availability_zone
                .as_deref()
                .filter(|az| !az.is_empty())
            {
                tags.push(format!("huawei-az:{az}"));
            }
            if let Some(state) = subnet.status.as_deref() {
                tags.push(format!("huawei-state:{state}"));
            }
            inventory.assets.push(CloudAsset {
                asset,
                environment: None,
                owner: None,
                criticality: None,
                tags,
            });
        }
        Ok(())
    }

    /// Resolve the project id (and, when possible, its name) to scope the ECS
    /// query. An explicit `--project-id` wins; otherwise IAM is queried and the
    /// project whose name matches the region is preferred.
    async fn resolve_project(&self) -> Result<(String, Option<String>)> {
        if let Some(project_id) = &self.project_id {
            return Ok((project_id.clone(), None));
        }
        let projects = self.fetch_projects().await?;
        let chosen = projects
            .iter()
            .find(|p| p.name.as_deref() == Some(self.region.as_str()))
            .or_else(|| projects.iter().find(|p| p.enabled))
            .or_else(|| projects.first())
            .ok_or_else(|| {
                anyhow!("no Huawei Cloud project is visible to this credential; pass --project-id")
            })?;
        Ok((chosen.id.clone(), chosen.name.clone()))
    }

    /// Best-effort IAM `ListProjects`.
    async fn fetch_projects(&self) -> Result<Vec<Project>> {
        let (url, headers) =
            self.signed_get(&self.iam_endpoint, &self.iam_host, "/v3/projects", &[]);
        let body = self
            .http
            .get(&url, &headers)
            .await
            .context("listing Huawei Cloud IAM projects")?;
        parse_projects(&body)
    }

    /// Fetch the flavor catalogue (id -> vCPUs/RAM). Best effort: a failure
    /// omits capacity rather than failing the import.
    async fn fetch_flavors(&self, project_id: &str) -> HashMap<String, Flavor> {
        let path = format!("/v2.1/{project_id}/flavors/detail");
        let (url, headers) = self.signed_get(&self.ecs_endpoint, &self.ecs_host, &path, &[]);
        match self.http.try_get(&url, &headers).await {
            Some(body) => parse_flavors(&body).unwrap_or_default(),
            None => HashMap::new(),
        }
    }

    /// Sign a GET and return the full URL plus headers.
    fn signed_get(
        &self,
        endpoint: &str,
        host: &str,
        path: &str,
        params: &[(String, String)],
    ) -> (String, Vec<String>) {
        let signed = sign_request(
            "GET",
            &self.credentials.access_key,
            &self.credentials.secret_key,
            host,
            path,
            params,
            &[],
            b"",
            Utc::now(),
        );
        let url = if signed.query.is_empty() {
            format!("{endpoint}{path}")
        } else {
            format!("{endpoint}{path}?{}", signed.query)
        };
        (url, signed.headers)
    }
}

/// Validate an endpoint URL and return its origin.
fn origin(endpoint: &str, what: &str) -> Result<UrlOrigin> {
    url_origin(endpoint).ok_or_else(|| {
        anyhow!(
            "invalid Huawei Cloud {what} endpoint '{endpoint}': expected an absolute \
             http(s) URL without embedded credentials"
        )
    })
}

/// The `Host` header for an origin, including a non-default port and
/// bracketing an IPv6 literal.
fn host_header(origin: &UrlOrigin) -> String {
    let default_port = (origin.scheme == "https" && origin.port == 443)
        || (origin.scheme == "http" && origin.port == 80);
    if default_port {
        origin.host.clone()
    } else if origin.host.contains(':') {
        format!("[{}]:{}", origin.host, origin.port)
    } else {
        format!("{}:{}", origin.host, origin.port)
    }
}

/// The best IP for a server: a private/fixed address first, then a floating
/// one.
fn server_ip(server: &HuaweiServer) -> Option<IpAddr> {
    let mut fixed: Option<IpAddr> = None;
    let mut floating: Option<IpAddr> = None;
    for addresses in server.addresses.values() {
        for address in addresses {
            let Some(ip) = address.addr.as_deref().and_then(parse_ip_cidr) else {
                continue;
            };
            if address.ip_type.as_deref() == Some("floating") {
                if floating.is_none() {
                    floating = Some(ip);
                }
            } else if fixed.is_none() {
                fixed = Some(ip);
            }
        }
    }
    fixed.or(floating)
}

// --- JSON response parsing ------------------------------------------------

#[derive(Debug, Deserialize)]
struct ServersDoc {
    #[serde(default)]
    servers: Vec<HuaweiServer>,
    #[serde(default, rename = "servers_links")]
    links: Vec<Link>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct Link {
    #[serde(default)]
    rel: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct HuaweiServer {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    addresses: HashMap<String, Vec<ServerAddress>>,
    #[serde(default)]
    flavor: FlavorRef,
    #[serde(default)]
    metadata: HashMap<String, String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(rename = "OS-EXT-AZ:availability_zone", default)]
    availability_zone: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct FlavorRef {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct ServerAddress {
    #[serde(default)]
    addr: Option<String>,
    #[serde(rename = "OS-EXT-IPS:type", default)]
    ip_type: Option<String>,
    #[serde(rename = "OS-EXT-IPS-MAC:mac_addr", default)]
    mac: Option<String>,
    #[serde(rename = "OS-EXT-IPS:port_id", default)]
    port_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProjectsDoc {
    #[serde(default)]
    projects: Vec<Project>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct Project {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct FlavorsDoc {
    #[serde(default)]
    flavors: Vec<Flavor>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct Flavor {
    #[serde(default)]
    id: String,
    #[serde(default)]
    vcpus: Option<u32>,
    #[serde(default)]
    ram: Option<u64>,
}

impl Flavor {
    /// RAM in MiB (the API reports `ram` in MiB).
    fn ram_mb(&self) -> Option<u64> {
        self.ram
    }
}

/// Parse a `ListServersDetails` response.
fn parse_servers(json: &str) -> Result<ServerPage> {
    let doc: ServersDoc =
        serde_json::from_str(json).context("parsing Huawei Cloud ListServersDetails response")?;
    let has_next = doc
        .links
        .iter()
        .any(|link| link.rel.as_deref() == Some("next"));
    Ok(ServerPage {
        servers: doc.servers,
        has_next,
    })
}

/// Parse an IAM `ListProjects` response.
fn parse_projects(json: &str) -> Result<Vec<Project>> {
    let doc: ProjectsDoc =
        serde_json::from_str(json).context("parsing Huawei Cloud ListProjects response")?;
    Ok(doc.projects)
}

/// Parse a `ListFlavorsDetails` response into an id-keyed map.
fn parse_flavors(json: &str) -> Result<HashMap<String, Flavor>> {
    let doc: FlavorsDoc =
        serde_json::from_str(json).context("parsing Huawei Cloud ListFlavorsDetails response")?;
    let mut flavors = HashMap::new();
    for flavor in doc.flavors.into_iter().take(MAX_FLAVORS) {
        if !flavor.id.is_empty() {
            flavors.insert(flavor.id.clone(), flavor);
        }
    }
    Ok(flavors)
}

// --- EVS volumes ----------------------------------------------------------

#[derive(Debug, Deserialize)]
struct VolumesDoc {
    #[serde(default)]
    volumes: Vec<HuaweiVolume>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct HuaweiVolume {
    #[serde(default)]
    id: Option<String>,
    #[serde(rename = "size", default)]
    size_gb: Option<u64>,
    #[serde(rename = "volume_type", default)]
    volume_type: Option<String>,
    #[serde(default)]
    attachments: Vec<VolumeAttachment>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct VolumeAttachment {
    #[serde(rename = "server_id", default)]
    server_id: Option<String>,
    #[serde(default)]
    device: Option<String>,
}

/// Parse a `ListVolumesDetails` response. The `volumes_links` cursor is not
/// needed: [`HuaweiClient::list_all`] pages until a short batch.
fn parse_volumes(json: &str) -> Result<Vec<HuaweiVolume>> {
    let doc: VolumesDoc =
        serde_json::from_str(json).context("parsing Huawei Cloud ListVolumesDetails response")?;
    Ok(doc.volumes)
}

// --- VPCs -----------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct VpcsDoc {
    #[serde(default)]
    vpcs: Vec<HuaweiVpc>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct HuaweiVpc {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    cidr: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

fn parse_vpcs(json: &str) -> Result<Vec<HuaweiVpc>> {
    let doc: VpcsDoc =
        serde_json::from_str(json).context("parsing Huawei Cloud ListVpcs response")?;
    Ok(doc.vpcs)
}

// --- Subnets --------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SubnetsDoc {
    #[serde(default)]
    subnets: Vec<HuaweiSubnet>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct HuaweiSubnet {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    cidr: Option<String>,
    #[serde(rename = "vpc_id", default)]
    vpc_id: Option<String>,
    #[serde(rename = "availability_zone", default)]
    availability_zone: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

fn parse_subnets(json: &str) -> Result<Vec<HuaweiSubnet>> {
    let doc: SubnetsDoc =
        serde_json::from_str(json).context("parsing Huawei Cloud ListSubnets response")?;
    Ok(doc.subnets)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVERS_JSON: &str = r#"{
      "servers": [
        {
          "id": "9b1e1c1f-1234",
          "name": "web-01",
          "status": "ACTIVE",
          "flavor": {"id": "s3.small.1", "name": "s3.small.1"},
          "metadata": {"os_type": "Linux", "env": "prod"},
          "tags": ["team-a"],
          "OS-EXT-AZ:availability_zone": "cn-north-4a",
          "addresses": {
            "vpc-a": [
              {"addr": "192.168.0.5", "OS-EXT-IPS:type": "fixed", "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:aa:bb:01", "OS-EXT-IPS:port_id": "port-aaa"},
              {"addr": "203.0.113.5", "OS-EXT-IPS:type": "floating"}
            ]
          }
        },
        {
          "id": "no-ip",
          "name": "stopped-01",
          "status": "SHUTOFF",
          "flavor": {"id": "s3.small.1", "name": "s3.small.1"},
          "addresses": {}
        }
      ],
      "servers_links": [
        {"rel": "previous", "href": "https://ecs.example/v2.1/p/servers/detail?offset=0"},
        {"rel": "next", "href": "https://ecs.example/v2.1/p/servers/detail?offset=100"}
      ]
    }"#;

    #[test]
    fn parses_servers_and_next_link() {
        let page = parse_servers(SERVERS_JSON).expect("parse");
        assert_eq!(page.servers.len(), 2);
        assert!(page.has_next);
        let first = &page.servers[0];
        assert_eq!(first.id.as_deref(), Some("9b1e1c1f-1234"));
        assert_eq!(first.name.as_deref(), Some("web-01"));
        assert_eq!(
            first.metadata.get("os_type").map(String::as_str),
            Some("Linux")
        );
        assert_eq!(first.availability_zone.as_deref(), Some("cn-north-4a"));
        assert_eq!(first.tags, vec!["team-a".to_string()]);
        assert_eq!(
            server_ip(first),
            Some("192.168.0.5".parse().unwrap()),
            "a fixed address wins over a floating one"
        );
        assert_eq!(server_ip(&page.servers[1]), None);
    }

    #[test]
    fn floating_address_is_used_when_no_fixed_one_exists() {
        let mut server = HuaweiServer {
            id: Some("srv".into()),
            ..Default::default()
        };
        server.addresses.insert(
            "vpc".into(),
            vec![ServerAddress {
                addr: Some("203.0.113.9".into()),
                ip_type: Some("floating".into()),
                ..Default::default()
            }],
        );
        assert_eq!(server_ip(&server), Some("203.0.113.9".parse().unwrap()));
    }

    #[test]
    fn parses_projects_and_skips_disabled() {
        let json = r#"{"projects":[
          {"id":"p1","name":"cn-north-4","enabled":true},
          {"id":"p2","name":"cn-north-1","enabled":false}
        ]}"#;
        let projects = parse_projects(json).expect("parse");
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0].id, "p1");
        assert!(projects[0].enabled);
        assert!(!projects[1].enabled);
    }

    #[test]
    fn parses_flavors_into_a_map() {
        let json = r#"{"flavors":[
          {"id":"s3.small.1","name":"s3.small.1","vcpus":1,"ram":2048},
          {"id":"s3.medium.2","name":"s3.medium.2","vcpus":2,"ram":4096}
        ]}"#;
        let flavors = parse_flavors(json).expect("parse");
        assert_eq!(flavors.len(), 2);
        let small = flavors.get("s3.small.1").unwrap();
        assert_eq!(small.vcpus, Some(1));
        assert_eq!(small.ram_mb(), Some(2048));
    }

    #[test]
    fn client_validates_region_and_endpoint() {
        let creds = HuaweiCredentials {
            access_key: "AK".into(),
            secret_key: "SK".into(),
        };
        assert!(HuaweiClient::new(creds.clone(), "cn-north-4", None, None, false).is_ok());
        assert!(HuaweiClient::new(creds.clone(), "CN-NORTH-4", None, None, false).is_err());
        assert!(HuaweiClient::new(creds.clone(), "a b", None, None, false).is_err());
        assert!(HuaweiClient::new(
            creds.clone(),
            "cn-north-4",
            Some("p1".into()),
            Some("http://127.0.0.1:9000"),
            false
        )
        .is_ok());
        assert!(HuaweiClient::new(
            creds,
            "cn-north-4",
            None,
            Some("https://user@evil.example.com"),
            false
        )
        .is_err());
    }

    #[test]
    fn import_server_builds_asset_interfaces_and_capacity() {
        let creds = HuaweiCredentials {
            access_key: "AK".into(),
            secret_key: "SK".into(),
        };
        let client =
            HuaweiClient::new(creds, "cn-north-4", Some("p1".into()), None, false).unwrap();
        let page = parse_servers(SERVERS_JSON).expect("parse");
        let mut flavors = HashMap::new();
        flavors.insert(
            "s3.small.1".to_string(),
            Flavor {
                id: "s3.small.1".into(),
                vcpus: Some(1),
                ram: Some(2048),
            },
        );
        let mut inventory =
            CloudInventory::new("huawei", Some("p1".into()), Some("cn-north-4".into()));
        let mut instance_assets = HashMap::new();
        client.import_server(
            &page.servers[0],
            &flavors,
            Utc::now(),
            &mut instance_assets,
            &mut inventory,
        );

        assert_eq!(inventory.assets.len(), 1);
        assert_eq!(
            instance_assets.get("9b1e1c1f-1234"),
            Some(&inventory.assets[0].asset.id)
        );
        assert_eq!(
            inventory.assets[0].asset.hostname.as_deref(),
            Some("web-01")
        );
        assert_eq!(inventory.assets[0].asset.os_name.as_deref(), Some("Linux"));
        assert!(inventory.assets[0]
            .tags
            .contains(&"huawei-flavor:s3.small.1".to_string()));
        assert!(inventory.assets[0].tags.contains(&"env=prod".to_string()));
        assert_eq!(inventory.interfaces.len(), 2);
        assert!(inventory.interfaces[0].is_up == Some(true));
        assert_eq!(inventory.capacities.len(), 1);
        assert_eq!(inventory.capacities[0].cpu_cores, Some(1));
        assert_eq!(inventory.capacities[0].ram_total_mb, Some(2048));

        // A server without an address is skipped with a note.
        client.import_server(
            &page.servers[1],
            &flavors,
            Utc::now(),
            &mut instance_assets,
            &mut inventory,
        );
        assert_eq!(inventory.assets.len(), 1);
        assert!(inventory.skipped[0].contains("no-ip"));
    }

    #[test]
    fn parses_volumes_vpcs_and_subnets() {
        let json = r#"{"volumes":[
          {"id":"vol-1","size":40,"volume_type":"SSD","attachments":[
            {"server_id":"srv-1","device":"/dev/vdb","id":"vol-1"}]},
          {"id":"vol-2","size":100,"volume_type":"SATA","attachments":[]}
        ]}"#;
        let volumes = parse_volumes(json).expect("parse volumes");
        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[0].size_gb, Some(40));
        assert_eq!(
            volumes[0].attachments[0].device.as_deref(),
            Some("/dev/vdb")
        );
        assert!(volumes[1].attachments.is_empty());

        let json = r#"{"vpcs":[
          {"id":"vpc-1","name":"vpc-main","cidr":"192.168.0.0/16","status":"ACTIVE"}
        ]}"#;
        let vpcs = parse_vpcs(json).expect("parse vpcs");
        assert_eq!(vpcs.len(), 1);
        assert_eq!(vpcs[0].cidr.as_deref(), Some("192.168.0.0/16"));

        let json = r#"{"subnets":[
          {"id":"subnet-1","name":"sub-main","cidr":"192.168.1.0/24",
           "vpc_id":"vpc-1","availability_zone":"cn-north-4a","status":"ACTIVE"}
        ]}"#;
        let subnets = parse_subnets(json).expect("parse subnets");
        assert_eq!(subnets.len(), 1);
        assert_eq!(subnets[0].vpc_id.as_deref(), Some("vpc-1"));
        assert_eq!(subnets[0].availability_zone.as_deref(), Some("cn-north-4a"));
    }
}
