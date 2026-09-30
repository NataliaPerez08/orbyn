//! Proxmox VE adapter (Phase 5).
//!
//! Reads nodes, virtual machines and containers from the Proxmox VE REST API
//! (`/api2/json/...`) and normalizes them into Orbyn assets, interfaces and
//! capacity. Read-only: only GET requests are issued.
//!
//! Credentials use a Proxmox API token, passed as
//! `Authorization: PVEAPIToken=<user@realm!tokenid=secret>` through curl's
//! stdin (`-H @-`), so the secret never appears in process arguments, logs or
//! on disk.
//!
//! ## What is imported
//!
//! - **Nodes** (`/cluster/status` + `/nodes`): the hypervisors, addressed by
//!   their cluster IP, with CPU/RAM capacity.
//! - **Guests** (`/cluster/resources?type=vm`): QEMU VMs and LXC containers.
//!
//! A guest is only imported when an IP address can be determined, because
//! Orbyn reconciles assets by IP. QEMU addresses come from the guest agent
//! (`agent/network-get-interfaces`, best effort); LXC addresses come from
//! `lxc/{vmid}/interfaces`. A guest without a reachable address is skipped
//! with a note rather than guessed onto a synthetic IP.

use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;

use crate::domain::{Capacity, Interface};
use crate::integrations::cloud::{
    cloud_asset, parse_ip_cidr, CloudAdapter, CloudAsset, CloudInventory, CurlClient,
};
use crate::integrations::netbox::url_origin;

/// Upper bound on guests whose per-guest interface detail is fetched, so a
/// provider with a huge inventory cannot turn an import into an unbounded
/// crawl. Guests beyond the cap are reported as skipped.
pub const MAX_GUESTS: usize = 5_000;

/// A node as reported by `/cluster/status` (name and address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxmoxNode {
    pub name: String,
    pub ip: Option<std::net::IpAddr>,
    pub online: bool,
}

/// A node's capacity as reported by `/nodes`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxmoxNodeCapacity {
    pub node: String,
    pub maxcpu: Option<u32>,
    pub maxmem_bytes: Option<u64>,
    pub status: Option<String>,
}

/// A QEMU VM or LXC container from `/cluster/resources?type=vm`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxmoxGuest {
    pub kind: String,
    pub vmid: u64,
    pub node: String,
    pub name: Option<String>,
    pub status: Option<String>,
    pub maxcpu: Option<u32>,
    pub maxmem_bytes: Option<u64>,
    pub tags: Vec<String>,
    pub pool: Option<String>,
}

/// An interface observed inside a guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxmoxInterface {
    pub name: Option<String>,
    pub mac: Option<String>,
    pub ip: Option<std::net::IpAddr>,
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
struct RawClusterStatus {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    online: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct RawNode {
    node: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    maxcpu: Option<f64>,
    #[serde(default)]
    maxmem: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct RawResource {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    vmid: Option<u64>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    maxcpu: Option<f64>,
    #[serde(default)]
    maxmem: Option<f64>,
    #[serde(default)]
    tags: Option<String>,
    #[serde(default)]
    pool: Option<String>,
}

/// `/nodes/{node}/lxc/{vmid}/interfaces` row.
#[derive(Debug, Deserialize)]
struct RawLxcInterface {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    hwaddr: Option<String>,
    #[serde(default)]
    inet: Option<String>,
    #[serde(default)]
    inet6: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawAgentResult {
    #[serde(default)]
    result: Vec<RawAgentInterface>,
}

#[derive(Debug, Deserialize)]
struct RawAgentInterface {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "hardware-address")]
    hardware_address: Option<String>,
    #[serde(default, rename = "ip-addresses")]
    ip_addresses: Vec<RawAgentAddress>,
}

#[derive(Debug, Deserialize)]
struct RawAgentAddress {
    #[serde(default, rename = "ip-address")]
    ip_address: Option<String>,
    #[serde(default, rename = "ip-address-type")]
    ip_address_type: Option<String>,
}

/// Parse `/cluster/status`, keeping the `node` entries.
pub fn parse_cluster_status(json: &str) -> Result<Vec<ProxmoxNode>> {
    let envelope: Envelope<Vec<RawClusterStatus>> =
        serde_json::from_str(json).context("parsing Proxmox cluster status")?;
    Ok(envelope
        .data
        .into_iter()
        .filter(|entry| entry.kind == "node")
        .filter_map(|entry| {
            let name = entry.name?;
            Some(ProxmoxNode {
                name,
                ip: entry.ip.as_deref().and_then(parse_ip_cidr),
                online: entry.online.map(|v| v != 0).unwrap_or(true),
            })
        })
        .collect())
}

/// Parse `/nodes` capacity rows.
pub fn parse_nodes(json: &str) -> Result<Vec<ProxmoxNodeCapacity>> {
    let envelope: Envelope<Vec<RawNode>> =
        serde_json::from_str(json).context("parsing Proxmox nodes")?;
    Ok(envelope
        .data
        .into_iter()
        .map(|node| ProxmoxNodeCapacity {
            node: node.node,
            maxcpu: node.maxcpu.map(|v| v.max(0.0) as u32),
            maxmem_bytes: node.maxmem.map(|v| v.max(0.0) as u64),
            status: node.status,
        })
        .collect())
}

/// Parse `/cluster/resources?type=vm`, keeping QEMU VMs and LXC containers.
pub fn parse_guest_resources(json: &str) -> Result<Vec<ProxmoxGuest>> {
    let envelope: Envelope<Vec<RawResource>> =
        serde_json::from_str(json).context("parsing Proxmox cluster resources")?;
    Ok(envelope
        .data
        .into_iter()
        .filter(|r| r.kind == "qemu" || r.kind == "lxc")
        .filter_map(|r| {
            let vmid = r.vmid?;
            let node = r.node?;
            Some(ProxmoxGuest {
                kind: r.kind,
                vmid,
                node,
                name: r.name.filter(|n| !n.is_empty()),
                status: r.status,
                maxcpu: r.maxcpu.map(|v| v.max(0.0) as u32),
                maxmem_bytes: r.maxmem.map(|v| v.max(0.0) as u64),
                tags: r.tags.as_deref().map(split_tags).unwrap_or_default(),
                pool: r.pool.filter(|p| !p.is_empty()),
            })
        })
        .collect())
}

/// Parse `/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces`.
pub fn parse_guest_agent_interfaces(json: &str) -> Result<Vec<ProxmoxInterface>> {
    let envelope: Envelope<RawAgentResult> =
        serde_json::from_str(json).context("parsing Proxmox guest agent interfaces")?;
    Ok(envelope
        .data
        .result
        .into_iter()
        .map(|iface| {
            let usable = |addr: &&RawAgentAddress| !is_loopback_text(addr.ip_address.as_deref());
            let ip = iface
                .ip_addresses
                .iter()
                .filter(usable)
                .find(|addr| addr.ip_address_type.as_deref() == Some("ipv4"))
                .or_else(|| iface.ip_addresses.iter().find(usable))
                .and_then(|addr| addr.ip_address.as_deref())
                .and_then(parse_ip_cidr);
            ProxmoxInterface {
                name: iface.name.filter(|n| !n.is_empty()),
                mac: iface.hardware_address.filter(|m| !m.is_empty()),
                ip,
            }
        })
        .collect())
}

/// Parse `/nodes/{node}/lxc/{vmid}/interfaces`.
pub fn parse_lxc_interfaces(json: &str) -> Result<Vec<ProxmoxInterface>> {
    let envelope: Envelope<Vec<RawLxcInterface>> =
        serde_json::from_str(json).context("parsing Proxmox container interfaces")?;
    Ok(envelope
        .data
        .into_iter()
        .map(|iface| {
            let ip = iface
                .inet
                .as_deref()
                .filter(|v| !is_loopback_text(Some(v)))
                .and_then(parse_ip_cidr)
                .or_else(|| {
                    iface
                        .inet6
                        .as_deref()
                        .filter(|v| !is_loopback_text(Some(v)))
                        .and_then(parse_ip_cidr)
                });
            ProxmoxInterface {
                name: iface.name.filter(|n| !n.is_empty()),
                mac: iface.hwaddr.filter(|m| !m.is_empty()),
                ip,
            }
        })
        .collect())
}

/// Split a Proxmox tag string (`;` or `,` separated) into individual tags.
fn split_tags(raw: &str) -> Vec<String> {
    raw.split([';', ','])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

fn is_loopback_text(raw: Option<&str>) -> bool {
    match raw.and_then(parse_ip_cidr) {
        Some(ip) => ip.is_loopback(),
        None => true,
    }
}

/// A Proxmox node name is used inside a URL path; reject anything that is not
/// a plain hostname-like token.
fn valid_node_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The provenance account from a Proxmox API token (`user@realm!tokenid`).
pub fn token_account(token: &str) -> Option<String> {
    let user = token.split('!').next()?;
    if user.is_empty() || !user.contains('@') {
        None
    } else {
        Some(user.to_string())
    }
}

/// A read-only Proxmox VE API client backed by the `curl` binary.
pub struct ProxmoxClient {
    http: CurlClient,
    base_url: String,
    token_header: String,
    account: Option<String>,
    node: Option<String>,
}

impl ProxmoxClient {
    /// Create a client for `base_url` (`https://host:8006`), authenticating
    /// with a Proxmox API token.
    pub fn new(base_url: &str, token: String, insecure: bool) -> Result<Self> {
        let base = base_url.trim_end_matches('/');
        if url_origin(base).is_none() {
            return Err(anyhow!(
                "invalid Proxmox URL '{base}': expected an absolute http(s) \
                 URL without embedded credentials"
            ));
        }
        if token.trim().is_empty() {
            return Err(anyhow!("the Proxmox API token must not be empty"));
        }
        Ok(Self {
            http: CurlClient::new().insecure(insecure),
            base_url: format!("{base}/api2/json"),
            token_header: format!("Authorization: PVEAPIToken={token}"),
            account: token_account(&token),
            node: None,
        })
    }

    /// Restrict the import to a single node.
    pub fn with_node(mut self, node: Option<String>) -> Self {
        self.node = node;
        self
    }

    async fn get(&self, path: &str) -> Result<String> {
        let url = format!("{}{path}", self.base_url);
        self.http
            .get(&url, std::slice::from_ref(&self.token_header))
            .await
    }

    async fn try_get(&self, path: &str) -> Option<String> {
        let url = format!("{}{path}", self.base_url);
        self.http
            .try_get(&url, std::slice::from_ref(&self.token_header))
            .await
    }

    /// Fetch nodes and guests and normalize them into a [`CloudInventory`].
    pub async fn fetch_inventory(&self) -> Result<CloudInventory> {
        let observed_at = Utc::now();

        let cluster_status = self.get("/cluster/status").await?;
        let nodes = parse_cluster_status(&cluster_status)?;
        let nodes_json = self.get("/nodes").await?;
        let capacities = parse_nodes(&nodes_json)?;
        let resources_json = self.get("/cluster/resources?type=vm").await?;
        let guests = parse_guest_resources(&resources_json)?;

        let capacity_by_node: HashMap<&str, &ProxmoxNodeCapacity> =
            capacities.iter().map(|c| (c.node.as_str(), c)).collect();

        let mut inventory = CloudInventory::new("proxmox", self.account.clone(), self.node.clone());

        // Nodes: hypervisors addressed by their cluster IP.
        for node in &nodes {
            if self.node.as_deref().is_some_and(|only| only != node.name) {
                continue;
            }
            let Some(ip) = node.ip else {
                inventory
                    .skipped
                    .push(format!("node '{}' has no cluster IP", node.name));
                continue;
            };
            let asset = cloud_asset(ip, Some(node.name.clone()), "hypervisor", observed_at);
            inventory.assets.push(CloudAsset {
                asset,
                environment: None,
                owner: None,
                criticality: None,
                tags: {
                    let mut tags = vec![format!("proxmox-node:{}", node.name)];
                    if !node.online {
                        tags.push("proxmox-offline".to_string());
                    }
                    tags
                },
            });
            if let Some(capacity) = capacity_by_node.get(node.name.as_str()) {
                let asset_id = crate::domain::asset_id(ip);
                inventory.capacities.push(Capacity {
                    asset_id,
                    cpu_model: None,
                    cpu_sockets: None,
                    cpu_cores: capacity.maxcpu,
                    cpu_threads: None,
                    ram_total_mb: capacity.maxmem_bytes.map(|b| b / (1024 * 1024)),
                    hypervisor: None,
                    collected_at: observed_at,
                });
            }
        }

        // Guests (QEMU VMs and LXC containers).
        let mut guests_processed = 0usize;
        for guest in &guests {
            if self.node.as_deref().is_some_and(|only| only != guest.node) {
                continue;
            }
            if !valid_node_name(&guest.node) {
                inventory
                    .skipped
                    .push(format!("guest {} has an invalid node name", guest.vmid));
                continue;
            }
            if guests_processed >= MAX_GUESTS {
                inventory
                    .skipped
                    .push(format!("guest cap of {MAX_GUESTS} reached"));
                break;
            }
            guests_processed += 1;

            let interfaces = self.guest_interfaces(guest).await;
            let Some(primary) = interfaces.iter().find_map(|i| i.ip) else {
                inventory.skipped.push(format!(
                    "{} {} on '{}' has no reachable IP address",
                    guest.kind, guest.vmid, guest.node
                ));
                continue;
            };

            let asset_id = crate::domain::asset_id(primary);
            let device_class = if guest.kind == "lxc" {
                "container"
            } else {
                "virtual-machine"
            };
            let hostname = guest
                .name
                .clone()
                .unwrap_or_else(|| format!("{}-{}", guest.kind, guest.vmid));
            let asset = cloud_asset(primary, Some(hostname), device_class, observed_at);

            let mut tags = vec![
                format!("proxmox-node:{}", guest.node),
                format!("proxmox-vmid:{}", guest.vmid),
            ];
            if let Some(pool) = &guest.pool {
                tags.push(format!("proxmox-pool:{pool}"));
            }
            if let Some(status) = &guest.status {
                tags.push(format!("proxmox-status:{status}"));
            }
            tags.extend(guest.tags.iter().cloned());

            inventory.assets.push(CloudAsset {
                asset,
                environment: None,
                owner: None,
                criticality: None,
                tags,
            });
            inventory.capacities.push(Capacity {
                asset_id: asset_id.clone(),
                cpu_model: None,
                cpu_sockets: None,
                cpu_cores: guest.maxcpu,
                cpu_threads: None,
                ram_total_mb: guest.maxmem_bytes.map(|b| b / (1024 * 1024)),
                hypervisor: Some(if guest.kind == "lxc" {
                    "lxc".to_string()
                } else {
                    "kvm".to_string()
                }),
                collected_at: observed_at,
            });
            for iface in &interfaces {
                if iface.name.as_deref() == Some("lo") {
                    continue;
                }
                let mut interface = Interface::new(
                    &asset_id,
                    iface.name.as_deref(),
                    iface.mac.as_deref(),
                    iface.ip,
                );
                interface.is_up = Some(true);
                inventory.interfaces.push(interface);
            }
        }

        Ok(inventory)
    }

    /// Fetch and parse a guest's interfaces, tolerating a guest without a
    /// running agent (an expected condition, not an error).
    async fn guest_interfaces(&self, guest: &ProxmoxGuest) -> Vec<ProxmoxInterface> {
        let path = if guest.kind == "lxc" {
            format!("/nodes/{}/lxc/{}/interfaces", guest.node, guest.vmid)
        } else {
            format!(
                "/nodes/{}/qemu/{}/agent/network-get-interfaces",
                guest.node, guest.vmid
            )
        };
        let Some(json) = self.try_get(&path).await else {
            return Vec::new();
        };
        let parsed = if guest.kind == "lxc" {
            parse_lxc_interfaces(&json)
        } else {
            parse_guest_agent_interfaces(&json)
        };
        parsed.unwrap_or_default()
    }
}

#[async_trait]
impl CloudAdapter for ProxmoxClient {
    fn provider(&self) -> &'static str {
        "proxmox"
    }

    async fn fetch(&self) -> Result<CloudInventory> {
        self.fetch_inventory().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER_STATUS: &str = r#"{"data":[
      {"type":"cluster","name":"dc1","nodes":2},
      {"type":"node","name":"pve1","nodeid":0,"online":1,"ip":"10.0.0.10"},
      {"type":"node","name":"pve2","nodeid":1,"online":0,"ip":"10.0.0.11"},
      {"type":"node","name":"pve3","nodeid":2,"online":1}
    ]}"#;

    const NODES: &str = r#"{"data":[
      {"node":"pve1","status":"online","maxcpu":16,"maxmem":68719476736},
      {"node":"pve2","status":"offline","maxcpu":8,"maxmem":34359738368}
    ]}"#;

    const RESOURCES: &str = r#"{"data":[
      {"id":"qemu/100","type":"qemu","vmid":100,"node":"pve1","name":"web-01","status":"running","maxcpu":4,"maxmem":8589934592,"tags":"prod;web","pool":"app"},
      {"id":"lxc/200","type":"lxc","vmid":200,"node":"pve1","name":"ct-01","status":"running","maxcpu":2,"maxmem":2147483648,"tags":"prod"},
      {"id":"storage/local","type":"storage","node":"pve1"}
    ]}"#;

    #[test]
    fn parses_nodes_with_ip_and_online_state() {
        let nodes = parse_cluster_status(CLUSTER_STATUS).unwrap();
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].name, "pve1");
        assert_eq!(nodes[0].ip, Some("10.0.0.10".parse().unwrap()));
        assert!(nodes[0].online);
        assert!(!nodes[1].online);
        assert_eq!(nodes[2].ip, None, "node without an IP is still listed");
    }

    #[test]
    fn parses_node_capacity() {
        let capacities = parse_nodes(NODES).unwrap();
        assert_eq!(capacities.len(), 2);
        assert_eq!(capacities[0].maxcpu, Some(16));
        assert_eq!(capacities[0].maxmem_bytes, Some(68_719_476_736));
    }

    #[test]
    fn parses_guest_resources_and_ignores_other_types() {
        let guests = parse_guest_resources(RESOURCES).unwrap();
        assert_eq!(guests.len(), 2, "storage entries are ignored");
        let vm = &guests[0];
        assert_eq!(vm.kind, "qemu");
        assert_eq!(vm.vmid, 100);
        assert_eq!(vm.node, "pve1");
        assert_eq!(vm.name.as_deref(), Some("web-01"));
        assert_eq!(vm.maxcpu, Some(4));
        assert_eq!(vm.tags, vec!["prod".to_string(), "web".to_string()]);
        assert_eq!(vm.pool.as_deref(), Some("app"));
        let ct = &guests[1];
        assert_eq!(ct.kind, "lxc");
        assert_eq!(ct.tags, vec!["prod".to_string()]);
    }

    #[test]
    fn parses_guest_agent_interfaces_and_picks_non_loopback_ip() {
        let json = r#"{"data":{"result":[
          {"name":"lo","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4","prefix":8}]},
          {"name":"eth0","hardware-address":"aa:bb:cc:dd:ee:01","ip-addresses":[
            {"ip-address":"fe80::1","ip-address-type":"ipv6","prefix":64},
            {"ip-address":"10.0.0.5","ip-address-type":"ipv4","prefix":24}]}
        ]}}"#;
        let ifaces = parse_guest_agent_interfaces(json).unwrap();
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0].name.as_deref(), Some("lo"));
        assert_eq!(ifaces[0].ip, None, "loopback is not chosen");
        assert_eq!(ifaces[1].name.as_deref(), Some("eth0"));
        assert_eq!(ifaces[1].mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(ifaces[1].ip, Some("10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn parses_lxc_interfaces() {
        let json = r#"{"data":[
          {"name":"lo","hwaddr":"00:00:00:00:00:00","inet":"127.0.0.1/8"},
          {"name":"eth0","hwaddr":"AA:BB:CC:DD:EE:02","inet":"10.0.0.6/24","inet6":"fe80::2/64"}
        ]}"#;
        let ifaces = parse_lxc_interfaces(json).unwrap();
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0].ip, None);
        assert_eq!(ifaces[1].ip, Some("10.0.0.6".parse().unwrap()));
        assert_eq!(ifaces[1].mac.as_deref(), Some("AA:BB:CC:DD:EE:02"));
    }

    #[test]
    fn token_account_extracts_the_user_realm() {
        assert_eq!(
            token_account("root@pam!orbyn=secret"),
            Some("root@pam".to_string())
        );
        assert_eq!(token_account("opaque-token"), None);
    }

    #[test]
    fn node_name_validation_rejects_path_injection() {
        assert!(valid_node_name("pve1"));
        assert!(valid_node_name("pve-1.dc"));
        assert!(!valid_node_name(""));
        assert!(!valid_node_name("pve/../etc"));
        assert!(!valid_node_name("pve 1"));
    }

    #[test]
    fn client_validates_base_url_and_token() {
        assert!(
            ProxmoxClient::new("https://pve.example.com:8006", "root@pam!t=s".into(), false)
                .is_ok()
        );
        assert!(
            ProxmoxClient::new("https://user@pve.example.com", "root@pam!t=s".into(), false)
                .is_err()
        );
        assert!(ProxmoxClient::new("not-a-url", "root@pam!t=s".into(), false).is_err());
        assert!(ProxmoxClient::new("https://pve.example.com", "".into(), false).is_err());
    }
}
