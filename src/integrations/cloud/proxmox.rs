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
//! ## Extended coverage
//!
//! - **Node storage** (`/nodes/{node}/storage`): each active datastore is
//!   normalized into a filesystem row on the node (mount = storage name).
//! - **Guest config** (`/nodes/{node}/{kind}/{vmid}/config`): OS identity
//!   (`ostype`), CPU/RAM allocation and static addresses (`netN` for LXC,
//!   `ipconfigN` for QEMU).
//! - **Guest OS** (`/nodes/{node}/qemu/{vmid}/agent/get-osinfo`): precise OS
//!   name/version for VMs with a running agent.
//! - **Guest disks** (`/nodes/{node}/qemu/{vmid}/agent/get-fsinfo`, and the
//!   LXC `rootfs` volume size): filesystem rows.
//!
//! A guest is only imported when an IP address can be determined, because
//! Orbyn reconciles assets by IP. Addresses are taken, in order, from the
//! live guest (QEMU `agent/network-get-interfaces`; LXC `lxc/{vmid}/interfaces`)
//! and then from the guest config, so a stopped container or a VM without a
//! running agent is still imported when its config carries a static address.
//! A guest with no address anywhere is skipped with a note rather than
//! guessed onto a synthetic IP. Templates are skipped.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::Deserialize;

use crate::domain::{asset_id, normalize_mac, Capacity, Filesystem, Interface};
use crate::integrations::cloud::{
    cloud_asset, parse_ip_cidr, CloudAsset, CloudInventory, CurlClient,
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
    pub template: bool,
}

/// An interface observed inside a guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxmoxInterface {
    pub name: Option<String>,
    pub mac: Option<String>,
    pub ip: Option<IpAddr>,
}

/// A filesystem observed inside a guest (or a node datastore).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxmoxFs {
    pub device: Option<String>,
    pub mount: String,
    pub fs_type: Option<String>,
    pub size_kb: u64,
    pub used_kb: Option<u64>,
    pub available_kb: Option<u64>,
    pub used_pct: Option<u32>,
}

/// An active datastore from `/nodes/{node}/storage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxmoxStorage {
    pub name: String,
    pub storage_type: Option<String>,
    pub total_bytes: u64,
    pub used_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
}

/// Per-guest detail assembled from the guest config and, for VMs, the guest
/// agent: identity, allocation, interfaces and filesystems.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuestDetail {
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub cpu_cores: Option<u32>,
    pub cpu_sockets: Option<u32>,
    pub memory_mb: Option<u64>,
    pub interfaces: Vec<ProxmoxInterface>,
    /// Static address from the guest config (`netN` for LXC, `ipconfigN` for
    /// QEMU), used only when no live interface carries an address.
    pub static_ip: Option<IpAddr>,
    pub filesystems: Vec<ProxmoxFs>,
}

type ConfigMap = serde_json::Map<String, serde_json::Value>;

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
    #[serde(default)]
    template: Option<u8>,
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

#[derive(Debug, Deserialize)]
struct RawOsInfo {
    #[serde(default)]
    result: Option<RawOsInfoResult>,
}

#[derive(Debug, Deserialize)]
struct RawOsInfoResult {
    #[serde(default, rename = "pretty-name")]
    pretty_name: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "version-id")]
    version_id: Option<String>,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawFsInfo {
    #[serde(default)]
    result: Vec<RawFsInfoEntry>,
}

#[derive(Debug, Deserialize)]
struct RawFsInfoEntry {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    mountpoint: Option<String>,
    #[serde(default, rename = "type")]
    fs_type: Option<String>,
    #[serde(default, rename = "total-bytes")]
    total_bytes: Option<u64>,
    #[serde(default, rename = "used-bytes")]
    used_bytes: Option<u64>,
    #[serde(default)]
    disk: Vec<RawFsDisk>,
}

#[derive(Debug, Deserialize)]
struct RawFsDisk {
    #[serde(default)]
    dev: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawStorage {
    storage: String,
    #[serde(default, rename = "type")]
    storage_type: Option<String>,
    #[serde(default)]
    active: Option<u8>,
    #[serde(default)]
    total: Option<u64>,
    #[serde(default)]
    used: Option<u64>,
    #[serde(default)]
    avail: Option<u64>,
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
                template: r.template.is_some_and(|v| v != 0),
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

/// Parse `/nodes/{node}/qemu/{vmid}/agent/get-osinfo`, returning
/// `(os_name, os_version)`. A guest without a running agent yields `None`.
pub fn parse_guest_agent_osinfo(json: &str) -> Option<(String, Option<String>)> {
    let envelope: Envelope<RawOsInfo> = serde_json::from_str(json).ok()?;
    let result = envelope.data.result?;
    let name = result
        .pretty_name
        .or(result.name)
        .filter(|n| !n.is_empty())?;
    let version = result
        .version_id
        .or(result.version)
        .filter(|v| !v.is_empty());
    Some((name, version))
}

/// Parse `/nodes/{node}/qemu/{vmid}/agent/get-fsinfo` into filesystem rows.
pub fn parse_guest_agent_fsinfo(json: &str) -> Result<Vec<ProxmoxFs>> {
    let envelope: Envelope<RawFsInfo> =
        serde_json::from_str(json).context("parsing Proxmox guest agent filesystems")?;
    Ok(envelope
        .data
        .result
        .into_iter()
        .filter_map(fs_entry)
        .collect())
}

fn fs_entry(entry: RawFsInfoEntry) -> Option<ProxmoxFs> {
    let total = entry.total_bytes?;
    if total == 0 {
        return None;
    }
    let mount = entry.mountpoint.filter(|m| !m.is_empty())?;
    let used = entry.used_bytes;
    let used_pct = used.map(|u| ((u as f64 / total as f64) * 100.0).round() as u32);
    let device = entry.disk.into_iter().find_map(|d| d.dev).or(entry.name);
    Some(ProxmoxFs {
        device,
        mount,
        fs_type: entry.fs_type,
        size_kb: total / 1024,
        used_kb: used.map(|u| u / 1024),
        available_kb: used.map(|u| total.saturating_sub(u) / 1024),
        used_pct,
    })
}

/// Parse `/nodes/{node}/storage`, keeping active datastores with a size.
pub fn parse_node_storage(json: &str) -> Result<Vec<ProxmoxStorage>> {
    let envelope: Envelope<Vec<RawStorage>> =
        serde_json::from_str(json).context("parsing Proxmox node storage")?;
    Ok(envelope
        .data
        .into_iter()
        .filter_map(|s| {
            let total = s.total?;
            if total == 0 || s.active == Some(0) {
                return None;
            }
            Some(ProxmoxStorage {
                name: s.storage,
                storage_type: s.storage_type,
                total_bytes: total,
                used_bytes: s.used,
                available_bytes: s.avail,
            })
        })
        .collect())
}

/// Parse `/nodes/{node}/lxc/{vmid}/config` into a [`GuestDetail`].
pub fn parse_lxc_config(json: &str) -> Result<GuestDetail> {
    let envelope: Envelope<ConfigMap> =
        serde_json::from_str(json).context("parsing Proxmox container config")?;
    let map = envelope.data;
    let mut detail = GuestDetail {
        os_name: cfg_str(&map, "ostype"),
        cpu_cores: cfg_u32(&map, "cores"),
        memory_mb: cfg_u64(&map, "memory"),
        ..GuestDetail::default()
    };
    if let Some(rootfs) = cfg_str(&map, "rootfs").and_then(|raw| lxc_rootfs(&raw)) {
        detail.filesystems.push(rootfs);
    }
    for (key, value) in &map {
        if !is_suffixed_key(key, "net") {
            continue;
        }
        let Some(raw) = value_string(value) else {
            continue;
        };
        let iface = parse_lxc_net(key, &raw);
        if detail.static_ip.is_none() {
            detail.static_ip = iface.ip;
        }
        detail.interfaces.push(iface);
    }
    Ok(detail)
}

/// Parse `/nodes/{node}/qemu/{vmid}/config` into a [`GuestDetail`].
pub fn parse_qemu_config(json: &str) -> Result<GuestDetail> {
    let envelope: Envelope<ConfigMap> =
        serde_json::from_str(json).context("parsing Proxmox VM config")?;
    let map = envelope.data;
    let sockets = cfg_u32(&map, "sockets");
    let cores_per_socket = cfg_u32(&map, "cores");
    let cpu_cores = match (cores_per_socket, sockets) {
        (Some(cores), Some(sockets)) => Some(cores.saturating_mul(sockets)),
        (Some(cores), None) => Some(cores),
        _ => None,
    };
    let mut detail = GuestDetail {
        os_name: qemu_ostype_name(cfg_str(&map, "ostype").as_deref()),
        cpu_cores,
        cpu_sockets: sockets,
        memory_mb: cfg_u64(&map, "memory"),
        ..GuestDetail::default()
    };
    for (key, value) in &map {
        let Some(raw) = value_string(value) else {
            continue;
        };
        if is_suffixed_key(key, "net") {
            detail.interfaces.push(parse_qemu_net(key, &raw));
        } else if is_suffixed_key(key, "ipconfig") && detail.static_ip.is_none() {
            detail.static_ip = parse_qemu_ipconfig(&raw);
        }
    }
    Ok(detail)
}

/// Map a QEMU `ostype` code to a coarse OS family.
fn qemu_ostype_name(ostype: Option<&str>) -> Option<String> {
    let ostype = ostype?;
    if ostype.starts_with("l2") {
        Some("Linux".to_string())
    } else if ostype.starts_with("win") {
        Some("Windows".to_string())
    } else if ostype.starts_with("solaris") {
        Some("Solaris".to_string())
    } else {
        None
    }
}

/// Parse an LXC `netN` value
/// (`name=eth0,bridge=vmbr0,hwaddr=..,ip=10.0.0.5/24,type=veth`).
fn parse_lxc_net(key: &str, raw: &str) -> ProxmoxInterface {
    let mut name = None;
    let mut mac = None;
    let mut v4 = None;
    let mut v6 = None;
    for token in raw.split(',') {
        let Some((field, value)) = token.split_once('=') else {
            continue;
        };
        match field.trim() {
            "name" => name = non_empty(value),
            "hwaddr" => mac = non_empty(value),
            "ip" => v4 = parse_static_ip(value),
            "ip6" => v6 = parse_static_ip(value),
            _ => {}
        }
    }
    ProxmoxInterface {
        name: name.or_else(|| Some(key.to_string())),
        mac,
        ip: v4.or(v6),
    }
}

/// Parse a QEMU `netN` value (`virtio=BC:24:...,bridge=vmbr1,firewall=0`).
fn parse_qemu_net(key: &str, raw: &str) -> ProxmoxInterface {
    let mut mac = None;
    for token in raw.split(',') {
        let Some((_field, value)) = token.split_once('=') else {
            continue;
        };
        if let Some(normalized) = normalize_mac(value.trim()) {
            mac = Some(normalized);
            break;
        }
    }
    ProxmoxInterface {
        name: Some(key.to_string()),
        mac,
        ip: None,
    }
}

/// Parse a QEMU `ipconfigN` value (`gw=10.0.0.1,ip=10.0.0.21/24`).
fn parse_qemu_ipconfig(raw: &str) -> Option<IpAddr> {
    let mut v4 = None;
    let mut v6 = None;
    for token in raw.split(',') {
        let Some((field, value)) = token.split_once('=') else {
            continue;
        };
        match field.trim() {
            "ip" => v4 = parse_static_ip(value),
            "ip6" => v6 = parse_static_ip(value),
            _ => {}
        }
    }
    v4.or(v6)
}

/// Parse a static address from a config value, rejecting DHCP/auto markers.
fn parse_static_ip(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if raw.is_empty() || matches!(raw, "dhcp" | "auto" | "manual") {
        return None;
    }
    parse_ip_cidr(raw)
}

/// Build a root filesystem row from an LXC `rootfs` volume
/// (`local-lvm:vm-100-disk-0,size=20G`).
fn lxc_rootfs(raw: &str) -> Option<ProxmoxFs> {
    let mut device = None;
    let mut size_kb = None;
    for (index, token) in raw.split(',').enumerate() {
        if index == 0 {
            device = non_empty(token);
            continue;
        }
        if let Some((field, value)) = token.split_once('=') {
            if field.trim() == "size" {
                size_kb = parse_size_kb(value.trim());
            }
        }
    }
    Some(ProxmoxFs {
        device,
        mount: "/".to_string(),
        fs_type: None,
        size_kb: size_kb.filter(|k| *k > 0)?,
        used_kb: None,
        available_kb: None,
        used_pct: None,
    })
}

/// Parse a Proxmox size with a unit suffix (`20G`, `512M`, `8` bytes).
fn parse_size_kb(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    let split = raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len());
    let (digits, unit) = raw.split_at(split);
    let value: u64 = digits.trim().parse().ok()?;
    match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => Some(value / 1024),
        "k" | "kb" => Some(value),
        "m" | "mb" => Some(value.saturating_mul(1024)),
        "g" | "gb" => Some(value.saturating_mul(1024 * 1024)),
        "t" | "tb" => Some(value.saturating_mul(1024 * 1024 * 1024)),
        _ => None,
    }
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

fn value_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn cfg_str(map: &ConfigMap, key: &str) -> Option<String> {
    value_string(map.get(key)?)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn cfg_u32(map: &ConfigMap, key: &str) -> Option<u32> {
    cfg_str(map, key)?.parse().ok()
}

fn cfg_u64(map: &ConfigMap, key: &str) -> Option<u64> {
    cfg_str(map, key)?.parse().ok()
}

fn non_empty(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        None
    } else {
        Some(raw.to_string())
    }
}

/// Whether `key` is `<prefix><digits>` (e.g. `net0`, `ipconfig0`).
fn is_suffixed_key(key: &str, prefix: &str) -> bool {
    key.strip_prefix(prefix)
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
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

fn fs_observation(asset_id: &str, fs: &ProxmoxFs) -> Filesystem {
    Filesystem {
        asset_id: asset_id.to_string(),
        device: fs.device.clone(),
        mount: fs.mount.clone(),
        fs_type: fs.fs_type.clone(),
        size_kb: fs.size_kb,
        used_kb: fs.used_kb,
        available_kb: fs.available_kb,
        used_pct: fs.used_pct,
    }
}

fn storage_observation(asset_id: &str, storage: &ProxmoxStorage) -> Filesystem {
    let used_pct = storage
        .used_bytes
        .map(|used| ((used as f64 / storage.total_bytes as f64) * 100.0).round() as u32);
    Filesystem {
        asset_id: asset_id.to_string(),
        device: None,
        mount: storage.name.clone(),
        fs_type: storage.storage_type.clone(),
        size_kb: storage.total_bytes / 1024,
        used_kb: storage.used_bytes.map(|used| used / 1024),
        available_kb: storage.available_bytes.map(|avail| avail / 1024),
        used_pct,
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
            if !valid_node_name(&node.name) {
                inventory
                    .skipped
                    .push("a node has an invalid name".to_string());
                continue;
            }
            let Some(ip) = node.ip else {
                inventory
                    .skipped
                    .push(format!("node '{}' has no cluster IP", node.name));
                continue;
            };
            let node_asset_id = asset_id(ip);
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
                inventory.capacities.push(Capacity {
                    asset_id: node_asset_id.clone(),
                    cpu_model: None,
                    cpu_sockets: None,
                    cpu_cores: capacity.maxcpu,
                    cpu_threads: None,
                    ram_total_mb: capacity.maxmem_bytes.map(|b| b / (1024 * 1024)),
                    hypervisor: None,
                    collected_at: observed_at,
                });
            }
            for storage in self.node_storage(&node.name).await {
                inventory
                    .filesystems
                    .push(storage_observation(&node_asset_id, &storage));
            }
        }

        // Guests (QEMU VMs and LXC containers).
        let mut guests_processed = 0usize;
        for guest in &guests {
            if self.node.as_deref().is_some_and(|only| only != guest.node) {
                continue;
            }
            if guest.template {
                inventory
                    .skipped
                    .push(format!("{} {} is a template", guest.kind, guest.vmid));
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

            let detail = self.guest_detail(guest).await;
            let primary = detail
                .interfaces
                .iter()
                .find_map(|i| i.ip)
                .or(detail.static_ip);
            let Some(primary) = primary else {
                inventory.skipped.push(format!(
                    "{} {} on '{}' has no reachable IP address",
                    guest.kind, guest.vmid, guest.node
                ));
                continue;
            };

            let guest_asset_id = asset_id(primary);
            let device_class = if guest.kind == "lxc" {
                "container"
            } else {
                "virtual-machine"
            };
            let hostname = guest
                .name
                .clone()
                .unwrap_or_else(|| format!("{}-{}", guest.kind, guest.vmid));
            let mut asset = cloud_asset(primary, Some(hostname), device_class, observed_at);
            asset.os_name = detail.os_name.clone();
            asset.os_version = detail.os_version.clone();

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
                owner: guest.pool.clone(),
                criticality: None,
                tags,
            });
            inventory.capacities.push(Capacity {
                asset_id: guest_asset_id.clone(),
                cpu_model: None,
                cpu_sockets: detail.cpu_sockets,
                cpu_cores: detail.cpu_cores.or(guest.maxcpu),
                cpu_threads: None,
                ram_total_mb: detail
                    .memory_mb
                    .or_else(|| guest.maxmem_bytes.map(|b| b / (1024 * 1024))),
                hypervisor: Some(if guest.kind == "lxc" {
                    "lxc".to_string()
                } else {
                    "kvm".to_string()
                }),
                collected_at: observed_at,
            });
            for iface in &detail.interfaces {
                if iface.name.as_deref() == Some("lo") {
                    continue;
                }
                let mut interface = Interface::new(
                    &guest_asset_id,
                    iface.name.as_deref(),
                    iface.mac.as_deref(),
                    iface.ip,
                );
                interface.is_up = Some(true);
                inventory.interfaces.push(interface);
            }
            for filesystem in &detail.filesystems {
                inventory
                    .filesystems
                    .push(fs_observation(&guest_asset_id, filesystem));
            }
        }

        Ok(inventory)
    }

    /// Fetch a guest's config and, for VMs, its guest-agent OS and filesystem
    /// detail, tolerating a guest without a running agent (an expected
    /// condition, not an error). Live interfaces take precedence over the
    /// config; the config provides the static-address fallback.
    async fn guest_detail(&self, guest: &ProxmoxGuest) -> GuestDetail {
        let config_path = format!("/nodes/{}/{}/{}/config", guest.node, guest.kind, guest.vmid);
        let configured = self
            .try_get(&config_path)
            .await
            .map(|json| {
                if guest.kind == "lxc" {
                    parse_lxc_config(&json)
                } else {
                    parse_qemu_config(&json)
                }
            })
            .and_then(Result::ok)
            .unwrap_or_default();
        let mut detail = configured;

        if guest.kind == "lxc" {
            let path = format!("/nodes/{}/lxc/{}/interfaces", guest.node, guest.vmid);
            if let Some(json) = self.try_get(&path).await {
                if let Ok(live) = parse_lxc_interfaces(&json) {
                    if !live.is_empty() {
                        detail.interfaces = live;
                    }
                }
            }
        } else {
            let iface_path = format!(
                "/nodes/{}/qemu/{}/agent/network-get-interfaces",
                guest.node, guest.vmid
            );
            if let Some(json) = self.try_get(&iface_path).await {
                if let Ok(live) = parse_guest_agent_interfaces(&json) {
                    if !live.is_empty() {
                        detail.interfaces = live;
                    }
                }
            }
            let os_path = format!("/nodes/{}/qemu/{}/agent/get-osinfo", guest.node, guest.vmid);
            if let Some((name, version)) = self
                .try_get(&os_path)
                .await
                .and_then(|json| parse_guest_agent_osinfo(&json))
            {
                detail.os_name = Some(name);
                detail.os_version = version;
            }
            let fs_path = format!("/nodes/{}/qemu/{}/agent/get-fsinfo", guest.node, guest.vmid);
            if let Some(filesystems) = self
                .try_get(&fs_path)
                .await
                .and_then(|json| parse_guest_agent_fsinfo(&json).ok())
                .filter(|filesystems| !filesystems.is_empty())
            {
                detail.filesystems = filesystems;
            }
        }

        detail
    }

    /// Fetch a node's active datastores, tolerating an unsupported endpoint.
    async fn node_storage(&self, node: &str) -> Vec<ProxmoxStorage> {
        let path = format!("/nodes/{node}/storage");
        self.try_get(&path)
            .await
            .and_then(|json| parse_node_storage(&json).ok())
            .unwrap_or_default()
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

    #[test]
    fn parses_lxc_config_os_network_and_rootfs() {
        let json = r#"{"data":{
          "ostype":"ubuntu",
          "cores":2,
          "memory":8192,
          "rootfs":"local-lvm:vm-110-disk-0,size=40G",
          "net0":"name=eth0,bridge=vmbr0,gw=172.20.0.10,hwaddr=BC:24:11:C7:D6:4C,ip=172.20.0.22/24,type=veth"
        }}"#;
        let detail = parse_lxc_config(json).unwrap();
        assert_eq!(detail.os_name.as_deref(), Some("ubuntu"));
        assert_eq!(detail.cpu_cores, Some(2));
        assert_eq!(detail.memory_mb, Some(8192));
        assert_eq!(detail.static_ip, Some("172.20.0.22".parse().unwrap()));
        assert_eq!(detail.interfaces.len(), 1);
        assert_eq!(detail.interfaces[0].name.as_deref(), Some("eth0"));
        assert_eq!(
            detail.interfaces[0].mac.as_deref(),
            Some("BC:24:11:C7:D6:4C")
        );
        assert_eq!(detail.filesystems.len(), 1);
        assert_eq!(detail.filesystems[0].mount, "/");
        assert_eq!(detail.filesystems[0].size_kb, 40 * 1024 * 1024);
        assert_eq!(
            detail.filesystems[0].device.as_deref(),
            Some("local-lvm:vm-110-disk-0")
        );
    }

    #[test]
    fn parses_qemu_config_os_cpu_and_static_ip() {
        let json = r#"{"data":{
          "ostype":"l26",
          "cores":2,
          "sockets":2,
          "memory":"2048",
          "net0":"virtio=BC:24:11:B6:97:E4,bridge=vmbr1,firewall=0",
          "ipconfig0":"gw=10.0.0.1,ip=10.0.0.21/24"
        }}"#;
        let detail = parse_qemu_config(json).unwrap();
        assert_eq!(detail.os_name.as_deref(), Some("Linux"));
        assert_eq!(detail.cpu_cores, Some(4), "cores per socket x sockets");
        assert_eq!(detail.cpu_sockets, Some(2));
        assert_eq!(detail.memory_mb, Some(2048));
        assert_eq!(detail.static_ip, Some("10.0.0.21".parse().unwrap()));
        assert_eq!(detail.interfaces.len(), 1);
        assert_eq!(detail.interfaces[0].name.as_deref(), Some("net0"));
        assert_eq!(
            detail.interfaces[0].mac.as_deref(),
            Some("bc:24:11:b6:97:e4")
        );
        assert_eq!(detail.interfaces[0].ip, None, "config has no live IP");
    }

    #[test]
    fn qemu_config_without_a_static_address_has_no_ip() {
        let json = r#"{"data":{"ostype":"l26","net0":"virtio=BC:24:11:43:86:D1,bridge=vmbr0"}}"#;
        let detail = parse_qemu_config(json).unwrap();
        assert_eq!(detail.static_ip, None);
    }

    #[test]
    fn parses_guest_agent_osinfo() {
        let json = r#"{"data":{"result":{
          "name":"Ubuntu",
          "pretty-name":"Ubuntu 24.04.5 LTS",
          "version-id":"24.04",
          "version":"24.04.5 LTS (Noble Numbat)",
          "id":"ubuntu"
        }}}"#;
        let (name, version) = parse_guest_agent_osinfo(json).unwrap();
        assert_eq!(name, "Ubuntu 24.04.5 LTS");
        assert_eq!(version.as_deref(), Some("24.04"));
        assert_eq!(parse_guest_agent_osinfo(r#"{"data":null}"#), None);
    }

    #[test]
    fn parses_guest_agent_fsinfo_sizes() {
        let json = r#"{"data":{"result":[
          {"name":"sda1","mountpoint":"/","type":"ext4","total-bytes":23826268160,"used-bytes":4626456576,
           "disk":[{"dev":"/dev/sda1"}]},
          {"name":"sda15","mountpoint":"/boot/efi","type":"vfat","total-bytes":0,"used-bytes":0}
        ]}}"#;
        let filesystems = parse_guest_agent_fsinfo(json).unwrap();
        assert_eq!(filesystems.len(), 1, "a zero-sized mount is dropped");
        let root = &filesystems[0];
        assert_eq!(root.mount, "/");
        assert_eq!(root.device.as_deref(), Some("/dev/sda1"));
        assert_eq!(root.fs_type.as_deref(), Some("ext4"));
        assert_eq!(root.size_kb, 23826268160 / 1024);
        assert_eq!(root.used_kb, Some(4626456576 / 1024));
        assert_eq!(root.available_kb, Some((23826268160 - 4626456576) / 1024));
        assert!(root.used_pct.is_some());
    }

    #[test]
    fn parses_node_storage_keeping_active_sized_datastores() {
        let json = r#"{"data":[
          {"storage":"local","type":"dir","active":1,"total":100861726720,"used":63545442304,"avail":32145547264},
          {"storage":"disabled","type":"dir","active":0,"total":1000,"used":1,"avail":999},
          {"storage":"empty","type":"dir","active":1,"total":0}
        ]}"#;
        let storages = parse_node_storage(json).unwrap();
        assert_eq!(storages.len(), 1);
        assert_eq!(storages[0].name, "local");
        assert_eq!(storages[0].storage_type.as_deref(), Some("dir"));
        assert_eq!(storages[0].total_bytes, 100861726720);
    }

    #[test]
    fn parse_size_kb_handles_proxmox_units() {
        assert_eq!(parse_size_kb("20G"), Some(20 * 1024 * 1024));
        assert_eq!(parse_size_kb("512M"), Some(512 * 1024));
        assert_eq!(parse_size_kb("8"), Some(0), "bare bytes divide by 1024");
        assert_eq!(parse_size_kb("2T"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size_kb("junk"), None);
    }

    #[test]
    fn qemu_ostype_maps_families() {
        assert_eq!(qemu_ostype_name(Some("l26")), Some("Linux".to_string()));
        assert_eq!(qemu_ostype_name(Some("win11")), Some("Windows".to_string()));
        assert_eq!(qemu_ostype_name(Some("other")), None);
        assert_eq!(qemu_ostype_name(None), None);
    }

    #[test]
    fn guest_resources_flag_templates() {
        let json = r#"{"data":[
          {"id":"qemu/9000","type":"qemu","vmid":9000,"node":"pve1","name":"gold","template":1},
          {"id":"qemu/100","type":"qemu","vmid":100,"node":"pve1","name":"web"}
        ]}"#;
        let guests = parse_guest_resources(json).unwrap();
        assert!(guests[0].template);
        assert!(!guests[1].template);
    }
}
