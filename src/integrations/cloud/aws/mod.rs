//! AWS adapter (Phase 5).
//!
//! Reads EC2 instances (and their elastic network interfaces), EBS volumes,
//! VPCs and subnets from the AWS EC2 query API and normalizes them into Orbyn
//! assets, interfaces and filesystems. Read-only: only the `Describe*` actions
//! and a best-effort `GetCallerIdentity` are issued.
//!
//! Requests are signed with SigV4 ([`sigv4`]) from credentials supplied by the
//! standard environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
//! `AWS_SESSION_TOKEN`) or flags. No credential is persisted; the signature
//! and the session token travel to curl on stdin, never in process arguments.
//!
//! An EC2 instance is imported when it has a private or public IP address.
//! Instances without one are skipped with a note. EBS volumes become
//! filesystem rows on the instance they are attached to (an unattached volume
//! has no host and is skipped with a note). VPCs and subnets become assets
//! keyed by the network address of their CIDR, tagged with their provider id.

pub mod sigv4;

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::domain::{Filesystem, Interface};
use crate::integrations::cloud::{
    cloud_asset, host_header, network_address, network_asset_ip, parse_ip_cidr, CloudAsset,
    CloudInventory, CurlClient,
};
use crate::integrations::netbox::url_origin;
use sigv4::sign_get;

/// EC2 API version.
const EC2_VERSION: &str = "2016-11-15";
/// STS API version.
const STS_VERSION: &str = "2011-06-15";
/// Maximum `DescribeInstances` pages followed.
const MAX_PAGES: usize = 100;
/// Maximum instances imported in one run.
const MAX_INSTANCES: usize = 100_000;
/// Maximum EBS volumes imported in one run.
const MAX_VOLUMES: usize = 100_000;
/// Maximum VPCs imported in one run.
const MAX_VPCS: usize = 10_000;
/// Maximum subnets imported in one run.
const MAX_SUBNETS: usize = 100_000;

/// AWS credentials for signing requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsCredentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

impl AwsCredentials {
    /// Resolve credentials from the standard AWS environment variables.
    pub fn from_env() -> Option<Self> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
        if access_key.is_empty() || secret_key.is_empty() {
            return None;
        }
        Some(Self {
            access_key,
            secret_key,
            session_token: std::env::var("AWS_SESSION_TOKEN")
                .ok()
                .filter(|t| !t.is_empty()),
        })
    }
}

/// A parsed `DescribeInstances` page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Page {
    instances: Vec<AwsInstance>,
    next_token: Option<String>,
}

/// A read-only AWS EC2 client backed by the `curl` binary.
pub struct AwsClient {
    http: CurlClient,
    credentials: AwsCredentials,
    region: String,
    endpoint: String,
    host: String,
    max_pages: usize,
}

impl AwsClient {
    /// Create a client for `region`, optionally overriding the EC2 endpoint
    /// (useful for tests and private endpoints).
    pub fn new(
        credentials: AwsCredentials,
        region: &str,
        endpoint_override: Option<&str>,
        insecure: bool,
    ) -> Result<Self> {
        if region.is_empty()
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            bail!("invalid AWS region '{region}'");
        }
        let endpoint = match endpoint_override {
            Some(endpoint) => endpoint.trim_end_matches('/').to_string(),
            None => format!("https://ec2.{region}.amazonaws.com"),
        };
        let origin = url_origin(&endpoint).ok_or_else(|| {
            anyhow!(
                "invalid AWS endpoint '{endpoint}': expected an absolute http(s) \
                 URL without embedded credentials"
            )
        })?;
        let host = host_header(&origin);
        Ok(Self {
            http: CurlClient::new().insecure(insecure),
            credentials,
            region: region.to_string(),
            endpoint,
            host,
            max_pages: MAX_PAGES,
        })
    }

    /// Fetch EC2 instances, EBS volumes, VPCs and subnets and normalize them
    /// into a [`CloudInventory`].
    pub async fn fetch_inventory(&self) -> Result<CloudInventory> {
        let observed_at = Utc::now();
        let account = self.caller_identity().await;
        let mut inventory = CloudInventory::new("aws", account, Some(self.region.clone()));
        let mut instance_assets: HashMap<String, String> = HashMap::new();

        let mut next_token: Option<String> = None;
        let mut pages = 0usize;
        let mut instances_seen = 0usize;
        loop {
            let mut params = vec![
                ("Action".to_string(), "DescribeInstances".to_string()),
                ("Version".to_string(), EC2_VERSION.to_string()),
            ];
            if let Some(token) = &next_token {
                params.push(("NextToken".to_string(), token.clone()));
            }
            let (url, headers) = self.sign(&self.endpoint, &self.host, "ec2", &params);
            let xml = self.http.get(&url, &headers).await?;
            let page = parse_describe_instances(&xml)?;

            for instance in page.instances {
                instances_seen += 1;
                if instances_seen > MAX_INSTANCES {
                    bail!("AWS DescribeInstances exceeded the {MAX_INSTANCES} instance limit");
                }
                self.import_instance(&instance, observed_at, &mut instance_assets, &mut inventory);
            }

            match page.next_token {
                Some(token) => {
                    next_token = Some(token);
                    pages += 1;
                    if pages >= self.max_pages {
                        bail!(
                            "AWS DescribeInstances exceeded the {} page limit",
                            self.max_pages
                        );
                    }
                }
                None => break,
            }
        }

        self.import_volumes(&instance_assets, observed_at, &mut inventory)
            .await?;
        self.import_vpcs(observed_at, &mut inventory).await?;
        self.import_subnets(observed_at, &mut inventory).await?;
        Ok(inventory)
    }

    /// Normalize one instance into the inventory, or record why it was
    /// skipped. On success the instance id is recorded so volumes can be
    /// attached to it.
    fn import_instance(
        &self,
        instance: &AwsInstance,
        observed_at: DateTime<Utc>,
        instance_assets: &mut HashMap<String, String>,
        inventory: &mut CloudInventory,
    ) {
        let instance_id = instance.instance_id.as_deref().unwrap_or("(unknown)");
        let ip = instance
            .private_ip_address
            .as_deref()
            .and_then(parse_ip_cidr)
            .or_else(|| {
                instance
                    .public_ip_address
                    .as_deref()
                    .and_then(parse_ip_cidr)
            })
            .or_else(|| {
                instance
                    .network_interfaces()
                    .iter()
                    .find_map(|eni| eni.private_ip_address.as_deref().and_then(parse_ip_cidr))
            });
        let Some(ip) = ip else {
            inventory
                .skipped
                .push(format!("instance {instance_id} has no IP address"));
            return;
        };

        let hostname = instance
            .tag_value("Name")
            .or_else(|| instance.private_dns_name.clone())
            .filter(|n| !n.is_empty());

        let mut asset = cloud_asset(ip, hostname, "virtual-machine", observed_at);
        if instance.platform.as_deref() == Some("windows") {
            asset.os_name = Some("Windows".to_string());
        }

        let asset_id = asset.id.clone();
        instance_assets.insert(instance_id.to_string(), asset_id.clone());
        let mut tags = vec![format!("aws-instance:{instance_id}")];
        if let Some(kind) = &instance.instance_type {
            tags.push(format!("aws-type:{kind}"));
        }
        if let Some(state) = instance.state_name() {
            tags.push(format!("aws-state:{state}"));
        }
        for tag in &instance.tag_set.items {
            if let (Some(key), Some(value)) = (&tag.key, &tag.value) {
                if !key.is_empty() {
                    tags.push(format!("{key}={value}"));
                }
            }
        }

        inventory.assets.push(CloudAsset {
            asset,
            environment: None,
            owner: None,
            criticality: None,
            tags,
        });

        for eni in instance.network_interfaces() {
            let eni_ip = eni
                .private_ip_address
                .as_deref()
                .and_then(parse_ip_cidr)
                .or_else(|| eni.public_ip().and_then(parse_ip_cidr));
            let mut interface = Interface::new(
                &asset_id,
                eni.network_interface_id.as_deref(),
                eni.mac_address.as_deref(),
                eni_ip,
            );
            interface.is_up = Some(true);
            inventory.interfaces.push(interface);
        }
    }

    /// Run a paginated EC2 `Describe*` action, returning every item.
    async fn describe_all<T>(
        &self,
        action: &str,
        parse: impl Fn(&str) -> Result<(Vec<T>, Option<String>)>,
    ) -> Result<Vec<T>> {
        let mut items = Vec::new();
        let mut next_token: Option<String> = None;
        let mut pages = 0usize;
        loop {
            let mut params = vec![
                ("Action".to_string(), action.to_string()),
                ("Version".to_string(), EC2_VERSION.to_string()),
            ];
            if let Some(token) = &next_token {
                params.push(("NextToken".to_string(), token.clone()));
            }
            let (url, headers) = self.sign(&self.endpoint, &self.host, "ec2", &params);
            let xml = self.http.get(&url, &headers).await?;
            let (page_items, token) = parse(&xml)?;
            items.extend(page_items);
            match token {
                Some(token) => {
                    next_token = Some(token);
                    pages += 1;
                    if pages >= self.max_pages {
                        bail!("AWS {action} exceeded the {} page limit", self.max_pages);
                    }
                }
                None => return Ok(items),
            }
        }
    }

    /// Normalize EBS volumes into filesystems on their attached instance.
    async fn import_volumes(
        &self,
        instance_assets: &HashMap<String, String>,
        _observed_at: DateTime<Utc>,
        inventory: &mut CloudInventory,
    ) -> Result<()> {
        let volumes = self
            .describe_all("DescribeVolumes", parse_describe_volumes)
            .await?;
        if volumes.len() > MAX_VOLUMES {
            bail!("AWS DescribeVolumes exceeded the {MAX_VOLUMES} volume limit");
        }
        for volume in &volumes {
            let volume_id = volume.volume_id.as_deref().unwrap_or("(unknown)");
            let Some(attachment) = volume.attachment_set.items.first() else {
                inventory
                    .skipped
                    .push(format!("volume {volume_id} is not attached to an instance"));
                continue;
            };
            let Some(instance_id) = attachment.instance_id.as_deref() else {
                inventory
                    .skipped
                    .push(format!("volume {volume_id} has no instance attachment"));
                continue;
            };
            let Some(asset_id) = instance_assets.get(instance_id) else {
                inventory.skipped.push(format!(
                    "volume {volume_id} is attached to unknown instance {instance_id}"
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
                size_kb: volume.size_gib.unwrap_or(0) * 1024 * 1024,
                used_kb: None,
                available_kb: None,
                used_pct: None,
            });
            if let Some(asset) = inventory
                .assets
                .iter_mut()
                .find(|a| &a.asset.id == asset_id)
            {
                asset.tags.push(format!("aws-volume:{volume_id}"));
                if let Some(kind) = &volume.volume_type {
                    asset.tags.push(format!("aws-volume-type:{kind}"));
                }
            }
        }
        Ok(())
    }

    /// Normalize VPCs into assets keyed by the network address of their CIDR.
    async fn import_vpcs(
        &self,
        observed_at: DateTime<Utc>,
        inventory: &mut CloudInventory,
    ) -> Result<()> {
        let vpcs = self
            .describe_all("DescribeVpcs", parse_describe_vpcs)
            .await?;
        if vpcs.len() > MAX_VPCS {
            bail!("AWS DescribeVpcs exceeded the {MAX_VPCS} VPC limit");
        }
        let mut seen: HashSet<String> = inventory
            .assets
            .iter()
            .map(|a| a.asset.id.clone())
            .collect();
        for vpc in &vpcs {
            let vpc_id = vpc.vpc_id.as_deref().unwrap_or("(unknown)");
            let Some(cidr) = vpc.cidr_block.as_deref().filter(|c| !c.is_empty()) else {
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
                .tag_set
                .value("Name")
                .or_else(|| Some(vpc_id.to_string()));
            let asset = cloud_asset(address, hostname, "vpc", observed_at);
            let mut tags = vec![format!("aws-vpc:{vpc_id}"), format!("aws-cidr:{cidr}")];
            if address != network {
                tags.push(format!("aws-netaddr:{network}"));
            }
            if vpc.is_default {
                tags.push("aws-default-vpc".to_string());
            }
            tags.extend(tag_set_entries(&vpc.tag_set));
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
        observed_at: DateTime<Utc>,
        inventory: &mut CloudInventory,
    ) -> Result<()> {
        let subnets = self
            .describe_all("DescribeSubnets", parse_describe_subnets)
            .await?;
        if subnets.len() > MAX_SUBNETS {
            bail!("AWS DescribeSubnets exceeded the {MAX_SUBNETS} subnet limit");
        }
        let mut seen: HashSet<String> = inventory
            .assets
            .iter()
            .map(|a| a.asset.id.clone())
            .collect();
        for subnet in &subnets {
            let subnet_id = subnet.subnet_id.as_deref().unwrap_or("(unknown)");
            let Some(cidr) = subnet.cidr_block.as_deref().filter(|c| !c.is_empty()) else {
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
                .tag_set
                .value("Name")
                .or_else(|| Some(subnet_id.to_string()));
            let asset = cloud_asset(address, hostname, "subnet", observed_at);
            let mut tags = vec![
                format!("aws-subnet:{subnet_id}"),
                format!("aws-cidr:{cidr}"),
            ];
            if address != network {
                tags.push(format!("aws-netaddr:{network}"));
            }
            if let Some(vpc_id) = &subnet.vpc_id {
                tags.push(format!("aws-vpc:{vpc_id}"));
            }
            if let Some(az) = subnet
                .availability_zone
                .as_deref()
                .filter(|az| !az.is_empty())
            {
                tags.push(format!("aws-az:{az}"));
            }
            if let Some(free) = subnet.available_ip_address_count {
                tags.push(format!("aws-free-ips:{free}"));
            }
            tags.extend(tag_set_entries(&subnet.tag_set));
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

    /// Resolve the AWS account id via STS, best effort: provenance is useful
    /// but a missing or denied call must not fail the inventory import.
    async fn caller_identity(&self) -> Option<String> {
        let endpoint = format!("https://sts.{}.amazonaws.com", self.region);
        let host = format!("sts.{}.amazonaws.com", self.region);
        let params = vec![
            ("Action".to_string(), "GetCallerIdentity".to_string()),
            ("Version".to_string(), STS_VERSION.to_string()),
        ];
        let (url, headers) = self.sign(&endpoint, &host, "sts", &params);
        let xml = self.http.try_get(&url, &headers).await?;
        parse_caller_identity(&xml)
    }

    /// Sign a GET for `endpoint`/`service`, returning the full URL and
    /// headers.
    fn sign(
        &self,
        endpoint: &str,
        host: &str,
        service: &str,
        params: &[(String, String)],
    ) -> (String, Vec<String>) {
        let signed = sign_get(
            &self.credentials.access_key,
            &self.credentials.secret_key,
            self.credentials.session_token.as_deref(),
            &self.region,
            service,
            host,
            "/",
            params,
            Utc::now(),
        );
        let url = format!("{endpoint}/?{}", signed.query);
        (url, signed.headers)
    }
}

// --- XML response parsing -------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename = "DescribeInstancesResponse")]
struct DescribeInstancesDoc {
    #[serde(rename = "reservationSet", default)]
    reservation_set: ReservationSet,
    #[serde(rename = "nextToken", default)]
    next_token: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ReservationSet {
    #[serde(rename = "item", default)]
    items: Vec<Reservation>,
}

#[derive(Debug, Deserialize, Default)]
struct Reservation {
    #[serde(rename = "instancesSet", default)]
    instances_set: InstanceSet,
}

#[derive(Debug, Deserialize, Default)]
struct InstanceSet {
    #[serde(rename = "item", default)]
    items: Vec<AwsInstance>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct AwsInstance {
    #[serde(rename = "instanceId", default)]
    instance_id: Option<String>,
    #[serde(rename = "instanceType", default)]
    instance_type: Option<String>,
    #[serde(rename = "privateIpAddress", default)]
    private_ip_address: Option<String>,
    #[serde(rename = "ipAddress", default)]
    public_ip_address: Option<String>,
    #[serde(rename = "privateDnsName", default)]
    private_dns_name: Option<String>,
    #[serde(rename = "platform", default)]
    platform: Option<String>,
    #[serde(rename = "instanceState", default)]
    instance_state: InstanceState,
    #[serde(rename = "tagSet", default)]
    tag_set: TagSet,
    #[serde(rename = "networkInterfaceSet", default)]
    network_interface_set: NetworkInterfaceSet,
}

impl AwsInstance {
    /// The `instanceState/name` value (e.g. `running`), trimmed.
    fn state_name(&self) -> Option<String> {
        self.instance_state
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    /// The value of the first tag with the given key.
    fn tag_value(&self, key: &str) -> Option<String> {
        self.tag_set
            .items
            .iter()
            .find(|tag| tag.key.as_deref() == Some(key))
            .and_then(|tag| tag.value.clone())
            .filter(|v| !v.is_empty())
    }

    fn network_interfaces(&self) -> &[AwsEni] {
        &self.network_interface_set.items
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct InstanceState {
    #[serde(rename = "name", default)]
    name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct TagSet {
    #[serde(rename = "item", default)]
    items: Vec<TagItem>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct TagItem {
    #[serde(rename = "key", default)]
    key: Option<String>,
    #[serde(rename = "value", default)]
    value: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct NetworkInterfaceSet {
    #[serde(rename = "item", default)]
    items: Vec<AwsEni>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct AwsEni {
    #[serde(rename = "networkInterfaceId", default)]
    network_interface_id: Option<String>,
    #[serde(rename = "privateIpAddress", default)]
    private_ip_address: Option<String>,
    #[serde(rename = "macAddress", default)]
    mac_address: Option<String>,
    #[serde(rename = "association", default)]
    association: EniAssociation,
}

impl AwsEni {
    fn public_ip(&self) -> Option<&str> {
        self.association.public_ip.as_deref()
    }
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct EniAssociation {
    #[serde(rename = "publicIp", default)]
    public_ip: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "GetCallerIdentityResponse")]
struct CallerIdentityDoc {
    #[serde(rename = "GetCallerIdentityResult", default)]
    result: CallerIdentityResult,
}

#[derive(Debug, Deserialize, Default)]
struct CallerIdentityResult {
    #[serde(rename = "Account", default)]
    account: Option<String>,
}

/// Parse a `DescribeInstances` XML response.
fn parse_describe_instances(xml: &str) -> Result<Page> {
    let doc: DescribeInstancesDoc =
        quick_xml::de::from_str(xml).context("parsing AWS DescribeInstances response")?;
    let mut instances = Vec::new();
    for reservation in doc.reservation_set.items {
        instances.extend(reservation.instances_set.items);
    }
    Ok(Page {
        instances,
        next_token: doc
            .next_token
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty()),
    })
}

/// Extract the account id from a `GetCallerIdentity` XML response.
fn parse_caller_identity(xml: &str) -> Option<String> {
    let doc: CallerIdentityDoc = quick_xml::de::from_str(xml).ok()?;
    doc.result
        .account
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
}

/// The `key=value` renderings of a tag set, skipping empty keys.
fn tag_set_entries(tag_set: &TagSet) -> Vec<String> {
    tag_set
        .items
        .iter()
        .filter_map(|tag| {
            let key = tag.key.as_deref().filter(|k| !k.is_empty())?;
            Some(format!("{key}={}", tag.value.as_deref().unwrap_or("")))
        })
        .collect()
}

impl TagSet {
    /// The value of the first tag with the given key.
    fn value(&self, key: &str) -> Option<String> {
        self.items
            .iter()
            .find(|tag| tag.key.as_deref() == Some(key))
            .and_then(|tag| tag.value.clone())
            .filter(|v| !v.is_empty())
    }
}

fn clean_token(token: Option<String>) -> Option<String> {
    token
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

// --- EBS volumes ----------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename = "DescribeVolumesResponse")]
struct DescribeVolumesDoc {
    #[serde(rename = "volumeSet", default)]
    volume_set: VolumeSet,
    #[serde(rename = "nextToken", default)]
    next_token: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct VolumeSet {
    #[serde(rename = "item", default)]
    items: Vec<AwsVolume>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct AwsVolume {
    #[serde(rename = "volumeId", default)]
    volume_id: Option<String>,
    #[serde(rename = "size", default)]
    size_gib: Option<u64>,
    #[serde(rename = "volumeType", default)]
    volume_type: Option<String>,
    #[serde(rename = "attachmentSet", default)]
    attachment_set: VolumeAttachmentSet,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct VolumeAttachmentSet {
    #[serde(rename = "item", default)]
    items: Vec<VolumeAttachment>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct VolumeAttachment {
    #[serde(rename = "instanceId", default)]
    instance_id: Option<String>,
    #[serde(rename = "device", default)]
    device: Option<String>,
}

fn parse_describe_volumes(xml: &str) -> Result<(Vec<AwsVolume>, Option<String>)> {
    let doc: DescribeVolumesDoc =
        quick_xml::de::from_str(xml).context("parsing AWS DescribeVolumes response")?;
    Ok((doc.volume_set.items, clean_token(doc.next_token)))
}

// --- VPCs -----------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename = "DescribeVpcsResponse")]
struct DescribeVpcsDoc {
    #[serde(rename = "vpcSet", default)]
    vpc_set: VpcSet,
    #[serde(rename = "nextToken", default)]
    next_token: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct VpcSet {
    #[serde(rename = "item", default)]
    items: Vec<AwsVpc>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct AwsVpc {
    #[serde(rename = "vpcId", default)]
    vpc_id: Option<String>,
    #[serde(rename = "cidrBlock", default)]
    cidr_block: Option<String>,
    #[serde(rename = "isDefault", default)]
    is_default: bool,
    #[serde(rename = "tagSet", default)]
    tag_set: TagSet,
}

fn parse_describe_vpcs(xml: &str) -> Result<(Vec<AwsVpc>, Option<String>)> {
    let doc: DescribeVpcsDoc =
        quick_xml::de::from_str(xml).context("parsing AWS DescribeVpcs response")?;
    Ok((doc.vpc_set.items, clean_token(doc.next_token)))
}

// --- Subnets --------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename = "DescribeSubnetsResponse")]
struct DescribeSubnetsDoc {
    #[serde(rename = "subnetSet", default)]
    subnet_set: SubnetSet,
    #[serde(rename = "nextToken", default)]
    next_token: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct SubnetSet {
    #[serde(rename = "item", default)]
    items: Vec<AwsSubnet>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
struct AwsSubnet {
    #[serde(rename = "subnetId", default)]
    subnet_id: Option<String>,
    #[serde(rename = "vpcId", default)]
    vpc_id: Option<String>,
    #[serde(rename = "cidrBlock", default)]
    cidr_block: Option<String>,
    #[serde(rename = "availabilityZone", default)]
    availability_zone: Option<String>,
    #[serde(rename = "availableIpAddressCount", default)]
    available_ip_address_count: Option<u64>,
    #[serde(rename = "tagSet", default)]
    tag_set: TagSet,
}

fn parse_describe_subnets(xml: &str) -> Result<(Vec<AwsSubnet>, Option<String>)> {
    let doc: DescribeSubnetsDoc =
        quick_xml::de::from_str(xml).context("parsing AWS DescribeSubnets response")?;
    Ok((doc.subnet_set.items, clean_token(doc.next_token)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTANCES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
  <reservationSet>
    <item>
      <reservationId>r-001</reservationId>
      <instancesSet>
        <item>
          <instanceId>i-1234567890abcdef0</instanceId>
          <instanceType>t3.micro</instanceType>
          <instanceState><code>16</code><name>running</name></instanceState>
          <privateIpAddress>10.0.0.5</privateIpAddress>
          <privateDnsName>ip-10-0-0-5.ec2.internal</privateDnsName>
          <platform>windows</platform>
          <tagSet>
            <item><key>Name</key><value>web-01</value></item>
            <item><key>env</key><value>prod</value></item>
          </tagSet>
          <networkInterfaceSet>
            <item>
              <networkInterfaceId>eni-0abc</networkInterfaceId>
              <privateIpAddress>10.0.0.5</privateIpAddress>
              <macAddress>0a:1b:2c:3d:4e:5f</macAddress>
              <association><publicIp>203.0.113.5</publicIp></association>
            </item>
          </networkInterfaceSet>
        </item>
        <item>
          <instanceId>i-noip</instanceId>
          <instanceState><code>80</code><name>stopped</name></instanceState>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
  <nextToken>page-2-token</nextToken>
</DescribeInstancesResponse>"#;

    #[test]
    fn parses_instances_and_next_token() {
        let page = parse_describe_instances(INSTANCES_XML).expect("parse");
        assert_eq!(page.instances.len(), 2);
        assert_eq!(page.next_token.as_deref(), Some("page-2-token"));
        let first = &page.instances[0];
        assert_eq!(first.instance_id.as_deref(), Some("i-1234567890abcdef0"));
        assert_eq!(first.instance_type.as_deref(), Some("t3.micro"));
        assert_eq!(first.private_ip_address.as_deref(), Some("10.0.0.5"));
        assert_eq!(first.platform.as_deref(), Some("windows"));
        assert_eq!(first.state_name().as_deref(), Some("running"));
        assert_eq!(first.tag_value("Name").as_deref(), Some("web-01"));
        assert_eq!(first.network_interfaces().len(), 1);
        assert_eq!(
            first.network_interfaces()[0].mac_address.as_deref(),
            Some("0a:1b:2c:3d:4e:5f")
        );
        assert_eq!(
            first.network_interfaces()[0].public_ip(),
            Some("203.0.113.5")
        );
        let second = &page.instances[1];
        assert_eq!(second.private_ip_address, None);
        assert_eq!(second.state_name().as_deref(), Some("stopped"));
    }

    #[test]
    fn parses_empty_instance_set() {
        let xml = r#"<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><reservationSet/></DescribeInstancesResponse>"#;
        let page = parse_describe_instances(xml).expect("parse");
        assert!(page.instances.is_empty());
        assert_eq!(page.next_token, None);
    }

    #[test]
    fn parses_caller_identity_account() {
        let xml = r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
          <GetCallerIdentityResult>
            <Arn>arn:aws:iam::123456789012:user/ops</Arn>
            <UserId>AIDAEXAMPLE</UserId>
            <Account>123456789012</Account>
          </GetCallerIdentityResult>
          <ResponseMetadata><RequestId>abc</RequestId></ResponseMetadata>
        </GetCallerIdentityResponse>"#;
        assert_eq!(parse_caller_identity(xml).as_deref(), Some("123456789012"));
    }

    #[test]
    fn host_header_includes_non_default_ports_only() {
        assert_eq!(
            host_header(&url_origin("https://ec2.us-east-1.amazonaws.com").unwrap()),
            "ec2.us-east-1.amazonaws.com"
        );
        assert_eq!(
            host_header(&url_origin("https://ec2.example.com:8443").unwrap()),
            "ec2.example.com:8443"
        );
        assert_eq!(
            host_header(&url_origin("http://127.0.0.1:9000").unwrap()),
            "127.0.0.1:9000"
        );
    }

    #[test]
    fn client_validates_region_and_endpoint() {
        let creds = AwsCredentials {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: "secret".into(),
            session_token: None,
        };
        assert!(AwsClient::new(creds.clone(), "us-east-1", None, false).is_ok());
        assert!(AwsClient::new(creds.clone(), "US-EAST-1", None, false).is_err());
        assert!(AwsClient::new(creds.clone(), "us east 1", None, false).is_err());
        assert!(AwsClient::new(
            creds.clone(),
            "us-east-1",
            Some("http://127.0.0.1:9000"),
            false
        )
        .is_ok());
        assert!(AwsClient::new(
            creds,
            "us-east-1",
            Some("https://user@evil.example.com"),
            false
        )
        .is_err());
    }

    #[test]
    fn skipped_instances_without_ip_are_reported() {
        let creds = AwsCredentials {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: "secret".into(),
            session_token: None,
        };
        let client = AwsClient::new(creds, "us-east-1", None, false).unwrap();
        let instance = AwsInstance {
            instance_id: Some("i-noip".into()),
            instance_state: InstanceState {
                name: Some("stopped".into()),
            },
            ..Default::default()
        };
        let mut inventory = CloudInventory::new("aws", None, Some("us-east-1".into()));
        let mut instance_assets = HashMap::new();
        client.import_instance(&instance, Utc::now(), &mut instance_assets, &mut inventory);
        assert!(inventory.assets.is_empty());
        assert_eq!(inventory.skipped.len(), 1);
        assert!(inventory.skipped[0].contains("i-noip"));
    }

    #[test]
    fn parses_volumes_vpcs_and_subnets() {
        let volumes = r#"<DescribeVolumesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">
          <volumeSet>
            <item>
              <volumeId>vol-111</volumeId>
              <size>100</size>
              <volumeType>gp3</volumeType>
              <attachmentSet>
                <item><volumeId>vol-111</volumeId><instanceId>i-111</instanceId><device>/dev/xvdf</device><state>attached</state></item>
              </attachmentSet>
            </item>
            <item>
              <volumeId>vol-detached</volumeId>
              <size>8</size>
              <volumeType>gp2</volumeType>
              <attachmentSet/>
            </item>
          </volumeSet>
          <nextToken>vol-page-2</nextToken>
        </DescribeVolumesResponse>"#;
        let (items, token) = parse_describe_volumes(volumes).expect("parse volumes");
        assert_eq!(items.len(), 2);
        assert_eq!(token.as_deref(), Some("vol-page-2"));
        assert_eq!(items[0].volume_id.as_deref(), Some("vol-111"));
        assert_eq!(items[0].size_gib, Some(100));
        assert_eq!(items[0].attachment_set.items.len(), 1);
        assert_eq!(
            items[0].attachment_set.items[0].device.as_deref(),
            Some("/dev/xvdf")
        );
        assert!(items[1].attachment_set.items.is_empty());

        let vpcs = r#"<DescribeVpcsResponse>
          <vpcSet><item><vpcId>vpc-1</vpcId><cidrBlock>10.10.0.0/16</cidrBlock><isDefault>true</isDefault>
            <tagSet><item><key>Name</key><value>main</value></item></tagSet></item></vpcSet>
        </DescribeVpcsResponse>"#;
        let (items, token) = parse_describe_vpcs(vpcs).expect("parse vpcs");
        assert_eq!(items.len(), 1);
        assert_eq!(token, None);
        assert!(items[0].is_default);
        assert_eq!(items[0].tag_set.value("Name").as_deref(), Some("main"));

        let subnets = r#"<DescribeSubnetsResponse>
          <subnetSet><item><subnetId>subnet-1</subnetId><vpcId>vpc-1</vpcId>
            <cidrBlock>10.10.1.0/24</cidrBlock><availabilityZone>eu-west-1a</availabilityZone>
            <availableIpAddressCount>250</availableIpAddressCount></item></subnetSet>
        </DescribeSubnetsResponse>"#;
        let (items, _) = parse_describe_subnets(subnets).expect("parse subnets");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].available_ip_address_count, Some(250));
    }
}
