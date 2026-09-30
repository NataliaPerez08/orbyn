//! AWS adapter (Phase 5).
//!
//! Reads EC2 instances (and their elastic network interfaces) from the AWS
//! EC2 query API and normalizes them into Orbyn assets and interfaces.
//! Read-only: only `DescribeInstances` and a best-effort `GetCallerIdentity`
//! are issued.
//!
//! Requests are signed with SigV4 ([`sigv4`]) from credentials supplied by the
//! standard environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
//! `AWS_SESSION_TOKEN`) or flags. No credential is persisted; the signature
//! and the session token travel to curl on stdin, never in process arguments.
//!
//! An EC2 instance is imported when it has a private or public IP address.
//! Instances without one are skipped with a note.

pub mod sigv4;

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::domain::Interface;
use crate::integrations::cloud::{
    cloud_asset, parse_ip_cidr, CloudAdapter, CloudAsset, CloudInventory, CurlClient,
};
use crate::integrations::netbox::{url_origin, UrlOrigin};
use sigv4::sign_get;

/// EC2 API version.
const EC2_VERSION: &str = "2016-11-15";
/// STS API version.
const STS_VERSION: &str = "2011-06-15";
/// Maximum `DescribeInstances` pages followed.
const MAX_PAGES: usize = 100;
/// Maximum instances imported in one run.
const MAX_INSTANCES: usize = 100_000;

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

    /// Fetch EC2 instances and normalize them into a [`CloudInventory`].
    pub async fn fetch_inventory(&self) -> Result<CloudInventory> {
        let observed_at = Utc::now();
        let account = self.caller_identity().await;
        let mut inventory = CloudInventory::new("aws", account, Some(self.region.clone()));

        let mut next_token: Option<String> = None;
        let mut instances_seen = 0usize;
        for _page in 0..self.max_pages {
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
                self.import_instance(&instance, observed_at, &mut inventory);
            }

            match page.next_token {
                Some(token) => next_token = Some(token),
                None => return Ok(inventory),
            }
        }
        bail!("AWS DescribeInstances exceeded the {MAX_PAGES} page limit")
    }

    /// Normalize one instance into the inventory, or record why it was
    /// skipped.
    fn import_instance(
        &self,
        instance: &AwsInstance,
        observed_at: DateTime<Utc>,
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

#[async_trait]
impl CloudAdapter for AwsClient {
    fn provider(&self) -> &'static str {
        "aws"
    }

    async fn fetch(&self) -> Result<CloudInventory> {
        self.fetch_inventory().await
    }
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
    #[serde(rename = "code", default)]
    #[allow(dead_code)]
    code: Option<String>,
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

/// The default request timeout, re-exported for documentation.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

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
                code: Some("80".into()),
                name: Some("stopped".into()),
            },
            ..Default::default()
        };
        let mut inventory = CloudInventory::new("aws", None, Some("us-east-1".into()));
        client.import_instance(&instance, Utc::now(), &mut inventory);
        assert!(inventory.assets.is_empty());
        assert_eq!(inventory.skipped.len(), 1);
        assert!(inventory.skipped[0].contains("i-noip"));
    }
}
