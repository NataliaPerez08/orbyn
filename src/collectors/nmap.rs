//! Nmap collector (v0.1 milestone).
//!
//! Executes `nmap` as an external process and parses its XML output into
//! normalized [`crate::domain::Observation`]s.
//!
//! Security rules:
//! - targets are passed as process arguments, never shell-interpolated;
//! - the scan runs read-only (`-sS -sV` style, no destructive options);
//! - scope is validated before execution.

use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use tokio::process::Command;

use crate::domain::{asset_id, Asset, Interface, Observation, Service};
use crate::process::{run_captured, MAX_STDERR_CAPTURE_BYTES, MAX_STDOUT_CAPTURE_BYTES};

use super::classify::classify_device;
use super::types::{Collector, ScanTarget};

/// Default whole-process timeout for an nmap run. Generous on purpose: wide
/// authorized CIDR scopes (down to /1 with `--allow-large-cidr`) make `-sV`
/// probes slow. Override with `ORBYN_NMAP_TIMEOUT_SECS`.
const DEFAULT_NMAP_TIMEOUT_SECS: u64 = 1800;

pub struct NmapCollector {
    binary: String,
    timeout: Duration,
}

impl NmapCollector {
    pub fn new() -> Self {
        Self {
            binary: std::env::var("ORBYN_NMAP_BIN").unwrap_or_else(|_| "nmap".to_string()),
            timeout: nmap_timeout_from_env(),
        }
    }

    /// Parse Nmap XML into observations. Kept as a method so it can be tested
    /// against recorded fixtures without invoking the real binary.
    pub fn parse_xml(&self, xml: &str) -> Result<Vec<Observation>> {
        parse_nmap_xml(xml)
    }
}

#[async_trait]
impl Collector for NmapCollector {
    fn name(&self) -> &'static str {
        "nmap"
    }

    async fn scan(&self, target: &ScanTarget) -> Result<Vec<Observation>> {
        let target = match target {
            ScanTarget::Ip(ip) => ip.to_string(),
            ScanTarget::Cidr(cidr) => cidr.clone(),
        };

        let child = Command::new(&self.binary)
            .arg("-oX")
            .arg("-")
            .arg("-sV")
            .arg("--no-stylesheet")
            .arg(&target)
            .env_remove("ORBYN_SNMP_COMMUNITY")
            .env_remove("ORBYN_NETBOX_TOKEN")
            .env_remove("ORBYN_WINRM_PASSWORD")
            .env_remove("ORBYN_DB")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("failed to start nmap; is it installed?")?;

        let captured = run_captured(
            child,
            None,
            MAX_STDOUT_CAPTURE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
            self.timeout,
            format!(
                "nmap timed out against {target} after {}s \
                 (adjust with ORBYN_NMAP_TIMEOUT_SECS)",
                self.timeout.as_secs()
            ),
        )
        .await?;

        if !captured.status.success() {
            return Err(anyhow!(
                "nmap exited with {}: {}",
                captured.status,
                captured.stderr.trim()
            ));
        }
        if captured.stdout_truncated {
            return Err(anyhow!(
                "nmap XML output exceeded the {} byte capture limit; \
                 scan a narrower CIDR so the report stays parseable",
                MAX_STDOUT_CAPTURE_BYTES
            ));
        }

        Ok(self.parse_xml(&captured.stdout)?)
    }
}

/// Resolve the nmap lifecycle timeout from `ORBYN_NMAP_TIMEOUT_SECS`,
/// falling back to (and warning about) the default on invalid values.
fn nmap_timeout_from_env() -> Duration {
    match std::env::var("ORBYN_NMAP_TIMEOUT_SECS") {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => {
                tracing::warn!(
                    "invalid ORBYN_NMAP_TIMEOUT_SECS '{raw}'; \
                     using the {DEFAULT_NMAP_TIMEOUT_SECS}s default"
                );
                Duration::from_secs(DEFAULT_NMAP_TIMEOUT_SECS)
            }
        },
        Err(_) => Duration::from_secs(DEFAULT_NMAP_TIMEOUT_SECS),
    }
}

impl Default for NmapCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an Nmap XML document into normalized observations.
fn parse_nmap_xml(xml: &str) -> Result<Vec<Observation>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut observations = Vec::new();
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) if e.name().as_ref() == b"host" => {
                if let Some(mut host) = parse_host(&mut reader)? {
                    observations.append(&mut host);
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(anyhow!("invalid Nmap XML: {e}")),
        }
    }
    Ok(observations)
}

/// A port collected while parsing a host element.
struct Port {
    proto: String,
    portid: u16,
    state: Option<String>,
    name: Option<String>,
    banner: Option<String>,
}

/// Parse a single `<host>` element (consuming through `</host>`).
///
/// Returns `None` for hosts that carry no usable address (e.g. hosts reported
/// as down), otherwise the asset observation plus one service observation per
/// open port.
fn parse_host(reader: &mut Reader<&[u8]>) -> Result<Option<Vec<Observation>>> {
    let mut ip: Option<IpAddr> = None;
    let mut hostname: Option<String> = None;
    let mut os_name: Option<String> = None;
    let mut mac: Option<String> = None;
    let mut mac_vendor: Option<String> = None;
    let mut ports: Vec<Port> = Vec::new();
    let mut in_os_tag = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"port" => ports.push(parse_port(&e)?),
                b"os" => in_os_tag = true,
                b"osmatch" if in_os_tag && os_name.is_none() => {
                    os_name = get_attr(&e, b"name")?;
                }
                _ => {}
            },
            Ok(Event::Empty(e)) => match e.name().as_ref() {
                b"address" => match get_attr(&e, b"addrtype")?.as_deref() {
                    Some("ipv4") | Some("ipv6") if ip.is_none() => {
                        if let Some(raw) = get_attr(&e, b"addr")? {
                            ip = raw.parse().ok();
                        }
                    }
                    Some("mac") if mac.is_none() => {
                        mac = get_attr(&e, b"addr")?;
                        mac_vendor = get_attr(&e, b"vendor")?;
                    }
                    _ => {}
                },
                b"hostname" if hostname.is_none() => {
                    hostname = get_attr(&e, b"name")?;
                }
                b"state" => {
                    if let Some(port) = ports.last_mut() {
                        port.state = get_attr(&e, b"state")?;
                    }
                }
                b"service" => {
                    if let Some(port) = ports.last_mut() {
                        port.name = get_attr(&e, b"name")?;
                        port.banner = banner(get_attr(&e, b"product")?, get_attr(&e, b"version")?);
                    }
                }
                b"osmatch" if os_name.is_none() => {
                    os_name = get_attr(&e, b"name")?;
                }
                _ => {}
            },
            Ok(Event::End(e)) if e.name().as_ref() == b"host" => break,
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(anyhow!("invalid Nmap XML: {e}")),
        }
    }

    let ip = match ip {
        Some(ip) => ip,
        None => return Ok(None),
    };

    let now = Utc::now();
    let id = asset_id(ip);
    let open_services: Vec<&str> = ports
        .iter()
        .filter(|p| p.state.as_deref() == Some("open"))
        .filter_map(|p| p.name.as_deref())
        .collect();
    let device_class = classify_device(
        os_name.as_deref(),
        mac_vendor.as_deref(),
        &open_services,
        None,
    );

    let mut observations = vec![Observation::Asset(Asset {
        id: id.clone(),
        ip,
        hostname,
        device_class,
        os_name,
        os_version: None,
        sys_descr: None,
        environment: None,
        owner: None,
        criticality: None,
        tags: Vec::new(),
        first_seen: now,
        last_seen: now,
    })];

    if mac.is_some() {
        observations.push(Observation::Interface(Interface {
            id: crate::domain::interface_id(&id, None, mac.as_deref(), Some(ip)),
            asset_id: id.clone(),
            name: None,
            mac: mac.as_deref().and_then(crate::domain::normalize_mac),
            ip: Some(ip),
            vendor: mac_vendor,
            mtu: None,
            if_index: None,
            is_up: None,
        }));
    }

    for port in ports {
        if port.state.as_deref() != Some("open") {
            continue;
        }
        observations.push(Observation::Service(Service {
            asset_id: id.clone(),
            proto: port.proto,
            port: port.portid,
            name: port.name,
            state: port.state.unwrap_or_default(),
            banner: port.banner,
        }));
    }

    Ok(Some(observations))
}

/// Extract protocol and port id from a `<port>` opening tag.
fn parse_port(e: &BytesStart<'_>) -> Result<Port> {
    let proto = get_attr(e, b"protocol")?.unwrap_or_default();
    let portid = get_attr(e, b"portid")?
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    Ok(Port {
        proto,
        portid,
        state: None,
        name: None,
        banner: None,
    })
}

fn banner(product: Option<String>, version: Option<String>) -> Option<String> {
    match (product, version) {
        (Some(p), Some(v)) => Some(format!("{p} {v}")),
        (Some(p), None) | (None, Some(p)) => Some(p),
        (None, None) => None,
    }
}

/// Read a single attribute value from an element.
fn get_attr(e: &BytesStart<'_>, key: &[u8]) -> Result<Option<String>> {
    for attr in e.attributes() {
        let attr = attr.context("reading XML attribute")?;
        if attr.key.as_ref() == key {
            return Ok(Some(
                attr.decoded_and_normalized_value(quick_xml::XmlVersion::Implicit1_0, e.decoder())
                    .context("unescaping XML attribute")?
                    .into_owned(),
            ));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX - -sV 10.0.0.10" start="1700000000" version="7.94" xmloutputversion="1.04">
<scaninfo type="connect" protocol="tcp" numservices="1000" services="1-1000"/>
<host starttime="1700000000" endtime="1700000001">
<status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="10.0.0.10" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Intel"/>
<hostnames>
<hostname name="server-a.example.com" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="https" product="nginx" version="1.18.0" method="probed" conf="10"/>
</port>
<port protocol="tcp" portid="3306">
<state state="filtered" reason="no-response" reason_ttl="0"/>
</port>
</ports>
<os>
<osmatch name="Linux 5.15.0-94-generic" accuracy="98" line="12345">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.x" accuracy="98"/>
</osmatch>
</os>
<times srtt="1000" rttvar="100" to="100000"/>
</host>
<host starttime="1700000002" endtime="1700000003">
<status state="down" reason="no-response" reason_ttl="0"/>
</host>
</nmaprun>
"#;

    #[test]
    fn parses_hosts_ports_and_os() {
        let collector = NmapCollector::new();
        let observations = collector.parse_xml(FIXTURE).expect("valid fixture");

        let assets: Vec<&Asset> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::Asset(a) => Some(a),
                _ => None,
            })
            .collect();
        let services: Vec<&Service> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::Service(s) => Some(s),
                _ => None,
            })
            .collect();
        let interfaces: Vec<&Interface> = observations
            .iter()
            .filter_map(|o| match o {
                Observation::Interface(i) => Some(i),
                _ => None,
            })
            .collect();

        assert_eq!(assets.len(), 1, "down host must be skipped");
        let asset = assets[0];
        assert_eq!(asset.id, "10-0-0-10");
        assert_eq!(asset.ip.to_string(), "10.0.0.10");
        assert_eq!(asset.hostname.as_deref(), Some("server-a.example.com"));
        assert_eq!(asset.os_name.as_deref(), Some("Linux 5.15.0-94-generic"));
        assert_eq!(asset.device_class.as_deref(), Some("server"));

        assert_eq!(services.len(), 2, "filtered port must be excluded");
        let ssh = services.iter().find(|s| s.port == 22).expect("port 22");
        assert_eq!(ssh.proto, "tcp");
        assert_eq!(ssh.name.as_deref(), Some("ssh"));
        assert_eq!(ssh.state, "open");
        assert_eq!(ssh.banner.as_deref(), Some("OpenSSH 8.9p1 Ubuntu"));

        let web = services.iter().find(|s| s.port == 443).expect("port 443");
        assert_eq!(web.name.as_deref(), Some("https"));
        assert_eq!(web.banner.as_deref(), Some("nginx 1.18.0"));

        assert_eq!(interfaces.len(), 1);
        let iface = interfaces[0];
        assert_eq!(iface.asset_id, "10-0-0-10");
        assert_eq!(iface.mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(iface.vendor.as_deref(), Some("Intel"));
        assert_eq!(iface.ip, Some("10.0.0.10".parse().unwrap()));
    }

    #[test]
    fn rejects_malformed_xml() {
        let collector = NmapCollector::new();
        assert!(collector
            .parse_xml(r#"<nmaprun version="unterminated"#)
            .is_err());
    }

    #[test]
    fn empty_run_produces_no_observations() {
        let collector = NmapCollector::new();
        let observations = collector
            .parse_xml("<nmaprun></nmaprun>")
            .expect("empty run is valid XML");
        assert!(observations.is_empty());
    }
}
