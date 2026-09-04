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

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::domain::{Asset, Observation, Service};

use super::types::{Collector, ScanTarget};

pub struct NmapCollector {
    binary: String,
}

impl NmapCollector {
    pub fn new() -> Self {
        Self {
            binary: std::env::var("ORBYN_NMAP_BIN").unwrap_or_else(|_| "nmap".to_string()),
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

        let mut child = Command::new(&self.binary)
            .arg("-oX")
            .arg("-")
            .arg("-sV")
            .arg("--no-stylesheet")
            .arg(&target)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to start nmap; is it installed?")?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut out) = child.stdout.take() {
            out.read_to_string(&mut stdout)
                .await
                .context("failed reading nmap stdout")?;
        }
        if let Some(mut err) = child.stderr.take() {
            err.read_to_string(&mut stderr)
                .await
                .context("failed reading nmap stderr")?;
        }
        let status = child.wait().await.context("failed waiting for nmap")?;

        if !status.success() {
            return Err(anyhow!("nmap exited with {status}: {}", stderr.trim()));
        }

        Ok(self.parse_xml(&stdout)?)
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
                b"address" if ip.is_none() => {
                    if matches!(
                        get_attr(&e, b"addrtype")?.as_deref(),
                        Some("ipv4") | Some("ipv6")
                    ) {
                        if let Some(raw) = get_attr(&e, b"addr")? {
                            ip = raw.parse().ok();
                        }
                    }
                }
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
    let id = ip.to_string().replace(['.', ':'], "-");
    let mut observations = vec![Observation::Asset(Asset {
        id: id.clone(),
        ip,
        hostname,
        device_class: None,
        os_name,
        os_version: None,
        first_seen: now,
        last_seen: now,
    })];

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
                attr.unescape_value()
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

        assert_eq!(assets.len(), 1, "down host must be skipped");
        let asset = assets[0];
        assert_eq!(asset.id, "10-0-0-10");
        assert_eq!(asset.ip.to_string(), "10.0.0.10");
        assert_eq!(asset.hostname.as_deref(), Some("server-a.example.com"));
        assert_eq!(asset.os_name.as_deref(), Some("Linux 5.15.0-94-generic"));

        assert_eq!(services.len(), 2, "filtered port must be excluded");
        let ssh = services.iter().find(|s| s.port == 22).expect("port 22");
        assert_eq!(ssh.proto, "tcp");
        assert_eq!(ssh.name.as_deref(), Some("ssh"));
        assert_eq!(ssh.state, "open");
        assert_eq!(ssh.banner.as_deref(), Some("OpenSSH 8.9p1 Ubuntu"));

        let web = services.iter().find(|s| s.port == 443).expect("port 443");
        assert_eq!(web.name.as_deref(), Some("https"));
        assert_eq!(web.banner.as_deref(), Some("nginx 1.18.0"));
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
