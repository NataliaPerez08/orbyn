//! Native TCP-connect collector (ROADMAP_V2 v1.4).
//!
//! Discovers hosts and open TCP ports without Nmap: a bounded top-ports
//! sweep using plain `TcpStream::connect`, plus a short banner read on open
//! sockets. No raw sockets, no privileges, no external binaries *required*.
//!
//! Optional accelerators, all fail-open (a missing tool never fails or
//! narrows a scan):
//! - ICMP liveness prefetch via the system `ping` (multi-host targets only):
//!   a clean no-reply skips the port sweep, matching nmap's default
//!   host-discovery semantics; ping errors/absence sweep anyway. Disable
//!   with `ORBYN_NATIVE_LIVENESS=0`.
//! - reverse DNS (PTR) for live hosts via `dig` (`dns::resolve_ptr`),
//!   disabled with `ORBYN_NATIVE_REVERSE_DNS=0`.
//!
//! UDP top-ports sweep (beyond the nmap baseline, which is TCP-only):
//! unprivileged connected-datagram probes — an ICMP port-unreachable
//! reads as closed (no observation), a response reads as open, silence
//! reads as `open|filtered`, never a bare `open` claim from silence
//! (plan §9: don't overstate states). Disable with
//! `ORBYN_NATIVE_UDP=0`.
//!
//! Documented differences vs the nmap adapter (ADR-0001, BASELINE_AUDIT G-2/G-3):
//! - liveness is ICMP-only (nmap also probes TCP 80/443); fail-open on errors;
//! - service identification is passive banners plus the versioned
//!   `fingerprint` probes (`native-fingerprints/v1`: HTTP `GET`, TLS
//!   handshake) — no full `-sV` probe cascade, no OS inference;
//! - CIDR expansions beyond `max_hosts` are refused with an error instead of
//!   attempted (IPv6 ranges are effectively limited to tiny prefixes).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::Utc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::task::JoinSet;

use crate::domain::{asset_id, Asset, Observation, Service};
use crate::process::{run_captured, MAX_STDERR_CAPTURE_BYTES};

use super::classify::classify_device;
use super::dns;
use super::fingerprint;
use super::types::{Collector, ScanTarget};

/// Whole-sweep connect timeout per (host, port) attempt.
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 1500;
/// How long to wait for a service banner on an open socket.
const BANNER_TIMEOUT_MS: u64 = 2000;
/// Concurrent connect attempts within one host sweep.
const DEFAULT_CONCURRENCY: usize = 128;
/// Hard cap on CIDR expansion (matches the default IPv4 /16 scope floor).
const DEFAULT_MAX_HOSTS: u64 = 65_536;
/// Whole-process cap for one `ping` liveness probe.
const PING_TIMEOUT: Duration = Duration::from_secs(3);
const PING_STDOUT_CAP: u64 = 4 * 1024;

/// Top TCP ports swept by default. A curated common-enterprise subset of
/// nmap's default list; deep enumeration stays on the nmap adapter.
const TOP_TCP_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445, 465,
    500, 512, 513, 514, 587, 623, 636, 873, 993, 995, 1080, 1099, 1433, 1521, 2049, 2181, 2375,
    2376, 2381, 3000, 3128, 3260, 3306, 3389, 4443, 5000, 5432, 5555, 5601, 5672, 5900, 5984, 5985,
    5986, 6000, 6379, 6443, 6667, 8000, 8008, 8009, 8080, 8081, 8443, 8844, 8888, 9000, 9001, 9042,
    9090, 9092, 9200, 9300, 9418, 9676, 9999, 10000, 11211, 15672, 16686, 27017, 27018, 27019,
    28017, 32400, 33060, 50000, 54310, 55555,
];

/// Well-known service names for swept ports (subset of the IANA table that
/// matters for classification).
const SERVICE_NAMES: &[(u16, &str)] = &[
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "domain"),
    (80, "http"),
    (110, "pop3"),
    (111, "rpcbind"),
    (123, "ntp"),
    (135, "msrpc"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (161, "snmp"),
    (389, "ldap"),
    (443, "https"),
    (445, "microsoft-ds"),
    (465, "smtps"),
    (500, "isakmp"),
    (512, "exec"),
    (513, "login"),
    (514, "shell"),
    (587, "submission"),
    (623, "ipmi"),
    (636, "ldaps"),
    (873, "rsync"),
    (993, "imaps"),
    (995, "pop3s"),
    (1080, "socks"),
    (1099, "rmiregistry"),
    (1433, "ms-sql-s"),
    (1521, "oracle"),
    (2049, "nfs"),
    (2181, "livelink"),
    (2375, "docker"),
    (2376, "docker-tls"),
    (3000, "http"),
    (3128, "http-proxy"),
    (3260, "iscsi"),
    (3306, "mysql"),
    (3389, "ms-wbt-server"),
    (4443, "https"),
    (5000, "upnp"),
    (5432, "postgresql"),
    (5601, "http"),
    (5672, "amqp"),
    (5900, "vnc"),
    (5984, "couchdb"),
    (5985, "winrm-http"),
    (5986, "winrm-https"),
    (6000, "x11"),
    (6379, "redis"),
    (6443, "https"),
    (6667, "irc"),
    (8000, "http"),
    (8008, "http"),
    (8009, "http-alt"),
    (8080, "http-proxy"),
    (8081, "http-proxy"),
    (8443, "https-alt"),
    (8844, "https-alt"),
    (8888, "http-alt"),
    (9000, "cslistener"),
    (9001, "etlservicemgr"),
    (9042, "http"),
    (9090, "websm"),
    (9200, "elasticsearch"),
    (9300, "elasticsearch"),
    (11211, "memcached"),
    (15672, "http"),
    (27017, "mongodb"),
    (33060, "mysqlx"),
    (50000, "sap"),
];

/// Top UDP ports swept by default: discovery-relevant datagram services
/// (SNMP enrichment, time, name services, management protocols).
const TOP_UDP_PORTS: &[u16] = &[53, 123, 137, 161, 500, 514, 1900, 5353];

/// Well-known service names for the swept UDP ports.
const UDP_SERVICE_NAMES: &[(u16, &str)] = &[
    (53, "domain"),
    (123, "ntp"),
    (137, "netbios-ns"),
    (161, "snmp"),
    (500, "isakmp"),
    (514, "syslog"),
    (1900, "upnp"),
    (5353, "zeroconf"),
];

pub struct NativeCollector {
    connect_timeout: Duration,
    concurrency: usize,
    max_hosts: u64,
    ports: Vec<u16>,
    /// ICMP liveness prefetch via the system `ping` (multi-host targets).
    liveness: bool,
    ping_bin: String,
    /// PTR hostname lookup for live hosts via `dig`.
    reverse_dns: bool,
    /// Random 0..jitter pause before each host sweep (pacing knob).
    jitter: Duration,
    /// UDP top-ports sweep (conservative `open|filtered` states).
    udp: bool,
    udp_ports: Vec<u16>,
}

impl NativeCollector {
    pub fn new() -> Self {
        Self {
            connect_timeout: Duration::from_millis(env_num(
                "ORBYN_NATIVE_CONNECT_TIMEOUT_MS",
                DEFAULT_CONNECT_TIMEOUT_MS,
            )),
            concurrency: env_num("ORBYN_NATIVE_CONCURRENCY", DEFAULT_CONCURRENCY as u64) as usize,
            max_hosts: env_num("ORBYN_NATIVE_MAX_HOSTS", DEFAULT_MAX_HOSTS),
            ports: TOP_TCP_PORTS.to_vec(),
            liveness: env_bool("ORBYN_NATIVE_LIVENESS", true),
            ping_bin: std::env::var("ORBYN_PING_BIN").unwrap_or_else(|_| "ping".to_string()),
            reverse_dns: env_bool("ORBYN_NATIVE_REVERSE_DNS", true),
            jitter: Duration::from_millis(env_num("ORBYN_NATIVE_JITTER_MS", 0)),
            udp: env_bool("ORBYN_NATIVE_UDP", true),
            udp_ports: TOP_UDP_PORTS.to_vec(),
        }
    }

    /// Sweep one host across the port list, returning the open ones.
    async fn sweep_host(&self, ip: IpAddr) -> Vec<OpenPort> {
        let mut open = Vec::new();
        let mut set: JoinSet<Option<OpenPort>> = JoinSet::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrency.max(1)));

        for &port in &self.ports {
            let permit = semaphore.clone().acquire_owned();
            let timeout = self.connect_timeout;
            set.spawn(async move {
                let _permit = permit.await;
                scan_port(ip, port, timeout).await
            });
        }
        while let Some(result) = set.join_next().await {
            if let Some(open_port) = result.unwrap_or(None) {
                open.push(open_port);
            }
        }
        open.sort_by_key(|p| p.port);
        open
    }

    /// Sweep one host across the UDP port list, returning hits as
    /// `(port, state)` pairs. Closed ports produce nothing.
    async fn sweep_host_udp(&self, ip: IpAddr) -> Vec<(u16, &'static str)> {
        let mut open = Vec::new();
        let mut set: JoinSet<Option<(u16, &'static str)>> = JoinSet::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrency.max(1)));

        for &port in &self.udp_ports {
            let permit = semaphore.clone().acquire_owned();
            let timeout = self.connect_timeout;
            set.spawn(async move {
                let _permit = permit.await;
                probe_udp_port(ip, port, timeout)
                    .await
                    .map(|state| (port, state))
            });
        }
        while let Some(result) = set.join_next().await {
            if let Some(hit) = result.unwrap_or(None) {
                open.push(hit);
            }
        }
        open.sort_by_key(|&(port, _)| port);
        open
    }

    /// ICMP liveness prefetch. Only a clean "no reply" (ping exit 1) says
    /// down; every other outcome (missing binary, timeout, permission or
    /// other error) fails open and the host is swept anyway.
    async fn ping_liveness(&self, ip: IpAddr) -> Liveness {
        // Per-platform flags: Unix `ping -c 1 -W 1`, Windows `ping -n 1 -w 1000`.
        let (count, wait) = if cfg!(windows) {
            (Vec::from(["-n", "1"]), Vec::from(["-w", "1000"]))
        } else {
            (Vec::from(["-c", "1"]), Vec::from(["-W", "1"]))
        };
        let child = Command::new(&self.ping_bin)
            .args(&count)
            .args(&wait)
            .arg(ip.to_string())
            .env_remove("ORBYN_SNMP_COMMUNITY")
            .env_remove("ORBYN_NETBOX_TOKEN")
            .env_remove("ORBYN_WINRM_PASSWORD")
            .env_remove("ORBYN_PROMETHEUS_TOKEN")
            .env_remove("ORBYN_DB")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn();
        let child = match child {
            Ok(child) => child,
            Err(_) => return Liveness::Unknown, // ping not installed: fail open
        };
        match run_captured(
            child,
            None,
            PING_STDOUT_CAP,
            MAX_STDERR_CAPTURE_BYTES,
            PING_TIMEOUT,
            format!("ping liveness probe timed out for {ip}"),
        )
        .await
        {
            Ok(captured) => liveness_from_exit_code(captured.status.code()),
            Err(_) => Liveness::Unknown,
        }
    }
}

/// Outcome of an ICMP liveness probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Liveness {
    Alive,
    Down,
    /// Probe unavailable or inconclusive: sweep anyway.
    Unknown,
}

fn liveness_from_exit_code(code: Option<i32>) -> Liveness {
    match code {
        Some(0) => Liveness::Alive,
        Some(1) => Liveness::Down,
        _ => Liveness::Unknown,
    }
}

impl Default for NativeCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// One open port with what the probes learned. `name` is an
/// evidence-based service name that overrides the port table; `banner`
/// is the product/version line (passive greeting or probe response).
struct OpenPort {
    port: u16,
    name: Option<&'static str>,
    banner: Option<String>,
}

#[async_trait]
impl Collector for NativeCollector {
    fn name(&self) -> &'static str {
        "native"
    }

    async fn scan(&self, target: &ScanTarget) -> Result<Vec<Observation>> {
        let hosts = expand_target(target, self.max_hosts)?;
        // Liveness only pays off (and only risks skipping) on ranges; a
        // single explicitly named host is always swept.
        let check_liveness = self.liveness && hosts.len() > 1;
        let mut observations = Vec::new();

        for ip in hosts {
            let pause = jitter_delay(self.jitter, ip);
            if !pause.is_zero() {
                tokio::time::sleep(pause).await;
            }
            if check_liveness && self.ping_liveness(ip).await == Liveness::Down {
                continue;
            }
            let open = self.sweep_host(ip).await;
            let udp = if self.udp {
                self.sweep_host_udp(ip).await
            } else {
                Vec::new()
            };
            if open.is_empty() && udp.is_empty() {
                continue; // down or fully filtered: no observation, like nmap
            }
            let hostname = if self.reverse_dns {
                first_ptr_name(ip).await
            } else {
                None
            };
            let now = Utc::now();
            let id = asset_id(ip);
            let names: Vec<&str> = open
                .iter()
                .filter_map(|p| p.name.or_else(|| service_name(p.port)))
                .chain(udp.iter().filter_map(|&(p, _)| udp_service_name(p)))
                .collect();
            observations.push(Observation::Asset(Asset {
                id: id.clone(),
                ip,
                hostname,
                device_class: classify_device(None, None, &names, None),
                os_name: None,
                os_version: None,
                sys_descr: None,
                environment: None,
                owner: None,
                criticality: None,
                tags: Vec::new(),
                first_seen: now,
                last_seen: now,
            }));
            for port in open {
                observations.push(Observation::Service(Service {
                    asset_id: id.clone(),
                    proto: "tcp".to_string(),
                    port: port.port,
                    // Evidence beats the port table; the table is the
                    // fallback when the probes made no claim.
                    name: port
                        .name
                        .map(str::to_string)
                        .or_else(|| service_name(port.port).map(str::to_string)),
                    state: "open".to_string(),
                    banner: port.banner,
                }));
            }
            for (port, state) in udp {
                observations.push(Observation::Service(Service {
                    asset_id: id.clone(),
                    proto: "udp".to_string(),
                    port,
                    name: udp_service_name(port).map(str::to_string),
                    // "open" only when the service answered; silence is
                    // honestly reported as open|filtered.
                    state: state.to_string(),
                    banner: None,
                }));
            }
        }
        Ok(observations)
    }
}

/// Connect to `(ip, port)` and identify what answers:
/// 1. TLS ports: rustls handshake, then the greeting or an HTTP `GET`
///    inside the tunnel.
/// 2. Otherwise: passive banner read (SSH, FTP, SMTP greet first).
/// 3. Silent ports: HTTP `GET` — HTTP servers wait for the client.
async fn scan_port(ip: IpAddr, port: u16, connect_timeout: Duration) -> Option<OpenPort> {
    let mut stream =
        match tokio::time::timeout(connect_timeout, TcpStream::connect((ip, port))).await {
            Ok(Ok(stream)) => stream,
            _ => return None,
        };
    if fingerprint::TLS_PORTS.contains(&port) {
        let fp = fingerprint::probe_tls(stream, ip).await?;
        return Some(OpenPort {
            port,
            name: fp.name,
            banner: fp.banner,
        });
    }
    if let Some(banner) = read_banner(&mut stream).await {
        return Some(OpenPort {
            port,
            name: None,
            banner: Some(banner),
        });
    }
    let fp = fingerprint::probe_http(&mut stream, &ip.to_string()).await;
    Some(OpenPort {
        port,
        name: fp.as_ref().and_then(|f| f.name),
        banner: fp.and_then(|f| f.banner),
    })
}

/// Read what the service sends first. Keep the first line, printable
/// ASCII only, capped.
async fn read_banner(stream: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(
        Duration::from_millis(BANNER_TIMEOUT_MS),
        stream.read(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    if n == 0 {
        return None;
    }
    fingerprint::first_printable_line(&buf[..n])
}

/// Probe one UDP port with a connected datagram socket — no raw
/// sockets, no privileges. An ICMP port-unreachable surfaces as
/// `ConnectionRefused` on a connected socket: closed, no observation.
/// A response proves open; silence is honestly `open|filtered` (ICMP
/// rate limiting makes many closed ports look silent on real networks).
async fn probe_udp_port(ip: IpAddr, port: u16, timeout: Duration) -> Option<&'static str> {
    let bind: &str = match ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let sock = tokio::net::UdpSocket::bind(bind).await.ok()?;
    sock.connect((ip, port)).await.ok()?;
    // Empty datagram: a minimal, read-only nudge. Errors here mean the
    // probe failed (or the port is already known closed): no claim.
    sock.send(&[]).await.ok()?;
    let mut buf = [0u8; 512];
    match tokio::time::timeout(timeout, sock.recv(&mut buf)).await {
        Ok(Ok(_)) => Some("open"), // the service answered
        Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => None, // closed
        Err(_) => Some("open|filtered"), // silence: could be either
        Ok(Err(_)) => None,        // probe failed: no claim
    }
}

/// Expand a validated target into individual host addresses, refusing
/// ranges larger than `max_hosts`.
fn expand_target(target: &ScanTarget, max_hosts: u64) -> Result<Vec<IpAddr>> {
    match target {
        ScanTarget::Ip(ip) => Ok(vec![*ip]),
        ScanTarget::Cidr(cidr) => {
            let (base, prefix) = cidr
                .split_once('/')
                .ok_or_else(|| anyhow!("invalid CIDR '{cidr}'"))?;
            match base.parse::<IpAddr>()? {
                IpAddr::V4(base) => {
                    let prefix: u8 = prefix.parse()?;
                    let count = 1u64 << (32 - prefix);
                    if count > max_hosts {
                        return Err(anyhow!(
                            "native collector refuses to expand '{cidr}' \
                             ({count} hosts > {max_hosts}); narrow the scope, raise \
                             ORBYN_NATIVE_MAX_HOSTS, or use --collector nmap"
                        ));
                    }
                    // Mask to the network address so bases like 10.0.0.5/24
                    // scan the real range and base + count cannot overflow.
                    let mask: u32 = if prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix)
                    };
                    let base = u32::from(base) & mask;
                    Ok((0..count)
                        .map(|i| IpAddr::V4(Ipv4Addr::from(base + i as u32)))
                        .collect())
                }
                IpAddr::V6(base) => {
                    let prefix: u8 = prefix.parse()?;
                    let count = 1u128 << (128 - prefix);
                    let max = u128::from(max_hosts);
                    if count > max {
                        return Err(anyhow!(
                            "native collector refuses to expand '{cidr}' \
                             ({count} hosts > {max}); IPv6 connect sweeps are only \
                             practical for tiny ranges — scan individual addresses \
                             or use --collector nmap"
                        ));
                    }
                    let mask: u128 = if prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix)
                    };
                    let base = u128::from(base) & mask;
                    Ok((0..count)
                        .map(|i| IpAddr::V6(Ipv6Addr::from(base + i)))
                        .collect())
                }
            }
        }
    }
}

fn service_name(port: u16) -> Option<&'static str> {
    SERVICE_NAMES
        .binary_search_by_key(&port, |&(p, _)| p)
        .ok()
        .map(|i| SERVICE_NAMES[i].1)
}

fn udp_service_name(port: u16) -> Option<&'static str> {
    UDP_SERVICE_NAMES
        .binary_search_by_key(&port, |&(p, _)| p)
        .ok()
        .map(|i| UDP_SERVICE_NAMES[i].1)
}

/// First PTR name for an IP, reusing the shared `dig` helper. `None` when
/// `dig` is missing, the lookup fails, or the address has no PTR record.
async fn first_ptr_name(ip: IpAddr) -> Option<String> {
    dns::resolve_ptr(ip)
        .await
        .ok()
        .and_then(|names| names.into_iter().next())
}

/// Pseudo-random 0..jitter pause, seeded from the clock and the host
/// address so concurrent runs spread out. Good enough for pacing, not for
/// anything cryptographic.
fn jitter_delay(jitter: Duration, ip: IpAddr) -> Duration {
    if jitter.is_zero() {
        return Duration::ZERO;
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let ip_bits = match ip {
        IpAddr::V4(v) => u32::from(v),
        IpAddr::V6(v) => u128::from(v) as u32,
    };
    let mixed = nanos.wrapping_mul(0x9E37_79B9) ^ ip_bits;
    Duration::from_nanos(mixed as u64 % jitter.as_nanos() as u64)
}

fn env_num(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(default)
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .and_then(|v| match v.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn target(raw: &str) -> ScanTarget {
        super::super::validate_target(raw).expect("valid target")
    }

    /// Collector with no external-tool dependencies: liveness and reverse
    /// DNS off, short timeouts, only the given ports swept.
    fn hermetic(ports: Vec<u16>) -> NativeCollector {
        NativeCollector {
            connect_timeout: Duration::from_millis(500),
            concurrency: 16,
            max_hosts: 256,
            ports,
            liveness: false,
            ping_bin: "ping".to_string(),
            reverse_dns: false,
            jitter: Duration::ZERO,
            udp: false,
            udp_ports: Vec::new(),
        }
    }

    async fn spawn_banner_listener() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                sock.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
            }
        });
        port
    }

    /// HTTP-style listener: silent until asked, then answers with a
    /// `Server` header — exercises the active fingerprint probe.
    async fn spawn_http_listener() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await; // the GET
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nServer: test-http/2.1\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await;
            }
        });
        port
    }

    #[test]
    fn top_ports_are_sorted_deduped_and_named() {
        let mut sorted = TOP_TCP_PORTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(&sorted, TOP_TCP_PORTS, "port list must be sorted+deduped");
        for &(port, _) in SERVICE_NAMES {
            assert!(TOP_TCP_PORTS.contains(&port), "named port {port} not swept");
        }
        let mut named = SERVICE_NAMES.to_vec();
        named.sort_by_key(|&(p, _)| p);
        named.dedup_by_key(|&mut (p, _)| p);
        assert_eq!(&named, SERVICE_NAMES, "names must be sorted+deduped");
    }

    #[test]
    fn expands_ipv4_cidr() {
        let hosts = expand_target(&target("10.0.0.0/30"), 100).unwrap();
        assert_eq!(hosts.len(), 4);
        assert_eq!(hosts[0].to_string(), "10.0.0.0");
        assert_eq!(hosts[3].to_string(), "10.0.0.3");
        // Non-network bases are masked to the real range.
        let hosts = expand_target(&target("10.0.0.5/30"), 100).unwrap();
        assert_eq!(hosts[0].to_string(), "10.0.0.4");
        assert_eq!(hosts[3].to_string(), "10.0.0.7");
        // Edge of the address space must not overflow.
        let hosts = expand_target(&target("255.255.255.0/30"), 100).unwrap();
        assert_eq!(hosts[3].to_string(), "255.255.255.3");
    }

    #[test]
    fn refuses_oversized_expansion() {
        let err = expand_target(&target("10.0.0.0/24"), 100).unwrap_err();
        assert!(err.to_string().contains("refuses to expand"));
        let err = expand_target(&target("2001:db8::/64"), 65_536).unwrap_err();
        assert!(err.to_string().contains("refuses to expand"));
        // Tiny IPv6 ranges work.
        let hosts = expand_target(&target("2001:db8::/126"), 100).unwrap();
        assert_eq!(hosts.len(), 4);
    }

    #[tokio::test]
    async fn open_port_is_found_with_banner_and_name() {
        let port = spawn_banner_listener().await;

        let collector = hermetic(vec![port]);
        let open = collector.sweep_host(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        let found = open.iter().find(|p| p.port == port).expect("port found");
        assert_eq!(found.banner.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
    }

    #[tokio::test]
    async fn silent_http_port_is_fingerprinted() {
        let port = spawn_http_listener().await;

        let collector = hermetic(vec![port]);
        let observations = collector
            .scan(&ScanTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .await
            .unwrap();
        // Evidence beats the port table: an HTTP response renames the
        // service and captures the product string.
        let service = observations
            .iter()
            .find_map(|o| match o {
                Observation::Service(s) if s.port == port => Some(s),
                _ => None,
            })
            .expect("service observed");
        assert_eq!(service.name.as_deref(), Some("http"));
        assert_eq!(service.banner.as_deref(), Some("test-http/2.1"));
    }

    #[tokio::test]
    async fn closed_port_is_not_open() {
        // Bind then drop: the port is very likely closed.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let collector = hermetic(vec![port]);
        let open = collector.sweep_host(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
        assert!(
            open.iter().all(|p| p.port != port),
            "dropped listener must not appear open"
        );
    }

    #[tokio::test]
    async fn scan_single_ip_reports_observations() {
        let port = spawn_banner_listener().await;

        let collector = hermetic(vec![port]);
        let observations = collector
            .scan(&ScanTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .await
            .unwrap();
        assert!(observations.iter().any(
            |o| matches!(o, Observation::Asset(a) if a.ip == IpAddr::V4(Ipv4Addr::LOCALHOST))
        ));
        assert!(observations
            .iter()
            .any(|o| matches!(o, Observation::Service(s) if s.port == port && s.state == "open")));
        // Reverse DNS is off in hermetic mode: hostname must stay unset.
        assert!(observations.iter().all(|o| match o {
            Observation::Asset(a) => a.hostname.is_none(),
            _ => true,
        }));
    }

    #[tokio::test]
    async fn scan_refuses_oversized_cidr() {
        // /8 only parses with the large-CIDR override; the native collector
        // still refuses to expand it beyond the host cap.
        let target =
            super::super::validate_target_with_policy("10.0.0.0/8", true).expect("valid target");
        let collector = NativeCollector::new();
        let err = collector.scan(&target).await.unwrap_err();
        assert!(err.to_string().contains("refuses to expand"));
    }

    #[test]
    fn liveness_exit_codes_map_to_three_states() {
        assert_eq!(liveness_from_exit_code(Some(0)), Liveness::Alive);
        assert_eq!(liveness_from_exit_code(Some(1)), Liveness::Down);
        assert_eq!(liveness_from_exit_code(Some(2)), Liveness::Unknown);
        assert_eq!(liveness_from_exit_code(None), Liveness::Unknown);
    }

    #[tokio::test]
    async fn missing_ping_binary_fails_open() {
        let mut collector = hermetic(Vec::new());
        collector.liveness = true;
        collector.ping_bin = "/nonexistent/orbyn-ping".to_string();
        // A broken/missing ping must read as Unknown, never Down.
        assert_eq!(
            collector
                .ping_liveness(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .await,
            Liveness::Unknown
        );
    }

    #[tokio::test]
    async fn liveness_unknown_still_sweeps_range() {
        let port = spawn_banner_listener().await;
        let mut collector = hermetic(vec![port]);
        collector.liveness = true;
        collector.ping_bin = "/nonexistent/orbyn-ping".to_string();
        // 127.0.0.0/30 spans four loopback addresses; fail-open liveness
        // must sweep them all rather than skipping.
        let observations = collector.scan(&target("127.0.0.0/30")).await.unwrap();
        assert!(
            observations
                .iter()
                .any(|o| matches!(o, Observation::Service(s) if s.port == port)),
            "fail-open liveness must not skip hosts"
        );
    }

    #[test]
    fn jitter_is_bounded_and_zero_jitter_is_free() {
        let jitter = Duration::from_millis(250);
        for ip in [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            assert!(
                jitter_delay(jitter, ip) < jitter,
                "delay must stay in 0..jitter"
            );
        }
        assert_eq!(
            jitter_delay(Duration::ZERO, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Duration::ZERO
        );
    }

    #[test]
    fn banner_is_named_for_well_known_port() {
        assert_eq!(service_name(22), Some("ssh"));
        assert_eq!(service_name(443), Some("https"));
        assert_eq!(service_name(65534), None);
    }

    #[test]
    fn udp_port_list_is_sorted_deduped_and_named() {
        let mut sorted = TOP_UDP_PORTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(&sorted, TOP_UDP_PORTS);
        let mut named = UDP_SERVICE_NAMES.to_vec();
        named.sort_by_key(|&(p, _)| p);
        named.dedup_by_key(|&mut (p, _)| p);
        assert_eq!(&named, UDP_SERVICE_NAMES);
        for &(port, _) in UDP_SERVICE_NAMES {
            assert!(
                TOP_UDP_PORTS.contains(&port),
                "named UDP port {port} not swept"
            );
        }
        assert_eq!(udp_service_name(161), Some("snmp"));
        assert_eq!(udp_service_name(137), Some("netbios-ns"));
        assert_eq!(udp_service_name(65534), None);
    }

    /// UDP socket that answers any datagram: proves "open".
    async fn spawn_udp_responder() -> u16 {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                if let Ok((_, peer)) = sock.recv_from(&mut buf).await {
                    let _ = sock.send_to(b"answer", peer).await;
                }
            }
        });
        port
    }

    #[tokio::test]
    async fn udp_responder_is_open() {
        let port = spawn_udp_responder().await;
        let state = probe_udp_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_millis(500),
        )
        .await
        .expect("responder port must be reported");
        assert_eq!(state, "open");
    }

    #[tokio::test]
    async fn udp_silent_socket_is_open_filtered() {
        // Bound but never answers: silence must read open|filtered,
        // never a bare "open" claim.
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let state = probe_udp_port(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            Duration::from_millis(300),
        )
        .await
        .expect("silent socket must still be reported");
        assert_eq!(state, "open|filtered");
    }

    #[cfg(unix)] // relies on loopback ICMP port-unreachable delivery
    #[tokio::test]
    async fn udp_closed_port_makes_no_claim() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = sock.local_addr().unwrap().port();
        drop(sock);
        assert!(
            probe_udp_port(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
                Duration::from_millis(500)
            )
            .await
            .is_none(),
            "closed UDP port must produce no observation"
        );
    }

    #[tokio::test]
    async fn scan_reports_udp_services() {
        let port = spawn_udp_responder().await;
        let mut collector = hermetic(Vec::new());
        collector.udp = true;
        collector.udp_ports = vec![port];
        let observations = collector
            .scan(&ScanTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)))
            .await
            .unwrap();
        let service = observations
            .iter()
            .find_map(|o| match o {
                Observation::Service(s) if s.proto == "udp" && s.port == port => Some(s),
                _ => None,
            })
            .expect("UDP responder must be observed");
        assert_eq!(service.state, "open");
        assert_eq!(service.name, None, "ephemeral port has no table name");
        assert_eq!(service.banner, None);
    }
}
