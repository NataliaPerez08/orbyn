//! SSH collector for Linux hosts (v0.3 milestone).
//!
//! Runs a single read-only probe command over the `ssh` binary and normalizes
//! the output into [`crate::domain::Observation`]s: OS details, hostname,
//! CPU/RAM capacity, filesystem inventory and running services.
//!
//! Security rules:
//! - the target and probe are passed as process arguments, never
//!   shell-interpolated; the probe string is a fixed constant, only the host
//!   comes from user input;
//! - `BatchMode=yes` disables interactive password prompts — authentication is
//!   ssh-agent or identity-file based (see [`CredentialProfile`]);
//! - the probe is strictly read-only: `cat`, `uname`, `hostname`, `lscpu`,
//!   `/proc/meminfo`, `df`, `systemctl list-units`;
//! - no secret material is held, logged or persisted.

use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use tokio::process::Command;

use crate::domain::{
    asset_id, Asset, Capacity, Connection, Filesystem, MetricSample, Observation, RunningService,
};
use crate::parsing::{parse_addr_port, split_sections};
use crate::process::{run_captured, MAX_STDERR_CAPTURE_BYTES, MAX_STDOUT_CAPTURE_BYTES};

use super::credentials::CredentialProfile;
use super::types::{Collector, CpuFacts, ScanTarget};

/// One read-only probe round trip. Sections are delimited by `###name` lines.
///
/// The `###metric` block samples CPU/RAM/swap/load three times ~2s apart, using
/// `/proc/stat` deltas (average CPU since the previous read), `/proc/meminfo`
/// and `/proc/loadavg`. No external tools besides `sed`/`awk`/`cut`/`tr`/`sleep`
/// are required, so it works on minimal hosts.
pub const LINUX_PROBE: &str = "echo '###os'; cat /etc/os-release; \
     echo '###kernel'; uname -r; \
     echo '###hostname'; hostname; \
     echo '###cpu'; lscpu 2>/dev/null || cat /proc/cpuinfo; \
     echo '###mem'; grep ^MemTotal /proc/meminfo; \
     echo '###disk'; df -kPT -x tmpfs -x devtmpfs; \
     echo '###svc'; systemctl --no-legend --no-pager --plain \
       list-units --type=service --state=running 2>/dev/null; \
     echo '###conn'; ss -tnp state established 2>/dev/null || netstat -tn 2>/dev/null; \
     echo '###metric'; \
     if [ -r /proc/stat ] && [ -r /proc/meminfo ]; then \
       for __i in 1 2 3; do \
         __c1=$(sed -n 's/^cpu  //p' /proc/stat); sleep 2; \
         __c2=$(sed -n 's/^cpu  //p' /proc/stat); \
         __cpu=$(printf '%s\n%s\n' \"$__c1\" \"$__c2\" | awk '{ if(NR==1){for(i=1;i<=NF;i++)a[i]=$i} else {for(i=1;i<=NF;i++)d[i]=$i-a[i]; t=0; for(i=1;i<=NF;i++)t+=d[i]; idle=d[4]+d[5]; printf \"%.1f\",(t-idle)*100/t } }'); \
         __mem=$(awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} /^SwapTotal:/{st=$2} /^SwapFree:/{sf=$2} END{printf \"%d|%d|%d|%d\",t,a,st,sf}' /proc/meminfo); \
         __load=$(cut -d' ' -f1-3 /proc/loadavg | tr ' ' ','); \
         echo \"${__cpu}|${__mem}|${__load}\"; \
       done; \
     fi";

/// Executes a fixed command on a remote host through the `ssh` binary.
///
/// The same transport serves the Linux and Windows host collectors; a native
/// WinRM transport can implement the same contract later.
#[derive(Debug, Clone)]
pub struct SshTransport {
    binary: String,
    profile: CredentialProfile,
}

/// Whole-process timeout for one SSH probe round trip.
const SSH_PROBE_TIMEOUT: Duration = Duration::from_secs(60);

impl SshTransport {
    pub fn new(profile: CredentialProfile) -> Self {
        Self {
            binary: std::env::var("ORBYN_SSH_BIN").unwrap_or_else(|_| "ssh".to_string()),
            profile,
        }
    }

    /// Run `command` on `host`, returning stdout. Fails on non-zero exit,
    /// connection error or a 60 second timeout.
    pub async fn run(&self, host: IpAddr, command: &str) -> Result<String> {
        let destination = if self.profile.username.is_empty() {
            host.to_string()
        } else {
            format!("{}@{}", self.profile.username, host)
        };

        let mut cmd = Command::new(&self.binary);
        cmd.arg("-o")
            .arg("BatchMode=yes")
            .arg("-o")
            .arg("ConnectTimeout=10")
            .arg("-o")
            .arg("StrictHostKeyChecking=accept-new")
            .arg("-o")
            .arg("LogLevel=ERROR")
            .arg("-p")
            .arg(self.profile.port.to_string());
        if let Some(identity) = &self.profile.identity_file {
            cmd.arg("-i").arg(identity);
        }
        cmd.arg(&destination)
            .arg(command)
            // Secret-bearing variables never reach the child environment
            // (audit OY-02): a hijacked binary must not be able to read the
            // community, the NetBox token or the database URL password.
            .env_remove("ORBYN_SNMP_COMMUNITY")
            .env_remove("ORBYN_NETBOX_TOKEN")
            .env_remove("ORBYN_DB")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let child = cmd
            .spawn()
            .context("failed to start ssh; is an OpenSSH client installed?")?;

        let captured = run_captured(
            child,
            None,
            MAX_STDOUT_CAPTURE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
            SSH_PROBE_TIMEOUT,
            format!("ssh timed out connecting to {destination}"),
        )
        .await?;

        if !captured.status.success() {
            return Err(anyhow!(
                "ssh exited with {} against {destination}: {}",
                captured.status,
                captured.stderr.trim()
            ));
        }
        if captured.stdout_truncated {
            return Err(anyhow!(
                "ssh probe output from {destination} exceeded the {} byte \
                 capture limit",
                MAX_STDOUT_CAPTURE_BYTES
            ));
        }
        Ok(captured.stdout)
    }
}

/// Linux host collector: one SSH probe producing normalized host facts.
pub struct LinuxCollector {
    transport: SshTransport,
}

impl LinuxCollector {
    pub fn new(profile: CredentialProfile) -> Self {
        Self {
            transport: SshTransport::new(profile),
        }
    }

    /// Parse probe output into facts without invoking ssh (fixture-testable).
    pub fn parse_probe(&self, output: &str) -> LinuxHostFacts {
        parse_linux_probe(output)
    }
}

impl Default for LinuxCollector {
    fn default() -> Self {
        Self::new(CredentialProfile::default())
    }
}

#[async_trait]
impl Collector for LinuxCollector {
    fn name(&self) -> &'static str {
        "ssh"
    }

    async fn scan(&self, target: &ScanTarget) -> Result<Vec<Observation>> {
        let ip = match target {
            ScanTarget::Ip(ip) => *ip,
            ScanTarget::Cidr(cidr) => {
                bail!("SSH collects a single host; target must be an IP address (got '{cidr}')")
            }
        };
        let output = self
            .transport
            .run(ip, LINUX_PROBE)
            .await
            .with_context(|| format!("ssh probe of {ip}"))?;
        let facts = parse_linux_probe(&output);
        Ok(linux_observations(ip, &facts))
    }
}

/// Host facts parsed from the Linux probe.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct LinuxHostFacts {
    pub os_name: Option<String>,
    pub kernel: Option<String>,
    pub hostname: Option<String>,
    pub cpu: Option<CpuFacts>,
    pub ram_total_mb: Option<u64>,
    pub filesystems: Vec<Filesystem>,
    pub services: Vec<RunningService>,
    pub connections: Vec<Connection>,
    /// Utilization snapshots in probe order (each roughly `snapshot_interval`
    /// seconds apart).
    pub metrics: Vec<SnapshotFacts>,
}

/// One utilization snapshot captured on the remote host.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SnapshotFacts {
    pub cpu_usage_percent: Option<f32>,
    pub ram_used_mb: Option<u64>,
    pub ram_available_mb: Option<u64>,
    pub swap_used_mb: Option<u64>,
    pub load_1m: Option<f32>,
    pub load_5m: Option<f32>,
    pub load_15m: Option<f32>,
}

/// Approximate spacing between snapshots in the probe (`sleep 2` per sample).
pub const SNAPSHOT_INTERVAL_SECS: i64 = 2;

/// Parse the full Linux probe output into facts.
pub fn parse_linux_probe(output: &str) -> LinuxHostFacts {
    let sections = split_sections(output);
    let section = |name: &str| sections.get(name).cloned().unwrap_or_default();

    let os_name = parse_os_release(&section("os"));
    let kernel = first_line(&section("kernel"));
    let hostname = first_line(&section("hostname"));
    let cpu = parse_cpu(&section("cpu"));
    let ram_total_mb = parse_meminfo(&section("mem"));
    let filesystems = parse_df(&section("disk"));
    let services = parse_systemctl(&section("svc"));
    let connections = parse_connections(&section("conn"));
    let metrics = parse_snapshots(&section("metric"));

    LinuxHostFacts {
        os_name,
        kernel,
        hostname,
        cpu,
        ram_total_mb,
        filesystems,
        services,
        connections,
        metrics,
    }
}

/// Parse `###metric` lines of the shape
/// `cpu|mem_total_kb|mem_avail_kb|swap_total_kb|swap_free_kb|load1,load5,load15`.
/// Malformed lines yield `None` fields or are skipped entirely when they carry
/// nothing usable.
pub fn parse_snapshots(lines: &[String]) -> Vec<SnapshotFacts> {
    let mut out = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.splitn(6, '|');
        let cpu: Option<f32> = parts.next().and_then(|v| v.trim().parse().ok());
        let t: Option<u64> = parts.next().and_then(|v| v.trim().parse().ok());
        let a: Option<u64> = parts.next().and_then(|v| v.trim().parse().ok());
        let st: Option<u64> = parts.next().and_then(|v| v.trim().parse().ok());
        let sf: Option<u64> = parts.next().and_then(|v| v.trim().parse().ok());
        let load: Option<Vec<f32>> = parts.next().and_then(|v| {
            let fields: Vec<f32> = v
                .trim()
                .split(',')
                .filter_map(|x| x.trim().parse().ok())
                .collect();
            if fields.len() == 3 {
                Some(fields)
            } else {
                None
            }
        });

        let ram_used_mb = match (t, a) {
            (Some(total), Some(avail)) if total >= avail && avail > 0 => {
                Some((total - avail) / 1024)
            }
            _ => None,
        };
        let swap_used_mb = match (st, sf) {
            (Some(total), Some(free)) if total > 0 && total >= free => Some((total - free) / 1024),
            _ => None,
        };

        if cpu.is_none() && ram_used_mb.is_none() && load.is_none() {
            continue;
        }

        let (l1, l5, l15) = match &load {
            Some(v) => (Some(v[0]), Some(v[1]), Some(v[2])),
            None => (None, None, None),
        };
        out.push(SnapshotFacts {
            cpu_usage_percent: cpu,
            ram_used_mb,
            ram_available_mb: a.map(|kb| kb / 1024),
            swap_used_mb,
            load_1m: l1,
            load_5m: l5,
            load_15m: l15,
        });
    }
    out
}

/// Build normalized observations from parsed facts. The asset observation
/// always comes first so foreign keys resolve inside the store transaction.
pub fn linux_observations(ip: IpAddr, facts: &LinuxHostFacts) -> Vec<Observation> {
    let now = Utc::now();
    let id = asset_id(ip);
    let mut observations = vec![Observation::Asset(Asset {
        id: id.clone(),
        ip,
        hostname: facts.hostname.clone(),
        device_class: Some("server".into()),
        os_name: facts.os_name.clone(),
        os_version: facts.kernel.clone(),
        sys_descr: None,
        environment: None,
        owner: None,
        criticality: None,
        tags: Vec::new(),
        first_seen: now,
        last_seen: now,
    })];

    if facts.cpu.is_some() || facts.ram_total_mb.is_some() {
        let cpu = facts.cpu.clone().unwrap_or_default();
        observations.push(Observation::Capacity(Capacity {
            asset_id: id.clone(),
            cpu_model: cpu.model,
            cpu_sockets: cpu.sockets,
            cpu_cores: cpu.cores,
            cpu_threads: cpu.threads,
            ram_total_mb: facts.ram_total_mb,
            collected_at: now,
        }));
    }

    for fs in &facts.filesystems {
        let mut fs = fs.clone();
        fs.asset_id = id.clone();
        observations.push(Observation::Filesystem(fs));
    }
    for svc in &facts.services {
        let mut svc = svc.clone();
        svc.asset_id = id.clone();
        observations.push(Observation::RunningService(svc));
    }
    for conn in &facts.connections {
        let mut conn = conn.clone();
        conn.asset_id = id.clone();
        observations.push(Observation::Connection(conn));
    }
    for (i, snap) in facts.metrics.iter().enumerate() {
        // Timestamps are synthesized: the host sampled every ~2 s, so give each
        // snapshot an offset backwards from "now" preserving its order.
        let sampled_at = now
            - chrono::Duration::seconds(
                SNAPSHOT_INTERVAL_SECS * (facts.metrics.len() - 1 - i) as i64,
            );
        observations.push(Observation::MetricSample(MetricSample {
            asset_id: id.clone(),
            sampled_at,
            cpu_usage_percent: snap.cpu_usage_percent,
            ram_used_mb: snap.ram_used_mb,
            ram_available_mb: snap.ram_available_mb,
            swap_used_mb: snap.swap_used_mb,
            load_1m: snap.load_1m,
            load_5m: snap.load_5m,
            load_15m: snap.load_15m,
        }));
    }
    observations
}

fn first_line(lines: &[String]) -> Option<String> {
    lines
        .iter()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// Parse `/etc/os-release`, preferring `PRETTY_NAME` over `NAME`.
fn parse_os_release(lines: &[String]) -> Option<String> {
    let mut pretty = None;
    let mut name = None;
    for line in lines {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        match key.trim() {
            "PRETTY_NAME" => pretty = Some(value.to_string()),
            "NAME" => name = Some(value.to_string()),
            _ => {}
        }
    }
    pretty.or(name)
}

/// Parse CPU capacity from `lscpu` output, falling back to `/proc/cpuinfo`.
fn parse_cpu(lines: &[String]) -> Option<CpuFacts> {
    if lines.is_empty() {
        return None;
    }
    if lines.iter().any(|l| l.starts_with("Architecture:")) {
        Some(parse_lscpu(lines))
    } else {
        parse_cpuinfo(lines)
    }
}

fn parse_lscpu(lines: &[String]) -> CpuFacts {
    let mut facts = CpuFacts::default();
    let mut cores_per_socket: Option<u32> = None;
    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "Model name" => facts.model = Some(value.to_string()),
            "CPU(s)" => facts.threads = value.parse().ok(),
            "Socket(s)" => facts.sockets = value.parse().ok(),
            "Core(s) per socket" => cores_per_socket = value.parse().ok(),
            _ => {}
        }
    }
    if let (Some(per_socket), Some(sockets)) = (cores_per_socket, facts.sockets) {
        facts.cores = Some(per_socket.saturating_mul(sockets));
    }
    facts
}

fn parse_cpuinfo(lines: &[String]) -> Option<CpuFacts> {
    let mut threads = 0u32;
    let mut model = None;
    let mut physical_ids = std::collections::BTreeSet::new();
    let mut core_keys = std::collections::BTreeSet::new();
    let mut last_physical = String::new();

    for line in lines {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "processor" => threads += 1,
            "model name" => model = Some(value.to_string()),
            "physical id" => {
                last_physical = value.to_string();
                physical_ids.insert(last_physical.clone());
            }
            "core id" => {
                core_keys.insert(format!("{last_physical}/{}", value));
            }
            _ => {}
        }
    }

    if threads == 0 {
        return None;
    }
    let sockets = if physical_ids.is_empty() {
        1
    } else {
        physical_ids.len() as u32
    };
    let cores = if core_keys.is_empty() {
        threads
    } else {
        core_keys.len() as u32
    };
    Some(CpuFacts {
        model,
        sockets: Some(sockets),
        cores: Some(cores),
        threads: Some(threads),
    })
}

/// Parse `MemTotal:  16384532 kB` into whole megabytes (rounded).
fn parse_meminfo(lines: &[String]) -> Option<u64> {
    let line = lines.iter().find(|l| l.starts_with("MemTotal"))?;
    let kb = line.split_whitespace().nth(1)?.parse::<u64>().ok()?;
    Some((kb + 512) / 1024)
}

/// Parse `df -kPT` output into filesystem observations.
fn parse_df(lines: &[String]) -> Vec<Filesystem> {
    let mut out = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Filesystem") {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 7 {
            continue;
        }
        let Some(size_kb) = fields[2].parse::<u64>().ok() else {
            continue;
        };
        out.push(Filesystem {
            asset_id: String::new(),
            device: Some(fields[0].to_string()),
            mount: fields[6..].join(" "),
            fs_type: Some(fields[1].to_string()),
            size_kb,
            used_kb: fields[3].parse().ok(),
            available_kb: fields[4].parse().ok(),
            used_pct: fields[5].trim_end_matches('%').parse().ok(),
        });
    }
    out
}

/// Parse `systemctl list-units --type=service --state=running` output.
fn parse_systemctl(lines: &[String]) -> Vec<RunningService> {
    let mut out = Vec::new();
    for line in lines {
        let trimmed = line.trim_end();
        if trimmed.trim().is_empty() {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 4 || fields[2] != "active" {
            continue;
        }
        out.push(RunningService {
            asset_id: String::new(),
            name: fields[0].to_string(),
            state: Some(fields[3].to_string()),
            description: if fields.len() > 4 {
                Some(fields[4..].join(" "))
            } else {
                None
            },
        });
    }
    out
}

/// Parse active TCP connections from `ss -tnp state established` output,
/// falling back to `netstat -tn` (optionally `-p`) format.
///
/// Accepted row shapes:
///
/// - `ss`: `ESTAB|ESTABLISHED recvq sendq local peer [users:(("proc",...))]`
/// - `netstat`: `tcp|tcp6 recvq sendq local peer ESTABLISHED [pid/prog[:name]]`
///   where the trailing process column is the BusyBox `pid/prog` form or the
///   net-tools `pid/prog:name` form (`-` when unavailable).
///
/// Rows in other states (e.g. `LISTEN`, emitted by `ss` builds that ignore
/// the `state established` filter) are skipped. Loopback remote endpoints
/// and self-connections (remote == local address) are dropped: they never
/// become dependency evidence.
fn parse_connections(lines: &[String]) -> Vec<Connection> {
    let mut out = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("State")
            || trimmed.starts_with("Proto")
            || trimmed.starts_with("Active Internet")
        {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        let (local, peer, process) = if fields.first().is_some_and(|field| {
            field.eq_ignore_ascii_case("tcp") || field.eq_ignore_ascii_case("tcp6")
        }) {
            // tcp 0 0 local peer ESTABLISHED [pid/prog[:name]]
            if fields.len() < 5
                || !fields[5..]
                    .iter()
                    .any(|field| field.eq_ignore_ascii_case("established"))
            {
                continue;
            }
            let process = fields[5..]
                .iter()
                .find(|field| field.contains('/'))
                .and_then(|field| netstat_process(field));
            (fields[3], fields[4], process)
        } else {
            // ESTAB 0 0 local peer [users:(("proc",pid=..,fd=..))]
            if fields.len() < 5
                || !(fields[0].eq_ignore_ascii_case("estab")
                    || fields[0].eq_ignore_ascii_case("established"))
            {
                continue;
            }
            let process = if fields.len() > 5 {
                first_quoted(&fields[5..].join(" "))
            } else {
                None
            };
            (fields[3], fields[4], process)
        };

        let Some((local_ip, local_port)) = parse_addr_port(local) else {
            continue;
        };
        let Some((remote_ip, remote_port)) = parse_addr_port(peer) else {
            continue;
        };
        if remote_ip.is_loopback() || remote_ip == local_ip {
            continue;
        }
        out.push(Connection {
            asset_id: String::new(),
            proto: "tcp".into(),
            local_ip: Some(local_ip),
            local_port: Some(local_port),
            remote_ip,
            remote_port,
            process,
        });
    }
    out
}

/// Extract the first double-quoted token (`users:(("nginx",pid=1,fd=2))`).
fn first_quoted(raw: &str) -> Option<String> {
    let start = raw.find('"')? + 1;
    let end = raw[start..].find('"')? + start;
    Some(raw[start..end].to_string())
}

/// Extract the program name from a `netstat -p` process column:
/// `1234/sshd` (BusyBox), `1234/sshd:server` (net-tools) or `-` when the
/// owning process is unavailable.
fn netstat_process(field: &str) -> Option<String> {
    let program = field.split('/').nth(1)?.split(':').next()?.trim();
    (!program.is_empty()).then(|| program.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROBE_OUTPUT: &str = "###os\n\
NAME=\"Ubuntu\"\n\
PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n\
VERSION_ID=\"22.04\"\n\
###kernel\n\
5.15.0-94-generic\n\
###hostname\n\
web-01\n\
###cpu\n\
Architecture:        x86_64\n\
CPU(s):              8\n\
Thread(s) per core:  2\n\
Core(s) per socket:  4\n\
Socket(s):           1\n\
Model name:          Intel(R) Xeon(R) Gold 6138 CPU @ 2.00GHz\n\
###mem\n\
MemTotal:       16384532 kB\n\
###disk\n\
Filesystem     Type   1024-blocks      Used Available Capacity Mounted on\n\
/dev/sda1      ext4       52425716  12345678  37380844      25% /\n\
/dev/sdb1      xfs       209612800  98765432 104947368      49% /data\n\
###svc\n\
nginx.service                 loaded active running A high performance web server and reverse proxy\n\
sshd.service                  loaded active running OpenBSD Secure Shell server\n\
stopped.service               loaded inactive dead   Should not appear\n";

    const METRIC_SECTION: &str = "23.4|16384532|12170892|2097152|1048576|0.52,0.41,0.30\n\
18.1|16384532|13000000|2097152|1200000|0.75,0.50,0.31\n\
bogus|not-a-number\n";

    const CONN_SECTION: &str = "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n\
ESTAB  0      0      10.0.0.5:443          10.0.0.9:51414           users:((\"nginx\",pid=1234,fd=9))\n\
ESTAB  0      0      10.0.0.5:54322        10.0.0.7:5432            users:((\"postgres\",pid=977,fd=6))\n\
ESTAB  0      0      127.0.0.1:54324       127.0.0.1:5432            \n\
ESTAB  0      0      10.0.0.5:22           10.0.0.5:51234            users:((\"sshd\",pid=1,fd=3))\n";

    const NETSTAT_SECTION: &str = "Active Internet connections (w/o servers)\n\
Proto Recv-Q Send-Q Local Address           Foreign Address         State\n\
tcp        0      0 10.0.0.5:443            10.0.0.9:51414          ESTABLISHED\n\
tcp        0      0 10.0.0.5:22             10.0.0.8:49222          ESTABLISHED\n\
tcp        0      0 10.0.0.5:22             10.0.0.8:49223          CLOSE_WAIT\n";

    #[test]
    fn parses_full_probe() {
        let facts = parse_linux_probe(PROBE_OUTPUT);
        assert_eq!(facts.os_name.as_deref(), Some("Ubuntu 22.04.4 LTS"));
        assert_eq!(facts.kernel.as_deref(), Some("5.15.0-94-generic"));
        assert_eq!(facts.hostname.as_deref(), Some("web-01"));

        let cpu = facts.cpu.expect("cpu facts");
        assert_eq!(
            cpu.model.as_deref(),
            Some("Intel(R) Xeon(R) Gold 6138 CPU @ 2.00GHz")
        );
        assert_eq!(cpu.sockets, Some(1));
        assert_eq!(cpu.cores, Some(4));
        assert_eq!(cpu.threads, Some(8));

        assert_eq!(facts.ram_total_mb, Some(16001));

        assert_eq!(facts.filesystems.len(), 2);
        let root = facts.filesystems.iter().find(|f| f.mount == "/").unwrap();
        assert_eq!(root.device.as_deref(), Some("/dev/sda1"));
        assert_eq!(root.fs_type.as_deref(), Some("ext4"));
        assert_eq!(root.size_kb, 52425716);
        assert_eq!(root.used_pct, Some(25));

        // inactive units are filtered out
        assert_eq!(facts.services.len(), 2);
        let nginx = facts
            .services
            .iter()
            .find(|s| s.name == "nginx.service")
            .unwrap();
        assert_eq!(nginx.state.as_deref(), Some("running"));
        assert_eq!(
            nginx.description.as_deref(),
            Some("A high performance web server and reverse proxy")
        );
    }

    #[test]
    fn builds_observations_with_asset_first() {
        let facts = parse_linux_probe(PROBE_OUTPUT);
        let observations = linux_observations("10.0.0.5".parse().unwrap(), &facts);

        assert!(matches!(observations[0], Observation::Asset(_)));
        let count =
            |pred: &dyn Fn(&Observation) -> bool| observations.iter().filter(|o| pred(o)).count();
        assert_eq!(count(&|o| matches!(o, Observation::Asset(_))), 1);
        assert_eq!(count(&|o| matches!(o, Observation::Capacity(_))), 1);
        assert_eq!(count(&|o| matches!(o, Observation::Filesystem(_))), 2);
        assert_eq!(count(&|o| matches!(o, Observation::RunningService(_))), 2);
        assert_eq!(count(&|o| matches!(o, Observation::Connection(_))), 0);

        if let Some(Observation::Asset(asset)) = observations.first() {
            assert_eq!(asset.device_class.as_deref(), Some("server"));
            assert_eq!(asset.hostname.as_deref(), Some("web-01"));
        }
        if let Some(Observation::Capacity(cap)) = observations
            .iter()
            .find(|o| matches!(o, Observation::Capacity(_)))
        {
            assert_eq!(cap.ram_total_mb, Some(16001));
            assert_eq!(cap.cpu_threads, Some(8));
        }
    }

    #[test]
    fn parses_ss_connections_with_process() {
        let conns =
            parse_connections(&CONN_SECTION.lines().map(str::to_string).collect::<Vec<_>>());
        assert_eq!(
            conns.len(),
            2,
            "loopback and self connections must be dropped"
        );
        let to_db = conns.iter().find(|c| c.remote_port == 5432).unwrap();
        assert_eq!(to_db.remote_ip.to_string(), "10.0.0.7");
        assert_eq!(to_db.process.as_deref(), Some("postgres"));
        assert_eq!(to_db.proto, "tcp");
        assert_eq!(to_db.local_port, Some(54322));
    }

    #[test]
    fn parses_netstat_connections() {
        let conns = parse_connections(
            &NETSTAT_SECTION
                .lines()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        );
        assert_eq!(conns.len(), 2, "non-established states must be skipped");
        assert_eq!(conns[0].remote_port, 51414);
        assert_eq!(conns[0].process, None);
    }

    #[test]
    fn parses_established_ss_variant_without_process_metadata() {
        let lines = vec!["ESTABLISHED 0 0 10.0.0.5:443 10.0.0.9:51414".to_string()];
        let conns = parse_connections(&lines);
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].remote_port, 51414);
        assert_eq!(conns[0].process, None);
    }

    /// BusyBox `netstat -tn`: same layout as net-tools, no process column.
    const BUSYBOX_NETSTAT_SECTION: &str = "Active Internet connections (w/o servers)\n\
    Proto Recv-Q Send-Q Local Address           Foreign Address         State     \n\
    tcp        0      0 10.0.0.5:22             10.0.0.8:49222          ESTABLISHED\n\
    tcp        0      0 10.0.0.5:443            10.0.0.9:51414          ESTABLISHED\n\
    tcp        0      0 10.0.0.5:22             10.0.0.8:49223          CLOSE_WAIT \n";

    /// BusyBox `netstat -tnp`: trailing `pid/prog` process column.
    const BUSYBOX_NETSTAT_P_SECTION: &str = "Active Internet connections (w/o servers)\n\
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program\n\
    tcp        0      0 10.0.0.5:22             10.0.0.8:49222          ESTABLISHED 1234/sshd\n\
    tcp        0      0 10.0.0.5:443            10.0.0.9:51414          ESTABLISHED 987/nginx\n\
    tcp        0      0 10.0.0.5:54324          10.0.0.7:5432           ESTABLISHED -\n";

    /// net-tools `netstat -tnp`: `pid/prog:name` process column.
    const NETTOOLS_NETSTAT_P_SECTION: &str = "Active Internet connections (w/o servers)\n\
    Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n\
    tcp        0      0 10.0.0.5:22             10.0.0.8:49222          ESTABLISHED 1234/sshd:server\n\
    tcp        0      0 10.0.0.5:443            10.0.0.9:51414          ESTABLISHED 987/nginx:worker\n";

    #[test]
    fn parses_busybox_netstat_without_process_column() {
        let conns = parse_connections(
            &BUSYBOX_NETSTAT_SECTION
                .lines()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        );
        assert_eq!(conns.len(), 2, "CLOSE_WAIT must be skipped");
        assert!(conns.iter().all(|c| c.process.is_none()));
        assert_eq!(conns[1].remote_port, 51414);
    }

    #[test]
    fn parses_busybox_netstat_p_process_column() {
        let conns = parse_connections(
            &BUSYBOX_NETSTAT_P_SECTION
                .lines()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        );
        assert_eq!(conns.len(), 3);
        let ssh = conns.iter().find(|c| c.remote_port == 49222).unwrap();
        assert_eq!(ssh.process.as_deref(), Some("sshd"), "BusyBox pid/prog");
        let web = conns.iter().find(|c| c.remote_port == 51414).unwrap();
        assert_eq!(web.process.as_deref(), Some("nginx"));
        let db = conns.iter().find(|c| c.remote_port == 5432).unwrap();
        assert_eq!(db.process, None, "`-` means no process available");
    }

    #[test]
    fn parses_nettools_netstat_p_program_name() {
        let conns = parse_connections(
            &NETTOOLS_NETSTAT_P_SECTION
                .lines()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        );
        assert_eq!(conns.len(), 2);
        assert_eq!(conns[0].process.as_deref(), Some("sshd"), "prog:name form");
        assert_eq!(conns[1].process.as_deref(), Some("nginx"));
    }

    #[test]
    fn parses_ipv6_rows_in_both_formats() {
        // netstat prints bare IPv6 (`2001:db8::5:22`), ss prints bracketed.
        let lines: Vec<String> = [
            "tcp6       0      0 2001:db8::5:22          2001:db8::9:51414       ESTABLISHED 1234/sshd",
            "tcp6       0      0 ::ffff:10.0.0.5:443     ::ffff:10.0.0.9:51414  ESTABLISHED 987/nginx",
            "ESTAB      0      0 [2001:db8::5]:54322     [2001:db8::7]:5432     users:((\"postgres\",pid=977,fd=6))",
        ]
        .iter()
        .map(|l| l.to_string())
        .collect();
        let conns = parse_connections(&lines);
        assert_eq!(conns.len(), 3);
        assert_eq!(conns[0].remote_ip.to_string(), "2001:db8::9");
        assert_eq!(conns[0].process.as_deref(), Some("sshd"));
        assert_eq!(
            conns[1].remote_ip.to_string(),
            "10.0.0.9",
            "IPv4-mapped endpoints must collapse to IPv4"
        );
        assert_eq!(conns[2].remote_ip.to_string(), "2001:db8::7");
        assert_eq!(conns[2].process.as_deref(), Some("postgres"));
    }

    #[test]
    fn skips_listen_rows_from_ss_builds_without_state_filter() {
        // Old iproute2 builds accept but ignore `state established`, so the
        // output can contain listening and unconnected rows.
        let lines: Vec<String> = [
            "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process",
            "LISTEN 0      128    0.0.0.0:22            0.0.0.0:*               users:((\"sshd\",pid=1,fd=3))",
            "ESTAB  0      0      10.0.0.5:443          10.0.0.9:51414         users:((\"nginx\",pid=987,fd=9))",
            "UNCONN 0      0      0.0.0.0:68            0.0.0.0:*               users:((\"dhclient\",pid=2,fd=4))",
        ]
        .iter()
        .map(|l| l.to_string())
        .collect();
        let conns = parse_connections(&lines);
        assert_eq!(conns.len(), 1, "only ESTAB rows are dependency evidence");
        assert_eq!(conns[0].process.as_deref(), Some("nginx"));
    }

    #[test]
    fn full_probe_includes_connections() {
        let full = format!("{PROBE_OUTPUT}\n###conn\n{CONN_SECTION}");
        let facts = parse_linux_probe(&full);
        assert_eq!(facts.connections.len(), 2);
        let observations = linux_observations("10.0.0.5".parse().unwrap(), &facts);
        let conns = observations
            .iter()
            .filter(|o| matches!(o, Observation::Connection(_)))
            .count();
        assert_eq!(conns, 2);
    }

    #[test]
    fn parses_metric_snapshots() {
        let snaps = parse_snapshots(
            &METRIC_SECTION
                .lines()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        );
        assert_eq!(snaps.len(), 2, "the malformed line must be dropped");
        assert_eq!(snaps[0].cpu_usage_percent, Some(23.4));
        assert_eq!(snaps[0].ram_used_mb, Some(4114)); // (16384532-12170892)/1024
        assert_eq!(snaps[0].ram_available_mb, Some(11885));
        assert_eq!(snaps[0].swap_used_mb, Some(1024));
        assert_eq!(snaps[0].load_1m, Some(0.52));
        assert_eq!(snaps[0].load_15m, Some(0.30));
        assert_eq!(snaps[1].cpu_usage_percent, Some(18.1));
    }

    #[test]
    fn snapshots_become_metric_observations() {
        let full = format!("{PROBE_OUTPUT}###metric\n{METRIC_SECTION}");
        let facts = parse_linux_probe(&full);
        assert_eq!(facts.metrics.len(), 2);

        let observations = linux_observations("10.0.0.5".parse().unwrap(), &facts);
        let metrics: Vec<&Observation> = observations
            .iter()
            .filter(|o| matches!(o, Observation::MetricSample(_)))
            .collect();
        assert_eq!(metrics.len(), 2);

        if let Observation::MetricSample(first) = metrics[0] {
            assert_eq!(first.asset_id, "10-0-0-5");
            assert_eq!(first.cpu_usage_percent, Some(23.4));
        }
        // Oldest snapshot first, then a newer one with a later timestamp.
        if let (Observation::MetricSample(a), Observation::MetricSample(b)) =
            (&metrics[0], &metrics[1])
        {
            assert!(a.sampled_at <= b.sampled_at);
        }
    }

    #[test]
    fn parses_cpuinfo_fallback() {
        let cpuinfo = "processor\t: 0\n\
vendor_id\t: GenuineIntel\n\
model name\t: AMD EPYC 7R32 48-Core Processor\n\
physical id\t: 0\n\
core id\t\t: 0\n\
processor\t: 1\n\
model name\t: AMD EPYC 7R32 48-Core Processor\n\
physical id\t: 0\n\
core id\t\t: 1\n";
        let facts = parse_cpu(&cpuinfo.lines().map(str::to_string).collect::<Vec<_>>())
            .expect("cpuinfo facts");
        assert_eq!(facts.threads, Some(2));
        assert_eq!(facts.sockets, Some(1));
        assert_eq!(facts.cores, Some(2));
        assert_eq!(
            facts.model.as_deref(),
            Some("AMD EPYC 7R32 48-Core Processor")
        );
    }

    #[test]
    fn empty_probe_yields_asset_only() {
        let facts = parse_linux_probe("");
        let observations = linux_observations("10.0.0.9".parse().unwrap(), &facts);
        assert_eq!(observations.len(), 1);
        assert!(matches!(observations[0], Observation::Asset(_)));
    }

    #[test]
    fn mount_points_with_spaces_are_kept() {
        let df = "Filesystem     Type   1024-blocks      Used Available Capacity Mounted on\n\
/dev/sda1      ext4       52425716  12345678  37380844      25% /mnt/my disk\n";
        let filesystems = parse_df(&df.lines().map(str::to_string).collect::<Vec<_>>());
        assert_eq!(filesystems.len(), 1);
        assert_eq!(filesystems[0].mount, "/mnt/my disk");
    }
}
