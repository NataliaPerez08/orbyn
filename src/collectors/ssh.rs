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
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

use crate::domain::{Asset, Capacity, Filesystem, Observation, RunningService};
use crate::parsing::split_sections;

use super::credentials::CredentialProfile;
use super::types::{Collector, CpuFacts, ScanTarget};

/// One read-only probe round trip. Sections are delimited by `###name` lines.
pub const LINUX_PROBE: &str = "echo '###os'; cat /etc/os-release; \
     echo '###kernel'; uname -r; \
     echo '###hostname'; hostname; \
     echo '###cpu'; lscpu 2>/dev/null || cat /proc/cpuinfo; \
     echo '###mem'; grep ^MemTotal /proc/meminfo; \
     echo '###disk'; df -kPT -x tmpfs -x devtmpfs; \
     echo '###svc'; systemctl --no-legend --no-pager --plain \
       list-units --type=service --state=running 2>/dev/null";

/// Executes a fixed command on a remote host through the `ssh` binary.
///
/// The same transport serves the Linux and Windows host collectors; a native
/// WinRM transport can implement the same contract later.
#[derive(Debug, Clone)]
pub struct SshTransport {
    binary: String,
    profile: CredentialProfile,
}

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
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .context("failed to start ssh; is an OpenSSH client installed?")?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut out) = child.stdout.take() {
            out.read_to_string(&mut stdout)
                .await
                .context("failed reading ssh stdout")?;
        }
        if let Some(mut err) = child.stderr.take() {
            err.read_to_string(&mut stderr)
                .await
                .context("failed reading ssh stderr")?;
        }

        let status = timeout(Duration::from_secs(60), child.wait())
            .await
            .map_err(|_| anyhow!("ssh timed out connecting to {destination}"))?
            .context("failed waiting for ssh")?;

        if !status.success() {
            return Err(anyhow!(
                "ssh exited with {status} against {destination}: {}",
                stderr.trim()
            ));
        }
        Ok(stdout)
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
}

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

    LinuxHostFacts {
        os_name,
        kernel,
        hostname,
        cpu,
        ram_total_mb,
        filesystems,
        services,
    }
}

/// Build normalized observations from parsed facts. The asset observation
/// always comes first so foreign keys resolve inside the store transaction.
pub fn linux_observations(ip: IpAddr, facts: &LinuxHostFacts) -> Vec<Observation> {
    let now = Utc::now();
    let id = ip.to_string().replace(['.', ':'], "-");
    let mut observations = vec![Observation::Asset(Asset {
        id: id.clone(),
        ip,
        hostname: facts.hostname.clone(),
        device_class: Some("server".into()),
        os_name: facts.os_name.clone(),
        os_version: facts.kernel.clone(),
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
        let assets = observations
            .iter()
            .filter(|o| matches!(o, Observation::Asset(_)))
            .count();
        let capacity = observations
            .iter()
            .filter(|o| matches!(o, Observation::Capacity(_)))
            .count();
        let filesystems = observations
            .iter()
            .filter(|o| matches!(o, Observation::Filesystem(_)))
            .count();
        let services = observations
            .iter()
            .filter(|o| matches!(o, Observation::RunningService(_)))
            .count();
        assert_eq!(assets, 1);
        assert_eq!(capacity, 1);
        assert_eq!(filesystems, 2);
        assert_eq!(services, 2);

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
