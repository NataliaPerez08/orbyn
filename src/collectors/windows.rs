//! Windows host collector (v0.3 milestone).
//!
//! Collects Windows host facts (OS, CPU, RAM, disks, running services) by
//! running read-only PowerShell queries on the target host over one of two
//! interchangeable transports:
//!
//! - [`WindowsTransport::Ssh`]: PowerShell over the OpenSSH Server feature,
//!   the same [`SshTransport`] and [`CredentialProfile`] used for Linux;
//! - [`WindowsTransport::WinRm`]: the native WS-Man/WinRM transport
//!   ([`crate::collectors::winrm::WinRmTransport`]) over HTTPS.
//!
//! Both transports run the same fixed probe script, so parsing and
//! observation building are transport-independent.
//!
//! Security rules mirror the Linux collector:
//! - the probe is a fixed constant string; only the host comes from user input;
//! - every PowerShell query is read-only (`Get-CimInstance`, `Get-Service`);
//! - SSH authentication is ssh-agent or identity-file based; WinRM
//!   authentication is Basic over HTTPS with the password held in memory
//!   only (see the winrm module). No secrets are stored or logged.

use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;

use crate::domain::{
    asset_id, Asset, Capacity, Connection, Filesystem, MetricSample, Observation, RunningService,
};
use crate::parsing::{normalize_ip, split_csv_line, split_sections};

use super::credentials::CredentialProfile;
use super::ssh::{SnapshotFacts, SshTransport, SNAPSHOT_INTERVAL_SECS};
use super::types::{Collector, CpuFacts, ScanTarget};
use super::winrm::WinRmTransport;

/// One read-only PowerShell probe. Sections are delimited by `###name`
/// string literals; CIM queries emit CSV via `ConvertTo-Csv`.
///
/// This is the transport-independent script. The SSH transport wraps it in
/// `powershell -NoProfile -Command "..."` ([`ssh_windows_command`]); the
/// WinRM transport sends it as an encoded command, which also removes the
/// remote-shell quoting constraints.
pub const WINDOWS_PROBE_SCRIPT: &str = "& { \
     '###os'; Get-CimInstance Win32_OperatingSystem \
       | Select-Object Caption,Version,BuildNumber,CSName \
       | ConvertTo-Csv -NoTypeInformation; \
     '###cpu'; Get-CimInstance Win32_Processor \
       | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors \
       | ConvertTo-Csv -NoTypeInformation; \
     '###ram'; [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory); \
     '###disk'; Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -eq 3 \
       | Select-Object DeviceID,FileSystem,VolumeName,Size,FreeSpace \
       | ConvertTo-Csv -NoTypeInformation; \
     '###svc'; Get-Service | Where-Object Status -eq Running \
       | Select-Object Name,DisplayName \
       | ConvertTo-Csv -NoTypeInformation; \
     '###conn'; Get-NetTCPConnection | Where-Object State -eq Established \
       | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort \
       | ConvertTo-Csv -NoTypeInformation; \
     '###virt'; Get-CimInstance Win32_ComputerSystem \
       | Select-Object Manufacturer,Model \
       | ConvertTo-Csv -NoTypeInformation; \
     '###metric'; for ($i = 0; $i -lt 3; $i++) { \
       $cpu = [math]::Round((Get-CimInstance Win32_Processor \
         | Measure-Object LoadPercentage -Average).Average, 1); \
       $os = Get-CimInstance Win32_OperatingSystem; \
       $pg = (Get-CimInstance Win32_PageFileUsage \
         | Measure-Object CurrentUsage -Sum).Sum; \
       if ($null -eq $pg) { $pg = 0 }; \
       [Console]::WriteLine(('{0}|{1}|{2}|{3}' -f \
         $cpu, $os.TotalVisibleMemorySize, $os.FreePhysicalMemory, $pg)); \
       if ($i -lt 2) { Start-Sleep -Seconds 2 } \
     } \
      }";

/// Wrap a PowerShell script in the command line the SSH transport runs.
pub fn ssh_windows_command(script: &str) -> String {
    format!("powershell -NoProfile -Command \"{script}\"")
}

/// Command transport for the Windows collector: runs a fixed read-only
/// PowerShell script on a host and returns its stdout.
pub enum WindowsTransport {
    /// PowerShell over the OpenSSH Server feature of the Windows host.
    Ssh(SshTransport),
    /// Native WS-Man/WinRM over HTTPS.
    WinRm(WinRmTransport),
}

impl WindowsTransport {
    /// Run `script` on `host`, returning its stdout.
    pub async fn run(&self, host: IpAddr, script: &str) -> Result<String> {
        match self {
            Self::Ssh(ssh) => ssh.run(host, &ssh_windows_command(script)).await,
            Self::WinRm(winrm) => winrm.run(host, script).await,
        }
    }

    /// The collector name recorded in discovery job history.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ssh(_) => "windows",
            Self::WinRm(_) => "winrm",
        }
    }
}

/// Windows host collector over a [`WindowsTransport`].
pub struct WindowsCollector {
    transport: WindowsTransport,
}

impl WindowsCollector {
    /// Collector over the SSH transport (PowerShell over OpenSSH).
    pub fn new(profile: CredentialProfile) -> Self {
        Self {
            transport: WindowsTransport::Ssh(SshTransport::new(profile)),
        }
    }

    /// Collector over an explicit transport (SSH or native WinRM).
    pub fn with_transport(transport: WindowsTransport) -> Self {
        Self { transport }
    }

    /// Parse probe output into facts without invoking the transport
    /// (fixture-testable).
    pub fn parse_probe(&self, output: &str) -> WindowsHostFacts {
        parse_windows_probe(output)
    }
}

impl Default for WindowsCollector {
    fn default() -> Self {
        Self::new(CredentialProfile::default())
    }
}

#[async_trait]
impl Collector for WindowsCollector {
    fn name(&self) -> &'static str {
        self.transport.name()
    }

    async fn scan(&self, target: &ScanTarget) -> Result<Vec<Observation>> {
        let ip = match target {
            ScanTarget::Ip(ip) => *ip,
            ScanTarget::Cidr(cidr) => bail!(
                "Windows collection targets a single host; target must be an IP address (got '{cidr}')"
            ),
        };
        let output = self
            .transport
            .run(ip, WINDOWS_PROBE_SCRIPT)
            .await
            .with_context(|| format!("Windows probe of {ip}"))?;
        let facts = parse_windows_probe(&output);
        Ok(windows_observations(ip, &facts))
    }
}

/// Host facts parsed from the Windows probe.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct WindowsHostFacts {
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub hostname: Option<String>,
    pub cpu: Option<CpuFacts>,
    pub ram_total_mb: Option<u64>,
    /// Canonical hypervisor id when virtualization evidence was found
    /// (see [`crate::collectors::virt`]).
    pub hypervisor: Option<String>,
    pub filesystems: Vec<Filesystem>,
    pub services: Vec<RunningService>,
    pub connections: Vec<Connection>,
    /// Utilization snapshots in probe order.
    pub metrics: Vec<SnapshotFacts>,
}

/// Parse the full Windows probe output into facts.
pub fn parse_windows_probe(output: &str) -> WindowsHostFacts {
    let sections = split_sections(output);
    let section = |name: &str| sections.get(name).cloned().unwrap_or_default();

    let os_rows = csv_rows(&section("os"));
    let (os_name, mut os_version, hostname) = match os_rows.first() {
        Some(row) if row.len() >= 4 => (field(row, 0), field(row, 1), field(row, 3)),
        _ => (None, None, None),
    };
    if let (Some(version), Some(build)) =
        (&os_version, os_rows.first().and_then(|row| field(row, 2)))
    {
        os_version = Some(format!("{version} build {build}"));
    }

    let cpu_rows = csv_rows(&section("cpu"));
    let cpu = if cpu_rows.is_empty() {
        None
    } else {
        let mut cores = 0u32;
        let mut threads = 0u32;
        let mut model = None;
        for row in &cpu_rows {
            if model.is_none() {
                model = field(row, 0);
            }
            if let Some(c) = field(row, 1).and_then(|v| v.parse::<u32>().ok()) {
                cores += c;
            }
            if let Some(t) = field(row, 2).and_then(|v| v.parse::<u32>().ok()) {
                threads += t;
            }
        }
        Some(CpuFacts {
            model,
            sockets: Some(cpu_rows.len() as u32),
            cores: if cores > 0 { Some(cores) } else { None },
            threads: if threads > 0 { Some(threads) } else { None },
        })
    };

    let ram_total_mb = section("ram")
        .first()
        .and_then(|l| l.trim().parse::<u64>().ok())
        .map(|bytes| (bytes + 524_288) / 1_048_576);

    // Virtualization evidence: Win32_ComputerSystem Manufacturer/Model.
    let virt_rows = csv_rows(&section("virt"));
    let hypervisor = virt_rows.first().and_then(|row| {
        super::virt::detect_windows(field(row, 0).as_deref(), field(row, 1).as_deref())
    });

    let mut filesystems = Vec::new();
    for row in csv_rows(&section("disk")) {
        let Some(size) = field(&row, 3).and_then(|v| v.parse::<u64>().ok()) else {
            continue;
        };
        let free = field(&row, 4).and_then(|v| v.parse::<u64>().ok());
        let Some(mount) = field(&row, 0) else {
            continue;
        };
        filesystems.push(Filesystem {
            asset_id: String::new(),
            device: None,
            mount,
            fs_type: field(&row, 1),
            size_kb: (size + 512) / 1024,
            used_kb: free.map(|f| (size.saturating_sub(f) + 512) / 1024),
            available_kb: free.map(|f| (f + 512) / 1024),
            used_pct: free.map(|f| {
                (size.saturating_sub(f) * 100)
                    .checked_div(size)
                    .unwrap_or(0) as u32
            }),
        });
    }

    let mut services = Vec::new();
    for row in csv_rows(&section("svc")) {
        let Some(name) = field(&row, 0) else {
            continue;
        };
        services.push(RunningService {
            asset_id: String::new(),
            name,
            state: Some("running".into()),
            description: field(&row, 1),
        });
    }

    let mut connections = Vec::new();
    for row in csv_rows(&section("conn")) {
        let Some(remote_ip) = field(&row, 2).and_then(|v| normalize_ip(&v)) else {
            continue;
        };
        let Some(remote_port) = field(&row, 3).and_then(|v| v.parse::<u16>().ok()) else {
            continue;
        };
        if remote_ip.is_loopback() {
            continue;
        }
        let local_ip = field(&row, 0).and_then(|v| normalize_ip(&v));
        if local_ip == Some(remote_ip) {
            continue;
        }
        connections.push(Connection {
            asset_id: String::new(),
            proto: "tcp".into(),
            local_ip,
            local_port: field(&row, 1).and_then(|v| v.parse::<u16>().ok()),
            remote_ip,
            remote_port,
            process: None,
        });
    }

    let metrics = parse_windows_metric_lines(&section("metric"));

    WindowsHostFacts {
        os_name,
        os_version,
        hostname,
        cpu,
        ram_total_mb,
        hypervisor,
        filesystems,
        services,
        connections,
        metrics,
    }
}

/// Parse `###metric` lines of the shape `cpu_load|total_kb|free_kb|page_used_mb`.
/// CPU load is the instantaneous average processor load percentage, so there
/// are no load-average fields on Windows.
fn parse_windows_metric_lines(lines: &[String]) -> Vec<SnapshotFacts> {
    let mut out = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split('|');
        let cpu: Option<f32> = parts.next().and_then(|v| v.trim().parse().ok());
        let total_kb: Option<u64> = parts.next().and_then(|v| v.trim().parse().ok());
        let free_kb: Option<u64> = parts.next().and_then(|v| v.trim().parse().ok());
        let page_mb: Option<u64> = parts.next().and_then(|v| v.trim().parse().ok());

        let ram_used_mb = match (total_kb, free_kb) {
            (Some(total), Some(free)) if total >= free => Some((total - free) / 1024),
            _ => None,
        };

        if cpu.is_none() && ram_used_mb.is_none() {
            continue;
        }

        out.push(SnapshotFacts {
            cpu_usage_percent: cpu,
            ram_used_mb,
            ram_available_mb: free_kb.map(|kb| kb / 1024),
            swap_used_mb: page_mb.filter(|v| *v > 0),
            load_1m: None,
            load_5m: None,
            load_15m: None,
        });
    }
    out
}

/// Build normalized observations from parsed facts. The asset observation
/// always comes first so foreign keys resolve inside the store transaction.
pub fn windows_observations(ip: IpAddr, facts: &WindowsHostFacts) -> Vec<Observation> {
    let now = Utc::now();
    let id = asset_id(ip);
    let mut observations = vec![Observation::Asset(Asset {
        id: id.clone(),
        ip,
        hostname: facts.hostname.clone(),
        device_class: Some("server".into()),
        os_name: facts.os_name.clone(),
        os_version: facts.os_version.clone(),
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
            hypervisor: facts.hypervisor.clone(),
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
            load_1m: None,
            load_5m: None,
            load_15m: None,
        }));
    }
    observations
}

/// Parse CSV lines (PowerShell `ConvertTo-Csv`) into rows, skipping the
/// header line.
fn csv_rows(lines: &[String]) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut header_seen = false;
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !header_seen {
            header_seen = true;
            continue;
        }
        rows.push(split_csv_line(line));
    }
    rows
}

/// A non-empty trimmed field of a CSV row.
fn field(row: &[String], idx: usize) -> Option<String> {
    row.get(idx)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_command_wraps_the_probe_script() {
        let command = ssh_windows_command(WINDOWS_PROBE_SCRIPT);
        assert!(command.starts_with("powershell -NoProfile -Command \"& {"));
        assert!(command.ends_with("}\""));
        assert!(command.contains("Get-CimInstance Win32_OperatingSystem"));
    }

    #[test]
    fn transport_names_are_distinct() {
        let ssh = WindowsTransport::Ssh(SshTransport::new(CredentialProfile::default()));
        assert_eq!(ssh.name(), "windows");
    }

    const PROBE_OUTPUT: &str = "###os\n\
\"Caption\",\"Version\",\"BuildNumber\",\"CSName\"\n\
\"Microsoft Windows Server 2022 Standard\",\"10.0\",\"20348\",\"WIN-APP01\"\n\
###cpu\n\
\"Name\",\"NumberOfCores\",\"NumberOfLogicalProcessors\"\n\
\"Intel(R) Xeon(R) Silver 4310 CPU @ 2.20GHz\",\"12\",\"24\"\n\
###ram\n\
17179869184\n\
###disk\n\
\"DeviceID\",\"FileSystem\",\"VolumeName\",\"Size\",\"FreeSpace\"\n\
\"C:\",\"NTFS\",\"System\",\"107374182400\",\"53687091200\"\n\
\"D:\",\"NTFS\",\"Data\",\"214748364800\",\"107374182400\"\n\
###svc\n\
\"Name\",\"DisplayName\"\n\
\"W3SVC\",\"World Wide Web Publishing Service\"\n\
\"MSSQLSERVER\",\"SQL Server (MSSQLSERVER)\"\n\
###conn\n\
\"LocalAddress\",\"LocalPort\",\"RemoteAddress\",\"RemotePort\"\n\
\"10.0.0.20\",\"49222\",\"10.0.0.5\",\"443\"\n\
\"10.0.0.20\",\"49223\",\"10.0.0.9\",\"5432\"\n\
\"10.0.0.20\",\"49224\",\"127.0.0.1\",\"5432\"\n\
###metric\n\
45.5|16777216|8388608|512\n\
12.0|16777216|12582912|512\n";

    #[test]
    fn parses_full_probe() {
        let facts = parse_windows_probe(PROBE_OUTPUT);

        assert_eq!(
            facts.os_name.as_deref(),
            Some("Microsoft Windows Server 2022 Standard")
        );
        assert_eq!(facts.os_version.as_deref(), Some("10.0 build 20348"));
        assert_eq!(facts.hostname.as_deref(), Some("WIN-APP01"));

        let cpu = facts.cpu.expect("cpu facts");
        assert_eq!(
            cpu.model.as_deref(),
            Some("Intel(R) Xeon(R) Silver 4310 CPU @ 2.20GHz")
        );
        assert_eq!(cpu.sockets, Some(1));
        assert_eq!(cpu.cores, Some(12));
        assert_eq!(cpu.threads, Some(24));

        assert_eq!(facts.ram_total_mb, Some(16384));

        assert_eq!(facts.filesystems.len(), 2);
        let c = facts.filesystems.iter().find(|f| f.mount == "C:").unwrap();
        assert_eq!(c.fs_type.as_deref(), Some("NTFS"));
        assert_eq!(c.size_kb, 104857600);
        assert_eq!(c.available_kb, Some(52428800));
        assert_eq!(c.used_pct, Some(50));

        assert_eq!(facts.services.len(), 2);
        assert_eq!(facts.services[0].name, "W3SVC");
        assert_eq!(facts.services[0].state.as_deref(), Some("running"));
        assert_eq!(
            facts.services[0].description.as_deref(),
            Some("World Wide Web Publishing Service")
        );

        // loopback remotes are dropped
        assert_eq!(facts.connections.len(), 2);
        let to_web = facts
            .connections
            .iter()
            .find(|c| c.remote_port == 443)
            .unwrap();
        assert_eq!(to_web.remote_ip.to_string(), "10.0.0.5");
        assert_eq!(to_web.local_port, Some(49222));
        assert_eq!(to_web.proto, "tcp");
    }

    #[test]
    fn virt_section_becomes_capacity_hypervisor() {
        let output = "###virt\n\
\"Manufacturer\",\"Model\"\n\
\"Microsoft Corporation\",\"Virtual Machine\"\n\
###cpu\n\
\"Name\",\"NumberOfCores\",\"NumberOfLogicalProcessors\"\n\
\"Intel(R) Xeon(R) Silver 4310 CPU @ 2.20GHz\",\"12\",\"24\"\n";
        let facts = parse_windows_probe(output);
        assert_eq!(facts.hypervisor.as_deref(), Some("hyperv"));

        let observations = windows_observations("10.0.0.20".parse().unwrap(), &facts);
        let capacity = observations
            .iter()
            .find_map(|o| match o {
                Observation::Capacity(c) => Some(c),
                _ => None,
            })
            .expect("capacity observation");
        assert_eq!(capacity.hypervisor.as_deref(), Some("hyperv"));
    }

    #[test]
    fn physical_windows_host_reports_no_hypervisor() {
        let output = "###virt\n\
\"Manufacturer\",\"Model\"\n\
\"Dell Inc.\",\"PowerEdge R740\"\n";
        let facts = parse_windows_probe(output);
        assert_eq!(facts.hypervisor, None);
    }

    #[test]
    fn sums_multi_socket_cpus() {
        let cpu_section = "\"Name\",\"NumberOfCores\",\"NumberOfLogicalProcessors\"\n\
\"Xeon E5-2680 v4\",\"14\",\"28\"\n\
\"Xeon E5-2680 v4\",\"14\",\"28\"\n";
        let output = format!("###cpu\n{cpu_section}");
        let facts = parse_windows_probe(&output);
        let cpu = facts.cpu.unwrap();
        assert_eq!(cpu.sockets, Some(2));
        assert_eq!(cpu.cores, Some(28));
        assert_eq!(cpu.threads, Some(56));
    }

    #[test]
    fn builds_observations_with_asset_first() {
        let facts = parse_windows_probe(PROBE_OUTPUT);
        let observations = windows_observations("10.0.0.20".parse().unwrap(), &facts);

        assert!(matches!(observations[0], Observation::Asset(_)));
        // asset + capacity + 2 disks + 2 services + 2 connections + 2 metrics
        assert_eq!(observations.len(), 10);

        if let Some(Observation::Asset(asset)) = observations.first() {
            assert_eq!(asset.device_class.as_deref(), Some("server"));
            assert_eq!(asset.hostname.as_deref(), Some("WIN-APP01"));
        }
    }

    #[test]
    fn parses_windows_metric_snapshots() {
        let facts = parse_windows_probe(PROBE_OUTPUT);
        assert_eq!(facts.metrics.len(), 2);
        assert_eq!(facts.metrics[0].cpu_usage_percent, Some(45.5));
        assert_eq!(facts.metrics[0].ram_used_mb, Some(8192)); // (16777216-8388608)/1024
        assert_eq!(facts.metrics[0].ram_available_mb, Some(8192));
        assert_eq!(facts.metrics[0].swap_used_mb, Some(512));
        assert_eq!(facts.metrics[0].load_1m, None);
        assert_eq!(facts.metrics[1].ram_used_mb, Some(4096));

        let observations = windows_observations("10.0.0.20".parse().unwrap(), &facts);
        let metrics: Vec<&Observation> = observations
            .iter()
            .filter(|o| matches!(o, Observation::MetricSample(_)))
            .collect();
        assert_eq!(metrics.len(), 2);
        if let (Observation::MetricSample(a), Observation::MetricSample(b)) =
            (&metrics[0], &metrics[1])
        {
            assert!(a.sampled_at <= b.sampled_at);
        }
    }

    #[test]
    fn empty_probe_yields_asset_only() {
        let facts = parse_windows_probe("");
        let observations = windows_observations("10.0.0.21".parse().unwrap(), &facts);
        assert_eq!(observations.len(), 1);
    }

    #[test]
    fn crlf_csv_rows_parse() {
        let output = "###svc\r\n\"Name\",\"DisplayName\"\r\n\"W32Time\",\"Windows Time\"\r\n";
        let facts = parse_windows_probe(output);
        assert_eq!(facts.services.len(), 1);
        assert_eq!(facts.services[0].name, "W32Time");
    }
}
