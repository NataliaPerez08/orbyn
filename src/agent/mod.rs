//! Local profiler agent (ROADMAP_V2 v1.5).
//!
//! Samples the local host's CPU/RAM/swap/load on an interval and persists
//! the same [`MetricSample`] rows the SSH/Prometheus collectors write, so
//! `orbyn metrics`, assessment and the right-sizing rules work on agent
//! data unchanged. On a slower "facts" cadence it refreshes filesystem and
//! connection observations, which upsert idempotently.
//!
//! Platform sampling:
//!
//! - Linux: CPU from `/proc/stat` deltas, memory from `/proc/meminfo`,
//!   load from `/proc/loadavg` — no subprocesses for sampling. Facts come
//!   from `df -kPT` and `ss -tnp` through the shared SSH-collector parsers.
//! - Windows: one local PowerShell probe per sample (processor load,
//!   physical memory, page-file usage — the same `cpu|total|free|page`
//!   line the remote collector parses). Facts run the full read-only
//!   [`WINDOWS_PROBE_SCRIPT`] locally and reuse its parser and observation
//!   builder, minus its snapshot samples (the agent's interval samples are
//!   the real history; snapshots must not pollute the window).
//!
//! Restart resilience is by construction: samples are timestamped,
//! append-only rows (idempotent on `(asset_id, sampled_at)`), so a
//! restarted agent simply resumes appending. Retention prunes old rows on
//! start and hourly.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, Result};
pub mod sync;

use chrono::{DateTime, Utc};
use tokio::signal::ctrl_c;

use crate::domain::{asset_id, MetricSample, Observation};
use crate::process::{run_captured, MAX_STDERR_CAPTURE_BYTES};
use crate::store::Store;

/// Pause between the two `/proc/stat` reads behind one CPU sample.
#[cfg(unix)]
const CPU_DELTA_PAUSE: Duration = Duration::from_millis(250);
/// Cap for one local facts/metric probe subprocess.
const FACTS_TIMEOUT: Duration = Duration::from_secs(60);
const FACTS_STDOUT_CAP: u64 = 4 * 1024 * 1024;

/// Agent run configuration (CLI flags resolved).
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub asset_ip: IpAddr,
    pub interval: Duration,
    pub retention: chrono::Duration,
    /// `None` = run forever until signalled; `Some(0)` = `--once`.
    pub duration: Option<Duration>,
    pub facts_interval: Duration,
}

/// Memory facts extracted from `/proc/meminfo`, in whole megabytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg(unix)]
pub struct MemFacts {
    pub ram_total_mb: Option<u64>,
    pub ram_available_mb: Option<u64>,
    pub swap_total_mb: Option<u64>,
    pub swap_free_mb: Option<u64>,
}

impl MemFacts {
    pub fn ram_used_mb(&self) -> Option<u64> {
        match (self.ram_total_mb, self.ram_available_mb) {
            (Some(total), Some(available)) => Some(total.saturating_sub(available)),
            _ => None,
        }
    }
    pub fn swap_used_mb(&self) -> Option<u64> {
        match (self.swap_total_mb, self.swap_free_mb) {
            (Some(total), Some(free)) => Some(total.saturating_sub(free)),
            _ => None,
        }
    }
}

/// Load averages from `/proc/loadavg`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg(unix)]
pub struct LoadFacts {
    pub load_1m: Option<f32>,
    pub load_5m: Option<f32>,
    pub load_15m: Option<f32>,
}

/// Run the agent loop until `duration` elapses (or forever when `None`),
/// or SIGINT/SIGTERM arrives. Returns the number of samples persisted.
pub async fn run(store: &dyn Store, config: &AgentConfig) -> Result<usize> {
    let id = asset_id(config.asset_ip);
    ensure_asset(store, &id, config.asset_ip).await;
    prune(store, config).await?;

    let started = std::time::Instant::now();
    let mut persisted = 0usize;
    #[cfg(unix)]
    let mut last_stat = read_proc_stat().await?;
    #[cfg(windows)]
    let mut last_stat = String::new();
    let mut next_facts = std::time::Instant::now();
    let mut next_prune = std::time::Instant::now() + Duration::from_secs(3600);
    tracing::info!(
        asset = %id,
        interval_secs = config.interval.as_secs(),
        "agent loop started"
    );

    loop {
        // Sample first, then wait: `--once` still produces one sample.
        let sample = take_sample(&id, &mut last_stat).await?;
        store.insert_metric_samples(&[sample]).await?;
        persisted += 1;

        if std::time::Instant::now() >= next_facts {
            collect_facts(store, &id, config.asset_ip).await;
            next_facts = std::time::Instant::now() + config.facts_interval;
        }
        if std::time::Instant::now() >= next_prune {
            prune(store, config).await?;
            next_prune = std::time::Instant::now() + Duration::from_secs(3600);
        }

        if let Some(duration) = config.duration {
            if started.elapsed() >= duration {
                break;
            }
        }
        let pause = tokio::time::sleep(config.interval);
        tokio::select! {
            _ = pause => {}
            _ = ctrl_c() => break,
            _ = shutdown_signal() => break,
        }
    }
    tracing::info!(asset = %id, persisted, "agent loop stopped");
    Ok(persisted)
}

/// Delete samples older than the retention window.
async fn prune(store: &dyn Store, config: &AgentConfig) -> Result<()> {
    let cutoff = Utc::now() - config.retention;
    let removed = store.delete_metric_samples_before(cutoff).await?;
    if removed > 0 {
        tracing::info!(removed, "pruned metric samples past retention");
    }
    Ok(())
}

/// Make sure the local asset row exists (metric samples carry an FK to
/// assets). The upsert COALESCEs every optional field, so a bare agent
/// asset never clobbers facts an earlier discovery collected.
pub(crate) async fn ensure_asset(store: &dyn Store, id: &str, ip: IpAddr) {
    let now = Utc::now();
    let hostname = probe_lines(&["hostname"])
        .await
        .ok()
        .and_then(|lines| lines.first().cloned());
    let asset = crate::domain::Asset {
        id: id.to_string(),
        ip,
        hostname,
        device_class: None,
        os_name: None,
        os_version: None,
        sys_descr: None,
        environment: None,
        owner: None,
        criticality: None,
        tags: Vec::new(),
        first_seen: now,
        last_seen: now,
    };
    if let Err(e) = store.store_observation(Observation::Asset(asset)).await {
        tracing::warn!("agent could not ensure its asset row: {e:#}");
    }
}

/// Build one sample right now from a `/proc/stat` delta plus current
/// memory and load facts.
#[cfg(unix)]
fn sample_now(id: &str, prev_stat: &str, cur_stat: &str) -> Result<MetricSample> {
    let mem = parse_meminfo(&read_file("/proc/meminfo")?);
    let load = parse_loadavg(&read_file("/proc/loadavg")?);
    Ok(MetricSample {
        asset_id: id.to_string(),
        sampled_at: Utc::now(),
        cpu_usage_percent: cpu_percent(prev_stat, cur_stat),
        ram_used_mb: mem.ram_used_mb(),
        ram_available_mb: mem.ram_available_mb,
        swap_used_mb: mem.swap_used_mb(),
        load_1m: load.load_1m,
        load_5m: load.load_5m,
        load_15m: load.load_15m,
    })
}

/// Take one sample right now. Platform dispatch: Linux reads `/proc`
/// twice around a short pause; Windows runs the local PowerShell metric
/// probe. `last_stat` carries the previous `/proc/stat` read on Linux and
/// is unused on Windows.
#[cfg(unix)]
async fn take_sample(id: &str, last_stat: &mut String) -> Result<MetricSample> {
    tokio::time::sleep(CPU_DELTA_PAUSE).await;
    let stat = read_proc_stat().await?;
    let sample = sample_now(id, last_stat, &stat)?;
    *last_stat = stat;
    Ok(sample)
}

#[cfg(windows)]
async fn take_sample(id: &str, _last_stat: &mut String) -> Result<MetricSample> {
    let output = probe_output(&windows_metric_command()).await?;
    let lines: Vec<String> = output.lines().map(str::to_string).collect();
    windows_sample_from_lines(id, &lines)
        .ok_or_else(|| anyhow::anyhow!("windows metric probe produced no sample line"))
}

/// Map the first parseable `cpu|total_kb|free_kb|page_mb` line to a sample.
/// Pure so it is testable on every platform.
#[cfg(any(windows, test))]
pub(crate) fn windows_sample_from_lines(id: &str, lines: &[String]) -> Option<MetricSample> {
    let snap = crate::collectors::windows::parse_windows_metric_lines(lines)
        .into_iter()
        .next()?;
    Some(MetricSample {
        asset_id: id.to_string(),
        sampled_at: Utc::now(),
        cpu_usage_percent: snap.cpu_usage_percent,
        ram_used_mb: snap.ram_used_mb,
        ram_available_mb: snap.ram_available_mb,
        swap_used_mb: snap.swap_used_mb,
        load_1m: None,
        load_5m: None,
        load_15m: None,
    })
}

/// Refresh filesystem/connection facts. Failures degrade to a warning:
/// facts must never kill sampling.
#[cfg(unix)]
async fn collect_facts(store: &dyn Store, id: &str, _ip: IpAddr) {
    use crate::collectors::ssh::{parse_connections, parse_df};
    if let Ok(lines) = probe_lines(&["df", "-kPT"]).await {
        let filesystems: Vec<Observation> = parse_df(&lines)
            .into_iter()
            .map(|mut fs| {
                fs.asset_id = id.to_string();
                Observation::Filesystem(fs)
            })
            .collect();
        if !filesystems.is_empty() {
            if let Err(e) = store.store_observations(filesystems).await {
                tracing::warn!("agent filesystem facts failed: {e:#}");
            }
        }
    }
    if let Ok(lines) = probe_lines(&["ss", "-tnp", "state", "established"]).await {
        let connections: Vec<Observation> = parse_connections(&lines)
            .into_iter()
            .map(|mut c| {
                c.asset_id = id.to_string();
                Observation::Connection(c)
            })
            .collect();
        if !connections.is_empty() {
            if let Err(e) = store.store_observations(connections).await {
                tracing::warn!("agent connection facts failed: {e:#}");
            }
        }
    }
}

#[cfg(windows)]
async fn collect_facts(store: &dyn Store, _id: &str, ip: IpAddr) {
    // The full read-only probe doubles as the facts refresh: OS identity,
    // disks, running services and connections, reusing the remote
    // collector's parser and observation builder. Its three snapshot
    // samples are dropped — interval samples are the real history.
    let output = match probe_output(&windows_facts_command()).await {
        Ok(output) => output,
        Err(e) => {
            tracing::warn!("agent facts probe failed: {e:#}");
            return;
        }
    };
    let facts = crate::collectors::windows::parse_windows_probe(&output);
    let observations: Vec<Observation> =
        crate::collectors::windows::windows_observations(ip, &facts)
            .into_iter()
            .filter(|o| !matches!(o, Observation::MetricSample(_)))
            .collect();
    if let Err(e) = store.store_observations(observations).await {
        tracing::warn!("agent facts persistence failed: {e:#}");
    }
}

/// Local PowerShell argument vector for one metric sample.
#[cfg(windows)]
fn windows_metric_command() -> Vec<String> {
    let script = "& { \
        $cpu = [math]::Round((Get-CimInstance Win32_Processor \
          | Measure-Object LoadPercentage -Average).Average, 1); \
        $os = Get-CimInstance Win32_OperatingSystem; \
        $pg = (Get-CimInstance Win32_PageFileUsage \
          | Measure-Object CurrentUsage -Sum).Sum; \
        if ($null -eq $pg) { $pg = 0 }; \
        [Console]::WriteLine(('{0}|{1}|{2}|{3}' -f \
          $cpu, $os.TotalVisibleMemorySize, $os.FreePhysicalMemory, $pg)) \
      }";
    vec![
        "powershell".to_string(),
        "-NoProfile".to_string(),
        "-Command".to_string(),
        script.to_string(),
    ]
}

/// Local PowerShell argument vector for the full facts probe.
#[cfg(windows)]
fn windows_facts_command() -> Vec<String> {
    vec![
        "powershell".to_string(),
        "-NoProfile".to_string(),
        "-Command".to_string(),
        crate::collectors::windows::WINDOWS_PROBE_SCRIPT.to_string(),
    ]
}

/// Run a local probe and return its raw stdout.
async fn probe_output(argv: &[String]) -> Result<String> {
    use std::process::Stdio;
    use tokio::process::Command;
    let child = Command::new(&argv[0])
        .args(&argv[1..])
        .env_remove("ORBYN_SNMP_COMMUNITY")
        .env_remove("ORBYN_NETBOX_TOKEN")
        .env_remove("ORBYN_WINRM_PASSWORD")
        .env_remove("ORBYN_PROMETHEUS_TOKEN")
        .env_remove("ORBYN_DB")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting {}", argv[0]))?;
    let captured = run_captured(
        child,
        None,
        FACTS_STDOUT_CAP,
        MAX_STDERR_CAPTURE_BYTES,
        FACTS_TIMEOUT,
        format!("{} probe timed out", argv[0]),
    )
    .await?;
    if !captured.status.success() {
        anyhow::bail!("{} exited with {}", argv[0], captured.status);
    }
    Ok(captured.stdout)
}

/// Run a facts probe and split its stdout into lines.
async fn probe_lines(argv: &[&str]) -> Result<Vec<String>> {
    let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    Ok(probe_output(&owned)
        .await?
        .lines()
        .map(str::to_string)
        .collect())
}

/// SIGTERM (Unix); Windows uses ctrl_c alone.
#[cfg(unix)]
pub(crate) async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let _ = signal(SignalKind::terminate())
        .expect("install SIGTERM handler")
        .recv()
        .await;
}

#[cfg(windows)]
pub(crate) async fn shutdown_signal() {
    std::future::pending::<()>().await
}

/// Detect the local host's primary IP without sending traffic: a connected
/// UDP socket makes the OS pick a local address for the route. Falls back
/// to loopback when there is no route at all.
pub fn detect_local_ip() -> IpAddr {
    let probe: SocketAddr = "192.0.2.1:80".parse().expect("static address parses");
    match std::net::UdpSocket::bind("0.0.0.0:0").and_then(|sock| {
        sock.connect(probe)?;
        sock.local_addr()
    }) {
        Ok(addr) => addr.ip(),
        Err(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
    }
}

#[cfg(unix)]
fn read_file(path: &str) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {path}"))
}

#[cfg(unix)]
async fn read_proc_stat() -> Result<String> {
    // A tiny blocking read of a /proc file; microseconds on any system.
    tokio::task::spawn_blocking(move || read_file("/proc/stat"))
        .await
        .context("joining /proc/stat read task")?
}

/// CPU busy percent between two `/proc/stat` reads, from the aggregate
/// `cpu` line. `None` when either read lacks the line or no time passed.
#[cfg(unix)]
pub fn cpu_percent(prev_stat: &str, cur_stat: &str) -> Option<f32> {
    let prev = cpu_ticks(prev_stat)?;
    let cur = cpu_ticks(cur_stat)?;
    let total = cur.total.saturating_sub(prev.total);
    if total == 0 {
        return None;
    }
    let idle = cur.idle.saturating_sub(prev.idle);
    Some((1.0 - idle as f32 / total as f32) * 100.0)
}

/// Aggregate `cpu  user nice system idle iowait irq softirq steal ...`
/// ticks. Idle includes iowait; total includes everything parsed.
#[cfg(unix)]
fn cpu_ticks(stat: &str) -> Option<CpuTicks> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|f| f.parse().ok())
        .collect();
    if fields.len() < 4 {
        return None;
    }
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    let total: u64 = fields.iter().sum();
    Some(CpuTicks { idle, total })
}

#[cfg(unix)]
struct CpuTicks {
    idle: u64,
    total: u64,
}

/// Parse `/proc/meminfo` into whole megabytes (rounded), matching the
/// SSH collector's `MemTotal` rounding.
#[cfg(unix)]
pub fn parse_meminfo(content: &str) -> MemFacts {
    let kb = |key: &str| {
        content.lines().find(|l| l.starts_with(key)).and_then(|l| {
            l.split_whitespace()
                .nth(1)
                .and_then(|v| v.parse::<u64>().ok())
        })
    };
    let mb = |key: &str| kb(key).map(|v| (v + 512) / 1024);
    MemFacts {
        ram_total_mb: mb("MemTotal"),
        ram_available_mb: mb("MemAvailable"),
        swap_total_mb: mb("SwapTotal"),
        swap_free_mb: mb("SwapFree"),
    }
}

/// Parse `0.52 0.58 0.59 1/511 12345 ...` from `/proc/loadavg`.
#[cfg(unix)]
pub fn parse_loadavg(content: &str) -> LoadFacts {
    let mut fields = content.split_whitespace();
    LoadFacts {
        load_1m: fields.next().and_then(|v| v.parse().ok()),
        load_5m: fields.next().and_then(|v| v.parse().ok()),
        load_15m: fields.next().and_then(|v| v.parse().ok()),
    }
}

/// Sample coverage of a stored window: count, span, and the largest gap
/// between consecutive samples (the restart/outage signal).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Coverage {
    pub sample_count: usize,
    pub first: Option<DateTime<Utc>>,
    pub last: Option<DateTime<Utc>>,
    pub span_hours: Option<f64>,
    /// Largest gap between consecutive samples, in seconds.
    pub largest_gap_secs: Option<f64>,
}

pub fn coverage(samples: &[MetricSample]) -> Coverage {
    let mut cov = Coverage {
        sample_count: samples.len(),
        first: samples.first().map(|s| s.sampled_at),
        last: samples.last().map(|s| s.sampled_at),
        span_hours: None,
        largest_gap_secs: None,
    };
    if let (Some(first), Some(last)) = (cov.first, cov.last) {
        cov.span_hours = Some((last - first).num_minutes() as f64 / 60.0);
    }
    let mut largest: Option<f64> = None;
    for pair in samples.windows(2) {
        let gap = (pair[1].sampled_at - pair[0].sampled_at).num_milliseconds() as f64 / 1000.0;
        largest = Some(match largest {
            Some(l) if l >= gap => l,
            _ => gap,
        });
    }
    cov.largest_gap_secs = largest;
    cov
}

/// Render the agent report as a standalone static HTML document (no JS,
/// no dependencies): window stats plus coverage.
pub fn render_html(stats: &crate::metrics::WindowStats, cov: &Coverage, asset: &str) -> String {
    let esc = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let opt_f = |v: Option<f64>, suffix: &str| match v {
        Some(v) => format!("{v:.1}{suffix}"),
        None => "-".to_string(),
    };
    let opt_u = |v: Option<u64>, suffix: &str| match v {
        Some(v) => format!("{v}{suffix}"),
        None => "-".to_string(),
    };
    let readiness = if stats.right_sizing_ready() {
        "ready"
    } else {
        "not ready"
    };
    let cpu = format!(
        "{} / {} / {} / {}",
        opt_f(stats.cpu_avg_percent, "%"),
        opt_f(stats.cpu_p95_percent, "%"),
        opt_f(stats.cpu_p99_percent, "%"),
        opt_f(stats.cpu_peak_percent, "%")
    );
    let ram = format!(
        "{} / {} / {} / {}",
        opt_u(stats.ram_avg_mb.map(|v| v as u64), " MB"),
        opt_u(stats.ram_p95_mb.map(|v| v as u64), " MB"),
        opt_u(stats.ram_p99_mb.map(|v| v as u64), " MB"),
        opt_u(stats.ram_peak_mb.map(|v| v as u64), " MB")
    );
    let swap = format!(
        "{} / {} / {}",
        opt_u(stats.swap_avg_mb.map(|v| v as u64), " MB"),
        opt_u(stats.swap_p95_mb.map(|v| v as u64), " MB"),
        opt_u(stats.swap_peak_mb.map(|v| v as u64), " MB")
    );
    let first = cov
        .first
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "-".into());
    let last = cov
        .last
        .map(|t| t.to_rfc3339())
        .unwrap_or_else(|| "-".into());
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Orbyn agent report — {asset_esc}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a2e; }}
table {{ border-collapse: collapse; margin-top: 1rem; }}
th, td {{ border: 1px solid #d0d0dd; padding: .4rem .8rem; text-align: left; }}
th {{ background: #f2f2fa; }}
h2 {{ margin-top: 2rem; }}
</style>
</head>
<body>
<h1>Orbyn agent report</h1>
<p>Asset: <strong>{asset_esc}</strong> · generated {generated}</p>

<h2>Utilization window</h2>
<table>
<tr><th>samples</th><td>{samples}</td></tr>
<tr><th>span</th><td>{span}</td></tr>
<tr><th>confidence</th><td>{confidence}</td></tr>
<tr><th>right-sizing</th><td>{readiness}</td></tr>
<tr><th>CPU avg / p95 / p99 / peak</th><td>{cpu}</td></tr>
<tr><th>RAM used avg / p95 / p99 / peak</th><td>{ram}</td></tr>
<tr><th>swap used avg / p95 / peak</th><td>{swap}</td></tr>
</table>

<h2>Coverage</h2>
<table>
<tr><th>first sample</th><td>{first}</td></tr>
<tr><th>last sample</th><td>{last}</td></tr>
<tr><th>largest gap</th><td>{gap}</td></tr>
</table>
</body>
</html>
"#,
        asset_esc = esc(asset),
        generated = Utc::now().to_rfc3339(),
        samples = stats.sample_count,
        span = opt_f(stats.span_hours, " h"),
        confidence = stats.confidence,
        readiness = readiness,
        cpu = cpu,
        ram = ram,
        swap = swap,
        first = first,
        last = last,
        gap = opt_f(cov.largest_gap_secs, " s"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT_A: &str = "cpu  100 0 100 790 10 0 0 0 0 0\n";
    const STAT_B: &str = "cpu  110 0 110 780 10 0 0 0 0 0\n";

    #[cfg(unix)]
    #[test]
    fn cpu_percent_from_stat_delta() {
        // A: total=1000, idle=800. B: total=1010, idle=790.
        // delta total=10, delta idle=-10 -> busy 200%? No: idle decreased,
        // clamp at saturating_sub -> 0 idle delta over 10 total = 100%.
        // Use a realistic pair instead:
        let a = "cpu  500 0 300 7000 100 0 0 0\n";
        let b = "cpu  520 0 320 7010 100 0 0 0\n";
        // total delta = 50, idle delta = 10 -> 80% busy.
        let pct = cpu_percent(a, b).expect("delta computes");
        assert!((pct - 80.0).abs() < 0.01, "got {pct}");
        assert_eq!(cpu_percent(a, a), None, "no elapsed time -> None");
        assert_eq!(cpu_percent("garbage", a), None);
    }

    #[cfg(unix)]
    #[test]
    fn cpu_percent_handles_stat_a_b_pair() {
        // STAT_A total=1000 idle=800; STAT_B total=1010 idle=790:
        // delta total=10, delta idle=-10 -> clamped 0 -> 100% busy.
        let pct = cpu_percent(STAT_A, STAT_B).expect("delta computes");
        assert!((pct - 100.0).abs() < 0.01, "got {pct}");
    }

    #[cfg(unix)]
    #[test]
    fn meminfo_parses_all_fields() {
        let mem = parse_meminfo(
            "MemTotal:       16384532 kB\n\
             MemFree:         1234567 kB\n\
             MemAvailable:    8388608 kB\n\
             SwapTotal:       2097148 kB\n\
             SwapFree:        1048574 kB\n",
        );
        assert_eq!(mem.ram_total_mb, Some(16001));
        assert_eq!(mem.ram_available_mb, Some(8192));
        assert_eq!(mem.swap_total_mb, Some(2048));
        assert_eq!(mem.swap_free_mb, Some(1024));
        assert_eq!(mem.ram_used_mb(), Some(7809));
        assert_eq!(mem.swap_used_mb(), Some(1024));
        assert_eq!(parse_meminfo("").ram_total_mb, None);
        assert_eq!(parse_meminfo("").ram_used_mb(), None);
    }

    #[cfg(unix)]
    #[test]
    fn loadavg_parses_three_values() {
        let load = parse_loadavg("0.52 0.58 0.59 1/511 12345\n");
        assert_eq!(load.load_1m, Some(0.52));
        assert_eq!(load.load_5m, Some(0.58));
        assert_eq!(load.load_15m, Some(0.59));
        assert_eq!(parse_loadavg("").load_1m, None);
    }

    #[test]
    fn windows_sample_line_maps_to_metric_sample() {
        let lines: Vec<String> = vec!["12.5|16767948|8388608|256".into(), "".into()];
        let sample = windows_sample_from_lines("win-host", &lines).expect("line maps");
        assert_eq!(sample.asset_id, "win-host");
        assert_eq!(sample.cpu_usage_percent, Some(12.5));
        assert_eq!(sample.ram_used_mb, Some(8182));
        assert_eq!(sample.ram_available_mb, Some(8192));
        assert_eq!(sample.swap_used_mb, Some(256));
        assert_eq!(sample.load_1m, None, "Windows carries no load averages");
        assert!(windows_sample_from_lines("win-host", &[]).is_none());
        assert!(windows_sample_from_lines("win-host", &["garbage".into()]).is_none());
    }

    #[test]
    fn coverage_reports_span_and_largest_gap() {
        let base = Utc::now() - chrono::Duration::hours(2);
        let mk = |mins: i64| MetricSample {
            asset_id: "a".into(),
            sampled_at: base + chrono::Duration::minutes(mins),
            cpu_usage_percent: None,
            ram_used_mb: None,
            ram_available_mb: None,
            swap_used_mb: None,
            load_1m: None,
            load_5m: None,
            load_15m: None,
        };
        // 0min, 1min, gap, 90min -> largest gap 89min = 5340s.
        let cov = coverage(&[mk(0), mk(1), mk(90)]);
        assert_eq!(cov.sample_count, 3);
        assert_eq!(cov.largest_gap_secs, Some(5340.0));
        assert!((cov.span_hours.unwrap() - 1.5).abs() < 0.001);
        assert_eq!(coverage(&[]).largest_gap_secs, None);
    }

    #[test]
    fn html_report_escapes_and_renders() {
        let now = Utc::now();
        let mk = |cpu: Option<f32>, at: DateTime<Utc>| MetricSample {
            asset_id: "10-0-0-1".into(),
            sampled_at: at,
            cpu_usage_percent: cpu,
            ram_used_mb: Some(1024),
            ram_available_mb: Some(2048),
            swap_used_mb: Some(0),
            load_1m: Some(0.5),
            load_5m: None,
            load_15m: None,
        };
        let window = vec![
            mk(Some(10.0), now - chrono::Duration::minutes(5)),
            mk(Some(30.0), now),
        ];
        let stats = crate::metrics::summarize(&window).expect("two samples summarize");
        let cov = coverage(&window);
        let html = render_html(&stats, &cov, "10-0-0-1<script>");
        assert!(html.contains("&lt;script&gt;"), "asset id must be escaped");
        assert!(html.contains("Utilization window"));
        assert!(html.contains("Coverage"));
    }

    #[test]
    fn detect_local_ip_never_panics() {
        let _ = detect_local_ip();
    }
}
