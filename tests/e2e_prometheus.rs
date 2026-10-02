//! End-to-end tests for the Prometheus historical utilization importer: a
//! fake `curl` serves `/api/v1/query_range` responses so the full flow —
//! query, inventory mapping, idempotent persistence, utilization windows
//! and right-sizing assessment — runs without a network.

mod common;

#[cfg(unix)]
use common::*;
#[cfg(unix)]
use std::path::PathBuf;

/// A fake `curl` implementing a minimal Prometheus range-query endpoint:
/// it dispatches on the (percent-encoded) query inside the URL and emits
/// one series per query, with points and instance labels taken from the
/// test's environment. It logs argv and the stdin config so secret
/// handling can be asserted.
#[cfg(unix)]
const FAKE_PROM_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
log="${ORBYN_PROM_LOG}"
url=""
for a in "$@"; do
  case "$a" in
    */api/v1/query_range*) url="$a" ;;
  esac
done
if [[ -n "$log" ]]; then
  printf '%s\n' "$@" >> "$log.argv"
  cat >> "$log.stdin"
fi
if [[ "$url" == *node_cpu_seconds_total* ]]; then
  values="${ORBYN_PROM_CPU_VALUES}"
  instance="${ORBYN_PROM_CPU_INSTANCE:-10.0.0.2:9100}"
elif [[ "$url" == *node_memory_MemTotal* ]]; then
  values="${ORBYN_PROM_RAM_VALUES}"
  instance="${ORBYN_PROM_RAM_INSTANCE:-10.0.0.2:9100}"
elif [[ "$url" == *node_memory_SwapTotal* ]]; then
  if [[ -z "${ORBYN_PROM_SWAP_VALUES:-}" ]]; then
    # No swap series configured: behave like an exporter without swap.
    printf '{"status":"success","data":{"resultType":"matrix","result":[]}}'
    printf '200'
    exit 0
  fi
  values="${ORBYN_PROM_SWAP_VALUES}"
  instance="${ORBYN_PROM_RAM_INSTANCE:-10.0.0.2:9100}"
else
  printf '{"status":"error","errorType":"bad_data","error":"unknown query"}'
  printf '400'
  exit 0
fi
# The status curl appends with -w: Orbyn reads it before parsing the body.
printf '{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"instance":"%s","job":"node"},"values":[%s]}]}}' "$instance" "$values"
printf '200'
"#;

/// A fake `ssh` emitting a Linux host probe without the `###metric`
/// snapshots, so the Prometheus import is the asset's only utilization
/// window (the snapshots would otherwise poison the percentiles).
#[cfg(unix)]
const FAKE_SSH_NO_SNAPSHOTS_SCRIPT: &str = r#"#!/usr/bin/env bash
cat <<'OUT'
###os
NAME="Ubuntu"
PRETTY_NAME="Ubuntu 22.04.4 LTS"
###kernel
5.15.0-94-generic
###hostname
web-01
###cpu
Architecture:        x86_64
CPU(s):              8
Thread(s) per core:  2
Core(s) per socket:  4
Socket(s):           1
Model name:          Intel(R) Xeon(R) Gold 6138 CPU @ 2.00GHz
###mem
MemTotal:       16384532 kB
###disk
Filesystem     Type   1024-blocks      Used Available Capacity Mounted on
/dev/sda1      ext4       52425716  12345678  37380844      25% /
###svc
nginx.service                 loaded active running A high performance web server and reverse proxy
###conn
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
OUT
"#;

/// Points for one series: `count` samples, `interval_hours` apart, ending
/// now, cycling through `values`.
#[cfg(unix)]
fn prom_points(count: usize, interval_hours: i64, values: &[f64]) -> String {
    let now = chrono::Utc::now().timestamp();
    (0..count)
        .map(|i| {
            let ts = now - i as i64 * interval_hours * 3600;
            prom_point(ts, values[i % values.len()])
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// One Prometheus `[clock,"value"]` point, with integers emitted unadorned
/// so byte-sized memory values survive the round trip.
#[cfg(unix)]
fn prom_point(ts: i64, v: f64) -> String {
    if v.fract() == 0.0 {
        format!("[{ts},\"{v:.0}\"]")
    } else {
        format!("[{ts},\"{v:.2}\"]")
    }
}

/// 48 points 8h apart (376h of span) with a low-utilization prior week and a
/// busier recent week, plus a constant swap level. The split mirrors the
/// importer's own window comparison: points older than 168h are the prior
/// half.
#[cfg(unix)]
fn prom_points_growing(prior_cpu: f64, recent_cpu: f64, swap_mb: f64) -> (String, String, String) {
    let now = chrono::Utc::now().timestamp();
    let (mut cpu, mut ram, mut swap) = (Vec::new(), Vec::new(), Vec::new());
    for i in 0..48 {
        let ts = now - i as i64 * 8 * 3600;
        let cpu_v = if i * 8 > 168 { prior_cpu } else { recent_cpu };
        cpu.push(prom_point(ts, cpu_v));
        ram.push(prom_point(ts, 2048.0));
        swap.push(prom_point(ts, swap_mb * 1024.0 * 1024.0));
    }
    (cpu.join(","), ram.join(","), swap.join(","))
}

#[cfg(unix)]
fn prom_env(dir: &TempDir, curl: &PathBuf) -> std::process::Command {
    let mut cmd = orbyn(dir);
    cmd.env("ORBYN_CURL_BIN", curl)
        .env("ORBYN_PROMETHEUS_TOKEN", "prom-secret-token");
    cmd
}

#[cfg(unix)]
fn week_of_low_utilization() -> (String, String) {
    // 24 points 8h apart: a 184h window, well past the 168h minimum.
    let cpu = prom_points(24, 8, &[15.0, 20.0, 25.0]);
    let ram = prom_points(24, 8, &[2147483648.0, 3221225472.0]); // 2048/3072 MB
    (cpu, ram)
}

#[cfg(unix)]
#[test]
fn prometheus_import_builds_a_week_of_history() {
    let dir = TempDir::new("prom");
    let log = dir.path().join("prom-curl");
    let curl = fake_bin(&dir, "curl", FAKE_PROM_CURL_SCRIPT);
    import_json(&dir, INVENTORY_JSON);

    let (cpu, ram) = week_of_low_utilization();
    let out = run_ok_combined(
        prom_env(&dir, &curl)
            .args(["prometheus", "import", "--url", "http://prometheus:9090"])
            .env("ORBYN_PROM_CPU_VALUES", &cpu)
            .env("ORBYN_PROM_RAM_VALUES", &ram)
            .env("ORBYN_PROM_LOG", log.to_str().unwrap()),
    );
    assert!(
        out.contains("Imported 24 metric samples from Prometheus"),
        "{out}"
    );
    assert!(out.contains("0 duplicates"), "{out}");

    // The window summarizes with its span and right-sizing readiness.
    let metrics = run_ok(orbyn(&dir).args(["metrics", "10.0.0.2"]));
    assert!(metrics.contains("24 samples over 184.0h"), "{metrics}");
    assert!(metrics.contains("sufficient for right-sizing"), "{metrics}");
    assert!(metrics.contains("p95 25.00%"), "{metrics}");

    let csv = run_ok(orbyn(&dir).args(["metrics", "10.0.0.2", "--format", "csv"]));
    assert!(csv.contains("right_sizing_ready,,true"), "{csv}");
    assert!(csv.contains("span_hours,,"), "{csv}");

    // The import is recorded in the audit trail.
    let audit = run_ok(orbyn(&dir).args(["audit", "--format", "csv"]));
    assert!(audit.contains("prometheus.import"), "{audit}");

    // The token reached curl only through the stdin header, never argv.
    let argv = std::fs::read_to_string(log.with_extension("argv")).expect("argv log");
    assert!(
        !argv.contains("prom-secret-token"),
        "token leaked to argv: {argv}"
    );
    assert!(
        argv.contains("/api/v1/query_range?query="),
        "expected the range query URL in argv: {argv}"
    );
    assert!(
        argv.contains("node_cpu_seconds_total"),
        "the PromQL must travel percent-encoded in the URL: {argv}"
    );
    let stdin_log = std::fs::read_to_string(log.with_extension("stdin")).expect("stdin log");
    assert!(
        stdin_log.contains("Authorization: Bearer prom-secret-token"),
        "token must be delivered through the stdin header: {stdin_log}"
    );
}

#[cfg(unix)]
#[test]
fn prometheus_reimport_is_idempotent() {
    let dir = TempDir::new("prom-idempotent");
    let curl = fake_bin(&dir, "curl", FAKE_PROM_CURL_SCRIPT);
    import_json(&dir, INVENTORY_JSON);

    let (cpu, ram) = week_of_low_utilization();
    let import = || {
        let mut cmd = prom_env(&dir, &curl);
        cmd.args(["prometheus", "import", "--url", "http://prometheus:9090"])
            .env("ORBYN_PROM_CPU_VALUES", &cpu)
            .env("ORBYN_PROM_RAM_VALUES", &ram);
        cmd
    };
    let first = run_ok_combined(&mut import());
    assert!(first.contains("Imported 24 metric samples"), "{first}");

    // Re-importing the same window inserts nothing and duplicates nothing.
    let second = run_ok_combined(&mut import());
    assert!(second.contains("Imported 0 metric samples"), "{second}");
    assert!(second.contains("24 duplicates skipped"), "{second}");

    let metrics = run_ok(orbyn(&dir).args(["metrics", "10.0.0.2"]));
    assert!(metrics.contains("24 samples over"), "{metrics}");
}

/// A fake `curl` that rate-limits the first `ORBYN_RETRY_FAILURES` calls with
/// a 429 before serving the usual fixtures, counting invocations in
/// `$ORBYN_RETRY_COUNTER`.
#[cfg(unix)]
const RETRY_THEN_OK_PROM_SCRIPT: &str = r#"#!/usr/bin/env bash
counter="${ORBYN_RETRY_COUNTER}"
n=0
if [[ -f "$counter" ]]; then n="$(cat "$counter")"; fi
n=$((n + 1))
printf '%s' "$n" > "$counter"
if [[ "$n" -le "${ORBYN_RETRY_FAILURES:-1}" ]]; then
  printf 'queries per second exceeded'
  printf '429'
  exit 0
fi
exec "$(dirname "$0")/curl-fixture" "$@"
"#;

#[cfg(unix)]
#[test]
fn prometheus_retries_a_rate_limited_query() {
    let dir = TempDir::new("prom-retry");
    // The retrying fake delegates to the plain fixture fake once the rate
    // limit is gone.
    fake_bin(&dir, "curl-fixture", FAKE_PROM_CURL_SCRIPT);
    let curl = fake_bin(&dir, "curl", RETRY_THEN_OK_PROM_SCRIPT);
    let counter = dir.path().join("curl-calls");
    import_json(&dir, INVENTORY_JSON);

    let (cpu, ram) = week_of_low_utilization();
    let out = run_ok_combined(
        prom_env(&dir, &curl)
            .args(["prometheus", "import", "--url", "http://prometheus:9090"])
            .env("ORBYN_PROM_CPU_VALUES", &cpu)
            .env("ORBYN_PROM_RAM_VALUES", &ram)
            .env("ORBYN_RETRY_COUNTER", &counter),
    );
    assert!(
        out.contains("Imported 24 metric samples from Prometheus"),
        "the rate-limited query must be replayed: {out}"
    );

    let calls: usize = std::fs::read_to_string(&counter)
        .expect("counter")
        .trim()
        .parse()
        .expect("numeric counter");
    // One 429, then CPU and RAM; the swap query the endpoint cannot answer is
    // a warning, not a failure.
    assert_eq!(calls, 1 + 2 + 1, "the 429 must be replayed once: {calls}");
}

#[cfg(unix)]
#[test]
fn prometheus_unmatched_series_fail_cleanly() {
    let dir = TempDir::new("prom-unmatched");
    let curl = fake_bin(&dir, "curl", FAKE_PROM_CURL_SCRIPT);
    import_json(&dir, INVENTORY_JSON);

    let (cpu, ram) = week_of_low_utilization();
    let out = run_fail(
        prom_env(&dir, &curl)
            .args(["prometheus", "import", "--url", "http://prometheus:9090"])
            .env("ORBYN_PROM_CPU_VALUES", &cpu)
            .env("ORBYN_PROM_RAM_VALUES", &ram)
            .env("ORBYN_PROM_CPU_INSTANCE", "10.0.0.99:9100")
            .env("ORBYN_PROM_RAM_INSTANCE", "10.0.0.99:9100"),
    );
    assert!(out.contains("no series matched a known asset"), "{out}");
    assert!(out.contains("2 unmatched series"), "{out}");

    // The failed import is still auditable.
    let audit = run_ok(orbyn(&dir).args(["audit", "--format", "csv"]));
    assert!(audit.contains("failed"), "{audit}");
}

#[cfg(unix)]
#[test]
fn assess_right_sizes_a_week_of_utilization() {
    let dir = TempDir::new("prom-right-size");
    let ssh = fake_bin(&dir, "ssh", FAKE_SSH_NO_SNAPSHOTS_SCRIPT);
    let curl = fake_bin(&dir, "curl", FAKE_PROM_CURL_SCRIPT);

    // Host-level collection records the allocation (8 cores, ~16 GB).
    run_ok_combined(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.5", "--collector", "ssh"])
            .env("ORBYN_SSH_BIN", &ssh),
    );

    // One meeting week of low utilization, then the assessment.
    let (cpu, ram) = week_of_low_utilization();
    run_ok_combined(
        prom_env(&dir, &curl)
            .args(["prometheus", "import", "--url", "http://prometheus:9090"])
            .env("ORBYN_PROM_CPU_VALUES", &cpu)
            .env("ORBYN_PROM_RAM_VALUES", &ram)
            .env("ORBYN_PROM_CPU_INSTANCE", "10.0.0.5:9100")
            .env("ORBYN_PROM_RAM_INSTANCE", "10.0.0.5:9100"),
    );

    let assess = run_ok(orbyn(&dir).args(["assess", "--format", "csv"]));
    assert!(assess.contains("rs.cpu-overprovisioned"), "{assess}");
    // 4 physical cores, p99 25%: ceil(4 x 0.25 x 1.5) = 2 cores.
    assert!(assess.contains("4 cores could shrink to 2"), "{assess}");
    assert!(assess.contains("rs.ram-overprovisioned"), "{assess}");
    assert!(
        !assess.contains("rs.window-insufficient"),
        "a ready window must not be called insufficient: {assess}"
    );
    assert!(!assess.contains("rs.cpu-saturated"), "{assess}");

    // The recommendation carries its evidence and rule version.
    assert!(
        assess.contains("window: 24 samples over 184.0h"),
        "{assess}"
    );
    assert!(assess.contains("0.8.0"), "{assess}");

    // The JSON form exposes the rule version and every right-sizing finding
    // carries its evidence array, so a recommendation never drops the data it
    // rests on.
    let json = run_ok(orbyn(&dir).args(["assess", "--format", "json"]));
    let report: serde_json::Value = serde_json::from_str(&json).expect("assess json");
    assert_eq!(report["rules_version"], "0.8.0");
    let rs_findings: Vec<&serde_json::Value> = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter(|f| {
            f["rule_id"]
                .as_str()
                .map(|id| id.starts_with("rs."))
                .unwrap_or(false)
        })
        .collect();
    assert!(!rs_findings.is_empty(), "right-sizing findings present");
    for f in rs_findings {
        assert!(
            f["evidence"]
                .as_array()
                .map(|e| !e.is_empty())
                .unwrap_or(false),
            "rs finding must carry evidence: {f}"
        );
    }
}

#[cfg(unix)]
#[test]
fn assess_reports_swap_pressure_and_a_growing_trend() {
    let dir = TempDir::new("prom-swap-trend");
    let ssh = fake_bin(&dir, "ssh", FAKE_SSH_NO_SNAPSHOTS_SCRIPT);
    let curl = fake_bin(&dir, "curl", FAKE_PROM_CURL_SCRIPT);

    // Host-level collection records the allocation (4 cores, ~16 GB).
    run_ok_combined(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.5", "--collector", "ssh"])
            .env("ORBYN_SSH_BIN", &ssh),
    );

    // Two weeks: a quiet prior week (5% CPU, no swap) and a recent week at
    // 30% CPU with 4 GB of swap in use.
    let (cpu, ram, swap) = prom_points_growing(5.0, 30.0, 4096.0);
    run_ok_combined(
        prom_env(&dir, &curl)
            .args(["prometheus", "import", "--url", "http://prometheus:9090"])
            .env("ORBYN_PROM_CPU_VALUES", &cpu)
            .env("ORBYN_PROM_RAM_VALUES", &ram)
            .env("ORBYN_PROM_SWAP_VALUES", &swap)
            .env("ORBYN_PROM_CPU_INSTANCE", "10.0.0.5:9100")
            .env("ORBYN_PROM_RAM_INSTANCE", "10.0.0.5:9100"),
    );

    // The window reports swap statistics and the week-over-week split.
    let metrics = run_ok(orbyn(&dir).args(["metrics", "10.0.0.5"]));
    assert!(metrics.contains("48 samples over 376.0h"), "{metrics}");
    assert!(metrics.contains("Swap used  : avg 4.00 GiB"), "{metrics}");
    assert!(
        metrics.contains("Trend      : last 168h vs the 168h before it"),
        "{metrics}"
    );
    assert!(
        metrics.contains("CPU p95: p95 5.00% -> 30.00%"),
        "{metrics}"
    );

    let csv = run_ok(orbyn(&dir).args(["metrics", "10.0.0.5", "--format", "csv"]));
    assert!(csv.contains("swap_used_mb,p95,4096"), "{csv}");
    assert!(csv.contains("cpu_usage_percent,prior_p95,5"), "{csv}");
    assert!(csv.contains("cpu_usage_percent,recent_p95,30"), "{csv}");

    // The assessment raises the paging warning and the trend, both gated on
    // the same ready window.
    let assess = run_ok(orbyn(&dir).args(["assess", "--format", "csv"]));
    assert!(assess.contains("rs.swap-pressure"), "{assess}");
    assert!(
        assess.contains("sustained swap usage (p95 4096 MB"),
        "{assess}"
    );
    assert!(assess.contains("rs.utilization-trend"), "{assess}");
    assert!(assess.contains("CPU p95 5.0% -> 30.0%"), "{assess}");
    assert!(!assess.contains("rs.window-insufficient"), "{assess}");
}

#[cfg(unix)]
#[test]
fn prometheus_import_tolerates_an_exporter_without_swap() {
    let dir = TempDir::new("prom-no-swap");
    let curl = fake_bin(&dir, "curl", FAKE_PROM_CURL_SCRIPT);
    import_json(&dir, INVENTORY_JSON);

    // No ORBYN_PROM_SWAP_VALUES: the fake returns an empty swap matrix, the
    // way an exporter without swap metrics would.
    let (cpu, ram) = week_of_low_utilization();
    let out = run_ok_combined(
        prom_env(&dir, &curl)
            .args(["prometheus", "import", "--url", "http://prometheus:9090"])
            .env("ORBYN_PROM_CPU_VALUES", &cpu)
            .env("ORBYN_PROM_RAM_VALUES", &ram),
    );
    assert!(
        out.contains("Imported 24 metric samples from Prometheus"),
        "{out}"
    );

    let metrics = run_ok(orbyn(&dir).args(["metrics", "10.0.0.2"]));
    assert!(metrics.contains("sufficient for right-sizing"), "{metrics}");
    // No swap samples means no swap line, not a line full of zeroes.
    assert!(!metrics.contains("Swap used"), "{metrics}");
    let assess = run_ok(orbyn(&dir).args(["assess", "--format", "csv"]));
    assert!(!assess.contains("rs.swap-pressure"), "{assess}");
}

#[cfg(unix)]
#[test]
fn assess_warns_when_the_window_is_too_short() {
    let dir = TempDir::new("prom-short-window");
    let ssh = fake_bin(&dir, "ssh", FAKE_SSH_NO_SNAPSHOTS_SCRIPT);
    let curl = fake_bin(&dir, "curl", FAKE_PROM_CURL_SCRIPT);

    run_ok_combined(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.5", "--collector", "ssh"])
            .env("ORBYN_SSH_BIN", &ssh),
    );

    // 15 hourly points: high sample confidence, but only a 14h window.
    let cpu = prom_points(15, 1, &[15.0, 20.0, 25.0]);
    let ram = prom_points(15, 1, &[2147483648.0]);
    run_ok_combined(
        prom_env(&dir, &curl)
            .args(["prometheus", "import", "--url", "http://prometheus:9090"])
            .env("ORBYN_PROM_CPU_VALUES", &cpu)
            .env("ORBYN_PROM_RAM_VALUES", &ram)
            .env("ORBYN_PROM_CPU_INSTANCE", "10.0.0.5:9100")
            .env("ORBYN_PROM_RAM_INSTANCE", "10.0.0.5:9100"),
    );

    let metrics = run_ok(orbyn(&dir).args(["metrics", "10.0.0.5"]));
    assert!(
        metrics.contains("insufficient for right-sizing"),
        "{metrics}"
    );

    let assess = run_ok(orbyn(&dir).args(["assess", "--format", "csv"]));
    assert!(assess.contains("rs.window-insufficient"), "{assess}");
    assert!(
        !assess.contains("rs.cpu-overprovisioned"),
        "snapshots and short windows must never drive sizing: {assess}"
    );
}
