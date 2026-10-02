//! End-to-end scale tests: a representative large inventory (thousands of
//! assets with interfaces, services and a week of utilization) must import,
//! assess, export and round-trip within a predictable time budget.
//!
//! The budgets are deliberately generous — they are not benchmarks. They exist
//! to catch order-of-magnitude regressions, above all the return of per-asset
//! (N+1) queries: a query per asset instead of a bulk read turns these
//! inventories from seconds into minutes. Every assertion also checks that the
//! output is complete, so a fast-but-truncated result fails too.

mod common;

#[cfg(unix)]
use common::*;
#[cfg(unix)]
use std::time::{Duration, Instant};

/// Assets in the representative inventory: large enough for per-asset query
/// patterns to show, small enough to keep the suite fast.
#[cfg(unix)]
const ASSETS: usize = 1_500;

/// Wall-clock budget for one read-heavy command over the whole inventory
/// (assessment, export, metrics). A bulk-read implementation finishes in
/// seconds; per-asset queries do not.
#[cfg(unix)]
const READ_BUDGET: Duration = Duration::from_secs(30);

/// Wall-clock budget for the write-heavy import of the same inventory.
#[cfg(unix)]
const IMPORT_BUDGET: Duration = Duration::from_secs(30);

/// Run `cmd`, failing the test if it takes longer than `budget`.
#[cfg(unix)]
fn run_within(cmd: &mut std::process::Command, budget: Duration, what: &str) -> String {
    let started = Instant::now();
    let out = run_ok(cmd);
    let elapsed = started.elapsed();
    assert!(
        elapsed < budget,
        "{what} took {elapsed:?}, over its {budget:?} budget for {ASSETS} assets"
    );
    eprintln!("{what}: {elapsed:?} for {ASSETS} assets");
    out
}

/// A fake `curl` serving a week of low utilization for every instance the
/// importer asks about, so the right-sizing path runs over real samples.
#[cfg(unix)]
const FAKE_PROM_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
url=""
for a in "$@"; do
  case "$a" in
    */api/v1/query_range*) url="$a" ;;
  esac
done
instance="$(printf '%s' "$url" | sed -n 's/.*instance%22%3A%22\([^%&]*\).*/\1/p')"
[[ -n "$instance" ]] || instance='10.0.0.1:9100'
now="$(date +%s)"
points=''
for i in $(seq 0 47); do
  ts=$((now - i * 8 * 3600))
  [[ -n "$points" ]] && points="$points,"
  points="$points[$ts,\"15.00\"]"
done
printf '{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"instance":"%s"},"values":[%s]}]}}' "$instance" "$points"
printf '200'
"#;

/// A fake `ssh` that reports the allocation and three low-utilization
/// snapshots, so the right-sizing rules have a window to work with.
#[cfg(unix)]
const FAKE_SSH_SCRIPT: &str = r#"#!/usr/bin/env bash
cat <<'OUT'
###os
PRETTY_NAME="Ubuntu 22.04.4 LTS"
###kernel
5.15.0-94-generic
###hostname
host-00001
###cpu
CPU(s):              8
Model name:          Intel(R) Xeon(R) Gold 6138 CPU @ 2.00GHz
###mem
MemTotal:       16384532 kB
###disk
Filesystem     Type   1024-blocks      Used Available Capacity Mounted on
/dev/sda1      ext4       52425716  13106429  39319287      25% /
###metric
12.50|16384532|2147483648|0|0|1.05,1.10,1.02
18.00|16384532|3221225472|0|0|1.20,1.15,1.10
22.00|16384532|1073741824|0|0|1.02,1.08,1.01
OUT
"#;

#[cfg(unix)]
fn import_file(dir: &TempDir, name: &str) -> std::path::PathBuf {
    let file = dir.path().join(name);
    std::fs::write(&file, representative_inventory(ASSETS)).expect("write inventory");
    file
}

#[cfg(unix)]
#[test]
fn representative_inventory_imports_assesses_and_exports_within_budget() {
    let dir = TempDir::new("scale-pipeline");
    let file = import_file(&dir, "inventory.json");

    // Import: the write-heavy path (every asset, interface and service).
    let started = Instant::now();
    let out = run_ok_combined(
        orbyn(&dir)
            .args(["import", "--format", "json", "--file"])
            .arg(&file),
    );
    let elapsed = started.elapsed();
    assert!(elapsed < IMPORT_BUDGET, "import took {elapsed:?}");
    eprintln!("import: {elapsed:?} for {ASSETS} assets");
    assert!(
        out.contains(&format!("Imported {ASSETS} assets")),
        "every asset must be imported: {out}"
    );
    assert!(
        out.contains(&format!("{} interfaces", ASSETS * INTERFACES_PER_ASSET)),
        "every interface must be imported: {out}"
    );
    assert!(
        out.contains(&format!("{} services", ASSETS * SERVICES_PER_ASSET)),
        "every service must be imported: {out}"
    );

    // Reads: one query per table, not one per asset.
    let assets = run_within(
        orbyn(&dir).args(["assets", "--format", "csv"]),
        READ_BUDGET,
        "assets --format csv",
    );
    assert_eq!(
        assets.lines().count(),
        ASSETS + 1,
        "every asset must be listed"
    );

    let assessment = run_within(
        orbyn(&dir).args(["assess", "--format", "json"]),
        READ_BUDGET,
        "assess --format json",
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&assessment).expect("assessment JSON parses");
    let findings = parsed["findings"].as_array().expect("findings array");
    assert!(
        findings.len() >= ASSETS,
        "the whole inventory must be assessed, got {} findings",
        findings.len()
    );

    let report = run_within(
        orbyn(&dir).args(["assess", "--format", "table"]),
        READ_BUDGET,
        "assess --format table",
    );
    assert!(!report.trim().is_empty(), "the report must render");

    for format in ["json", "csv", "terraform", "ansible", "ansible-yaml"] {
        let rendered = run_within(
            orbyn(&dir).args(["export", "--format", format]),
            READ_BUDGET,
            &format!("export --format {format}"),
        );
        if format == "json" {
            let parsed: serde_json::Value =
                serde_json::from_str(&rendered).expect("export JSON parses");
            assert_eq!(
                parsed["assets"].as_array().expect("assets array").len(),
                ASSETS,
                "every asset must be exported"
            );
        }
    }
}

/// The CSV export re-imported into a second database must preserve the whole
/// inventory within the import budget, so a large round trip stays operable.
#[cfg(unix)]
#[test]
fn representative_inventory_round_trips_through_csv_within_budget() {
    let source = TempDir::new("scale-roundtrip-source");
    let target = TempDir::new("scale-roundtrip-target");
    let file = import_file(&source, "inventory.json");
    run_ok_combined(
        orbyn(&source)
            .args(["import", "--format", "json", "--file"])
            .arg(&file),
    );

    let exported = run_within(
        orbyn(&source).args(["export", "--format", "csv"]),
        READ_BUDGET,
        "export --format csv",
    );
    let csv = source.path().join("inventory.csv");
    std::fs::write(&csv, exported).expect("write csv");

    let started = Instant::now();
    let out = run_ok_combined(
        orbyn(&target)
            .args(["import", "--format", "csv", "--file"])
            .arg(&csv),
    );
    let elapsed = started.elapsed();
    assert!(elapsed < IMPORT_BUDGET, "re-import took {elapsed:?}");
    eprintln!("csv re-import: {elapsed:?} for {ASSETS} assets");
    assert!(out.contains(&format!("Imported {ASSETS} assets")), "{out}");
    assert!(
        out.contains(&format!("{} interfaces", ASSETS * INTERFACES_PER_ASSET)),
        "interfaces survive the round trip: {out}"
    );
    assert!(
        out.contains(&format!("{} services", ASSETS * SERVICES_PER_ASSET)),
        "services survive the round trip: {out}"
    );

    // The second inventory is byte-identical to the first.
    let first = run_within(
        orbyn(&source).args(["export", "--format", "csv"]),
        READ_BUDGET,
        "export --format csv (source)",
    );
    let second = run_within(
        orbyn(&target).args(["export", "--format", "csv"]),
        READ_BUDGET,
        "export --format csv (target)",
    );
    assert_eq!(
        strip_timestamps(&first),
        strip_timestamps(&second),
        "the round trip must preserve every field"
    );
}

/// Drop the discovery timestamps, which legitimately differ between the two
/// runs, before comparing two exports.
#[cfg(unix)]
fn strip_timestamps(csv: &str) -> String {
    csv.lines()
        .map(|line| {
            let mut fields: Vec<&str> = line.split(',').collect();
            if fields.len() >= 12 {
                fields.truncate(10);
            }
            fields.join(",")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A week of imported utilization plus the right-sizing assessment must stay
/// within the read budget: the metric aggregation reads samples in bulk.
#[cfg(unix)]
#[test]
fn utilization_history_assesses_within_budget() {
    let dir = TempDir::new("scale-metrics");
    let file = import_file(&dir, "inventory.json");
    run_ok_combined(
        orbyn(&dir)
            .args(["import", "--format", "json", "--file"])
            .arg(&file),
    );

    // One host-level probe records the allocation and the snapshots.
    let ssh = fake_bin(&dir, "ssh", FAKE_SSH_SCRIPT);
    run_ok_combined(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.1", "--collector", "ssh"])
            .env("ORBYN_SSH_BIN", &ssh),
    );

    // A week of history for the whole estate through the Prometheus importer.
    let curl = fake_bin(&dir, "curl", FAKE_PROM_CURL_SCRIPT);
    let started = Instant::now();
    let out = run_ok_combined(
        orbyn(&dir)
            .args(["prometheus", "import", "--url", "http://prometheus:9090"])
            .env("ORBYN_CURL_BIN", &curl),
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < IMPORT_BUDGET,
        "prometheus import took {elapsed:?}"
    );
    eprintln!("prometheus import: {elapsed:?} for {ASSETS} assets");
    assert!(
        out.contains("metric samples from Prometheus"),
        "history must be imported: {out}"
    );

    let metrics = run_within(
        orbyn(&dir).args(["metrics", "10.0.0.1", "--format", "csv"]),
        READ_BUDGET,
        "metrics --format csv",
    );
    assert!(metrics.contains("right_sizing_ready"), "{metrics}");

    let assessment = run_within(
        orbyn(&dir).args(["assess", "--format", "json"]),
        READ_BUDGET,
        "assess --format json (with history)",
    );
    assert!(assessment.contains("rs."), "right-sizing rules must run");

    let graph = run_within(orbyn(&dir).arg("graph"), READ_BUDGET, "graph");
    assert!(!graph.trim().is_empty(), "the graph must render");
    let mermaid = run_within(
        orbyn(&dir).args(["graph", "--mermaid"]),
        READ_BUDGET,
        "graph --mermaid",
    );
    assert!(mermaid.contains("graph TD"), "{mermaid}");
}

/// A fake `nmap` that reports the target it was handed, so a fan-out over
/// many targets discovers a distinct host per target.
#[cfg(unix)]
const FAKE_NMAP_PER_TARGET_SCRIPT: &str = r#"#!/usr/bin/env bash
target="${@: -1}"
cat <<XML
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX - -sV" start="1700000000" version="7.94">
<host starttime="1700000000" endtime="1700000001">
<status state="up" reason="syn-ack"/>
<address addr="$target" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Intel"/>
<hostnames><hostname name="host-$target" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu"/></port>
</ports>
<os><osmatch name="Linux 5.15.0-94-generic" accuracy="98"/></os>
<times srtt="1000" rttvar="100" to="100000"/>
</host>
</nmaprun>
XML
"#;

/// Targets in the fan-out: far more than a test should scan one at a time.
#[cfg(unix)]
const TARGETS: usize = 1_024;

/// A bounded, rate-limited fan-out over many targets must finish inside the
/// import budget, discover every target, and be paced by `--rate-limit`.
#[cfg(unix)]
#[test]
fn bounded_concurrent_discovery_over_many_targets_finishes_within_budget() {
    let dir = TempDir::new("scale-discovery");
    let nmap = fake_bin(&dir, "nmap", FAKE_NMAP_PER_TARGET_SCRIPT);

    let mut args: Vec<String> = vec!["discover".into(), "--collector".into(), "nmap".into()];
    for i in 0..TARGETS {
        args.push("--target".into());
        args.push(format!("10.{}.{}.1", i / 250, i % 250));
    }
    args.push("--concurrency".into());
    args.push("16".into());
    args.push("--rate-limit".into());
    args.push("500".into());

    let started = Instant::now();
    let out = run_ok_combined(orbyn(&dir).args(args).env("ORBYN_NMAP_BIN", &nmap));
    let elapsed = started.elapsed();
    assert!(
        elapsed < IMPORT_BUDGET,
        "discovery of {TARGETS} targets took {elapsed:?}"
    );
    // 1023 launches at 500/s cannot finish faster than ~2s: the rate limit
    // paces the fan-out instead of bursting all of it.
    assert!(
        elapsed >= Duration::from_millis(1_800),
        "discovery finished in {elapsed:?}; --rate-limit 500 was not applied"
    );
    eprintln!("{TARGETS}-target discovery at 500/s: {elapsed:?}");
    assert!(
        out.contains(&format!("{TARGETS} assets")),
        "every target must be discovered: {out}"
    );

    let assets = run_within(
        orbyn(&dir).args(["assets", "--format", "csv"]),
        READ_BUDGET,
        "assets --format csv (after fan-out)",
    );
    assert_eq!(
        assets.lines().count(),
        TARGETS + 1,
        "every discovered asset must be listed"
    );

    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("nmap,succeeded"), "{jobs}");
    assert!(jobs.contains(&format!(",{TARGETS},")), "job counts: {jobs}");
}
