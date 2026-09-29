//! End-to-end discovery tests: Nmap, SNMP, SSH (Linux) and Windows collectors
//! run through the real `orbyn` binary against fake external tools.

mod common;

#[cfg(unix)]
use common::*;

#[cfg(unix)]
#[test]
fn nmap_discovery_persists_inventory_and_job() {
    let dir = TempDir::new("nmap");
    let bin = fake_bin(&dir, "nmap", FAKE_NMAP_SCRIPT);

    let mut cmd = orbyn(&dir);
    cmd.args(["discover", "--target", "10.0.0.10"])
        .env("ORBYN_NMAP_BIN", &bin);
    let out = run_ok_combined(&mut cmd);
    assert!(out.contains("1 assets, 2 services"));

    // assets table shows the discovered host with classification + OS
    let assets = run_ok(orbyn(&dir).arg("assets"));
    assert!(assets.contains("10.0.0.10"));
    assert!(assets.contains("server-a.example.com"));
    assert!(assets.contains("server"));

    // asset detail includes the MAC interface and services
    let detail = run_ok(orbyn(&dir).args(["asset", "10.0.0.10"]));
    assert!(detail.contains("00:11:22:33:44:55"));
    assert!(detail.contains("OpenSSH 8.9p1 Ubuntu"));
    assert!(detail.contains("nginx 1.18.0"));
    assert!(!detail.contains("3306"), "filtered port must not appear");

    // a job was recorded with counts
    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("nmap,succeeded"));
    assert!(jobs.contains(",1,2,"), "assets=1 services=2 in csv: {jobs}");
}

#[cfg(unix)]
#[test]
fn discover_rejects_unrestricted_scope() {
    let dir = TempDir::new("scope");
    let bin = fake_bin(&dir, "nmap", FAKE_NMAP_SCRIPT);

    let out = run_fail(
        orbyn(&dir)
            .args(["discover", "--target", "0.0.0.0/0"])
            .env("ORBYN_NMAP_BIN", &bin),
    );
    assert!(
        out.contains("scope") || out.contains("exceeds"),
        "got: {out}"
    );
}

/// A fake `nmap` that floods stderr with far more than the pipe buffer
/// before emitting valid XML: sequential pipe reads would deadlock here.
#[cfg(unix)]
const STDERR_FLOOD_NMAP_SCRIPT: &str = r#"#!/usr/bin/env bash
for i in $(seq 1 20000); do echo "stderr noise noise noise noise noise" >&2; done
cat <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -oX - -sV" start="1700000000" version="7.94">
<host starttime="1700000000" endtime="1700000001">
<status state="up" reason="syn-ack"/>
<address addr="10.0.0.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
</ports>
</host>
</nmaprun>
XML
"#;

#[cfg(unix)]
#[test]
fn nmap_discovery_survives_stderr_flood() {
    let dir = TempDir::new("nmap-flood");
    let bin = fake_bin(&dir, "nmap", STDERR_FLOOD_NMAP_SCRIPT);

    let out = run_ok_combined(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.10"])
            .env("ORBYN_NMAP_BIN", &bin),
    );
    assert!(out.contains("1 assets, 1 services"), "{out}");

    let assets = run_ok(orbyn(&dir).arg("assets"));
    assert!(assets.contains("10.0.0.10"), "asset persisted: {assets}");
}

#[cfg(unix)]
#[test]
fn nmap_discovery_times_out_hanging_scans() {
    let dir = TempDir::new("nmap-hang");
    // `exec` so the hang is the child itself and gets killed on timeout.
    let bin = fake_bin(&dir, "nmap", "#!/usr/bin/env bash\nexec sleep 600\n");

    let out = run_fail(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.10"])
            .env("ORBYN_NMAP_BIN", &bin)
            .env("ORBYN_NMAP_TIMEOUT_SECS", "1"),
    );
    assert!(out.contains("timed out"), "got: {out}");
    assert!(
        out.contains("ORBYN_NMAP_TIMEOUT_SECS"),
        "error names the override: {out}"
    );

    // the failed job is recorded with the timeout as its error
    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("nmap,failed"), "{jobs}");
    assert!(jobs.contains("timed out"), "{jobs}");
}

#[cfg(unix)]
#[test]
fn snmp_discovery_classifies_network_device() {
    let dir = TempDir::new("snmp");
    let bin = fake_bin(&dir, "snmpwalk", FAKE_SNMPWALK_SCRIPT);
    let args_log = dir.path().join("snmp-args.log");

    let out = run_ok(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.8", "--collector", "snmp"])
            .env("ORBYN_SNMP_BIN", &bin)
            .env("ORBYN_SNMP_COMMUNITY", "super-secret-community")
            .env("ORBYN_SNMP_ARGS_LOG", &args_log),
    );
    assert!(out.contains("switch-core-1"));
    assert!(out.contains("network-device"));
    let args = std::fs::read_to_string(&args_log).expect("SNMP args log");
    assert!(!args.contains("super-secret-community"));
    assert!(
        !args.contains("-c"),
        "SNMP community must not be an argument"
    );

    let ifaces = run_ok(orbyn(&dir).args(["interfaces", "10.0.0.8", "--format", "csv"]));
    assert!(ifaces.contains("00:1c:58:9a:bc:34"));
    assert!(ifaces.contains("1500"));

    // SNMP must reject a CIDR target
    let fail = run_fail(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.0/24", "--collector", "snmp"])
            .env("ORBYN_SNMP_BIN", &bin),
    );
    assert!(fail.contains("single host"), "got: {fail}");
}

#[cfg(unix)]
#[test]
fn snmp_community_from_stdin_reaches_the_walk() {
    let dir = TempDir::new("snmp-stdin");
    let bin = fake_bin(&dir, "snmpwalk", FAKE_SNMPWALK_SCRIPT);
    let args_log = dir.path().join("snmp-args.log");
    let conf_log = dir.path().join("snmp-conf.log");

    let output = run_with_stdin(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.8", "--collector", "snmp"])
            .args(["--community", "-"])
            .env("ORBYN_SNMP_BIN", &bin)
            .env("ORBYN_SNMP_ARGS_LOG", &args_log)
            .env("ORBYN_SNMP_CONF_LOG", &conf_log),
        "super-secret-community\n",
    );
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("super-secret-community"),
        "stdin community must never be printed: {combined}"
    );
    let args = std::fs::read_to_string(&args_log).expect("SNMP args log");
    assert!(
        !args.contains("super-secret-community"),
        "SNMP community must not be an argument: {args}"
    );
    let conf = std::fs::read_to_string(&conf_log).expect("SNMP conf log");
    assert!(
        conf.contains("defCommunity super-secret-community"),
        "stdin community must reach the walk config: {conf}"
    );
}

#[cfg(unix)]
#[test]
fn snmp_community_not_inherited_by_child_environment() {
    let dir = TempDir::new("snmp-env");
    let bin = fake_bin(&dir, "snmpwalk", FAKE_SNMPWALK_SCRIPT);
    let env_log = dir.path().join("snmp-env.log");
    let conf_log = dir.path().join("snmp-conf.log");

    // Audit OY-02: the community must reach the walk through the config
    // file, but never through the environment inherited by the child —
    // a hijacked snmpwalk could otherwise read it straight from `env`.
    let out = run_ok(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.8", "--collector", "snmp"])
            .env("ORBYN_SNMP_BIN", &bin)
            .env("ORBYN_SNMP_COMMUNITY", "super-secret-community")
            .env("ORBYN_SNMP_ENV_LOG", &env_log)
            .env("ORBYN_SNMP_CONF_LOG", &conf_log),
    );
    assert!(out.contains("switch-core-1"), "walk still succeeds: {out}");

    let child_env = std::fs::read_to_string(&env_log).expect("child env log");
    assert!(
        !child_env.contains("super-secret-community"),
        "community must not be inherited by the child: {child_env}"
    );
    let conf = std::fs::read_to_string(&conf_log).expect("conf log");
    assert!(
        conf.contains("defCommunity super-secret-community"),
        "community still reaches the walk config: {conf}"
    );
}

#[cfg(unix)]
#[test]
fn discover_failure_redacts_cli_community() {
    let dir = TempDir::new("snmp-redact");
    // A failing fake snmpwalk whose stderr carries the secret: proves a
    // CLI-provided community is registered with the redactor before the
    // error is persisted or printed.
    let script = r#"#!/usr/bin/env bash
printf 'snmpwalk: authentication failure (community super-secret-community)\n' >&2
exit 1
"#;
    let bin = fake_bin(&dir, "snmpwalk", script);

    let out = run_fail(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.8", "--collector", "snmp"])
            .args(["--community", "super-secret-community"])
            .env("ORBYN_SNMP_BIN", &bin),
    );
    assert!(
        !out.contains("super-secret-community"),
        "CLI community must be redacted: {out}"
    );
    assert!(
        out.contains("[REDACTED]"),
        "expected redaction placeholder: {out}"
    );
}

#[cfg(unix)]
#[test]
fn ssh_discovery_collects_host_facts_and_edges() {
    let dir = TempDir::new("ssh");
    let bin = fake_bin(&dir, "ssh", FAKE_SSH_LINUX_SCRIPT);

    // Pre-seed the inventory so connection endpoints resolve to assets.
    import_json(&dir, INVENTORY_JSON);

    let out = run_ok_combined(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.5", "--collector", "ssh"])
            .env("ORBYN_SSH_BIN", &bin),
    );
    assert!(out.contains("2 filesystems, 2 running services, 3 connections"));

    // the job record stores the full outcome, not only assets/services
    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(
        jobs.contains(",1,0,2,2,3,"),
        "assets=1 services=0 filesystems=2 running=2 conns=3 in csv: {jobs}"
    );

    // capacity
    let cap = run_ok(orbyn(&dir).args(["capacity", "10.0.0.5"]));
    assert!(cap.contains("Intel(R) Xeon(R) Gold 6138"));
    assert!(cap.contains("8"));
    assert!(cap.contains("16001 MB"));
    assert!(
        cap.contains("Hypervisor : vmware"),
        "virtualization metadata: {cap}"
    );

    // disks
    let disks = run_ok(orbyn(&dir).args(["disks", "10.0.0.5"]));
    assert!(disks.contains("/"));
    assert!(disks.contains("/data"));

    // running services
    let svcs = run_ok(orbyn(&dir).args(["host-services", "10.0.0.5"]));
    assert!(svcs.contains("nginx.service"));

    // connections (evidence) incl. the external endpoint and process name
    let conns = run_ok(orbyn(&dir).args(["connections", "10.0.0.5", "--format", "csv"]));
    assert!(conns.contains("postgres"));
    assert!(conns.contains("203.0.113.9,443"));
    assert!(!conns.contains("127.0.0.1"), "loopback must be filtered");

    // utilization window from the three sampled snapshots
    let metrics = run_ok(orbyn(&dir).args(["metrics", "10.0.0.5"]));
    assert!(
        metrics.contains("Utilization window: 3 samples"),
        "{metrics}"
    );
    assert!(
        metrics.contains("peak 80.00%"),
        "cpu avg/p95/p99/peak: {metrics}"
    );
    assert!(metrics.contains("RAM used  :"), "{metrics}");
    assert!(
        metrics.contains("low"),
        "confidence for 3 samples must be low: {metrics}"
    );
    let metrics_json = run_ok(orbyn(&dir).args(["metrics", "10.0.0.5", "--format", "json"]));
    assert!(
        metrics_json.contains("\"cpu_p95_percent\": 80.0"),
        "{metrics_json}"
    );
    let metrics_csv = run_ok(orbyn(&dir).args(["metrics", "10.0.0.5", "--format", "csv"]));
    assert!(
        metrics_csv.contains("cpu_usage_percent,avg,59.17"),
        "{metrics_csv}"
    );

    // dependency edges: only the two managed targets, not the external one
    let graph = run_ok(orbyn(&dir).args(["graph", "--format", "csv"]));
    assert!(
        graph.contains("10-0-0-5,10-0-0-2,tcp,5432"),
        "web->db edge: {graph}"
    );
    assert!(
        graph.contains("10-0-0-5,10-0-0-9,tcp,6379"),
        "web->cache edge: {graph}"
    );
    assert!(
        !graph.contains("203.0.113.9"),
        "external IP must not become an edge"
    );
}

#[cfg(unix)]
#[test]
fn windows_discovery_parses_powershell_csv() {
    let dir = TempDir::new("windows");
    let bin = fake_bin(&dir, "ssh", FAKE_SSH_WINDOWS_SCRIPT);

    run_ok(
        orbyn(&dir)
            .args([
                "discover",
                "--target",
                "10.0.0.20",
                "--collector",
                "windows",
            ])
            .env("ORBYN_SSH_BIN", &bin),
    );

    let detail = run_ok(orbyn(&dir).args(["asset", "10.0.0.20"]));
    assert!(detail.contains("Microsoft Windows Server 2022 Standard"));
    assert!(detail.contains("10.0 build 20348"));
    assert!(detail.contains("WIN-APP01"));
    assert!(
        detail.contains("Hypervisor : hyperv"),
        "virtualization metadata: {detail}"
    );

    let disks = run_ok(orbyn(&dir).args(["disks", "10.0.0.20", "--format", "csv"]));
    assert!(disks.contains("C:,NTFS"));
    assert!(disks.contains("D:,NTFS"));

    let svcs = run_ok(orbyn(&dir).args(["host-services", "10.0.0.20"]));
    assert!(svcs.contains("W3SVC"));
    assert!(svcs.contains("MSSQLSERVER"));

    // utilization window from the sampled snapshots
    let metrics = run_ok(orbyn(&dir).args(["metrics", "10.0.0.20"]));
    assert!(
        metrics.contains("Utilization window: 3 samples"),
        "{metrics}"
    );
    assert!(metrics.contains("peak 75.00%"), "{metrics}");
}

#[cfg(unix)]
#[test]
fn annotations_survive_rediscovery() {
    let dir = TempDir::new("annotate");
    let bin = fake_bin(&dir, "ssh", FAKE_SSH_LINUX_SCRIPT);

    import_json(&dir, INVENTORY_JSON);
    run_ok(orbyn(&dir).args([
        "annotate",
        "10.0.0.2",
        "--environment",
        "prod",
        "--owner",
        "platform",
        "--criticality",
        "high",
        "--add-tag",
        "core",
    ]));

    // Re-discover the same host (via ssh, which upserts the asset).
    run_ok(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.5", "--collector", "ssh"])
            .env("ORBYN_SSH_BIN", &bin),
    );

    let detail = run_ok(orbyn(&dir).args(["asset", "10.0.0.2"]));
    assert!(detail.contains("prod"));
    assert!(detail.contains("platform"));
    assert!(detail.contains("core"));
    assert!(detail.contains("high"));
}

/// A fake `ssh` that logs its start time and sleeps before emitting the
/// Linux probe, making launch pacing observable.
#[cfg(unix)]
const SLOW_LOGGING_SSH_SCRIPT: &str = r#"#!/usr/bin/env bash
if [[ -n "$ORBYN_SSH_START_LOG" ]]; then
  printf '%s\n' "$(date +%s.%N)" >> "$ORBYN_SSH_START_LOG"
fi
sleep 1
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
/dev/sdb1      xfs       209612800  98765432 104947368      49% /data
###svc
nginx.service                 loaded active running A high performance web server and reverse proxy
###conn
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB  0      0      10.0.0.5:54322        10.0.0.2:5432            users:(("postgres",pid=977,fd=6))
###metric
62.50|16384532|2655988|8388604|4194304|2.10,2.00,1.90
OUT
"#;

#[cfg(unix)]
fn ssh_start_gap_seconds(dir: &TempDir) -> f64 {
    let log = std::fs::read_to_string(dir.path().join("ssh-starts.log")).expect("ssh start log");
    let stamps: Vec<f64> = log.lines().filter_map(|l| l.trim().parse().ok()).collect();
    assert_eq!(stamps.len(), 2, "two ssh launches, got: {log}");
    stamps[1] - stamps[0]
}

#[cfg(unix)]
#[test]
fn multi_target_discovery_runs_one_job_over_all_targets() {
    let dir = TempDir::new("multi-target");
    let bin = fake_bin(&dir, "ssh", FAKE_SSH_LINUX_SCRIPT);

    let out = run_ok_combined(
        orbyn(&dir)
            .args([
                "discover",
                "--target",
                "10.0.0.5",
                "--target",
                "10.0.0.6",
                "--collector",
                "ssh",
            ])
            .env("ORBYN_SSH_BIN", &bin),
    );
    assert!(out.contains("2 assets"), "{out}");

    let assets = run_ok(orbyn(&dir).args(["assets", "--format", "csv"]));
    assert!(assets.contains("10.0.0.5"));
    assert!(assets.contains("10.0.0.6"));

    // one job covering both targets, with aggregated counts
    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("ssh,succeeded"), "{jobs}");
    assert!(
        jobs.contains("10.0.0.5;10.0.0.6"),
        "both targets recorded: {jobs}"
    );
    assert!(
        jobs.contains(",2,0,4,4,6,"),
        "assets=2 services=0 fs=4 running=4 conns=6: {jobs}"
    );
}

#[cfg(unix)]
#[test]
fn discovery_runs_targets_concurrently() {
    let dir = TempDir::new("concurrent");
    let bin = fake_bin(&dir, "ssh", SLOW_LOGGING_SSH_SCRIPT);
    let log = dir.path().join("ssh-starts.log");

    run_ok(
        orbyn(&dir)
            .args([
                "discover",
                "--target",
                "10.0.0.5",
                "--target",
                "10.0.0.6",
                "--collector",
                "ssh",
                "--concurrency",
                "2",
            ])
            .env("ORBYN_SSH_BIN", &bin)
            .env("ORBYN_SSH_START_LOG", &log),
    );

    let gap = ssh_start_gap_seconds(&dir);
    assert!(
        gap < 0.9,
        "probes sleep 1s; a gap of {gap:.2}s means they did not overlap"
    );
}

#[cfg(unix)]
#[test]
fn discovery_serializes_with_concurrency_one() {
    let dir = TempDir::new("serial");
    let bin = fake_bin(&dir, "ssh", SLOW_LOGGING_SSH_SCRIPT);
    let log = dir.path().join("ssh-starts.log");

    run_ok(
        orbyn(&dir)
            .args([
                "discover",
                "--target",
                "10.0.0.5",
                "--target",
                "10.0.0.6",
                "--collector",
                "ssh",
                "--concurrency",
                "1",
            ])
            .env("ORBYN_SSH_BIN", &bin)
            .env("ORBYN_SSH_START_LOG", &log),
    );

    let gap = ssh_start_gap_seconds(&dir);
    assert!(
        gap >= 0.9,
        "probes sleep 1s; with one worker the second must start after the \
         first finishes, got {gap:.2}s"
    );
}

#[cfg(unix)]
#[test]
fn rate_limit_paces_target_launches() {
    let dir = TempDir::new("rate-limit");
    let bin = fake_bin(&dir, "ssh", SLOW_LOGGING_SSH_SCRIPT);
    let log = dir.path().join("ssh-starts.log");

    run_ok(
        orbyn(&dir)
            .args([
                "discover",
                "--target",
                "10.0.0.5",
                "--target",
                "10.0.0.6",
                "--collector",
                "ssh",
                "--concurrency",
                "8",
                "--rate-limit",
                "1",
            ])
            .env("ORBYN_SSH_BIN", &bin)
            .env("ORBYN_SSH_START_LOG", &log),
    );

    let gap = ssh_start_gap_seconds(&dir);
    assert!(
        gap >= 0.9,
        "rate limit of 1/s must delay the second launch by ~1s, got {gap:.2}s"
    );
}

#[cfg(unix)]
#[test]
fn partial_failure_keeps_successful_targets() {
    let dir = TempDir::new("partial-failure");
    // Fails only when the destination is the unreachable host.
    let script = format!(
        r#"#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in
    *10.0.0.99*) echo "ssh: connect to host 10.0.0.99 port 22: Connection timed out" >&2; exit 255;;
  esac
done
{}
"#,
        FAKE_SSH_LINUX_SCRIPT.trim_start_matches("#!/usr/bin/env bash\n")
    );
    let bin = fake_bin(&dir, "ssh", &script);

    let out = run_fail(
        orbyn(&dir)
            .args([
                "discover",
                "--target",
                "10.0.0.5",
                "--target",
                "10.0.0.99",
                "--collector",
                "ssh",
            ])
            .env("ORBYN_SSH_BIN", &bin),
    );
    assert!(out.contains("1 of 2 targets failed"), "got: {out}");
    assert!(out.contains("timed out"), "got: {out}");

    // the reachable target's data is kept despite the failed job
    let assets = run_ok(orbyn(&dir).args(["assets", "--format", "csv"]));
    assert!(assets.contains("10.0.0.5"), "{assets}");
    assert!(!assets.contains("10.0.0.99"), "{assets}");

    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("ssh,failed"), "{jobs}");
    assert!(jobs.contains("timed out"), "{jobs}");
    assert!(jobs.contains(",1,0,2,2,3,"), "partial counts: {jobs}");
}

#[cfg(unix)]
#[test]
fn discover_rejects_zero_concurrency_and_rate_limit() {
    let dir = TempDir::new("bad-limits");
    let bin = fake_bin(&dir, "nmap", FAKE_NMAP_SCRIPT);

    let out = run_fail(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.10", "--concurrency", "0"])
            .env("ORBYN_NMAP_BIN", &bin),
    );
    assert!(
        out.contains("--concurrency must be at least 1"),
        "got: {out}"
    );

    let out = run_fail(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.10", "--rate-limit", "0"])
            .env("ORBYN_NMAP_BIN", &bin),
    );
    assert!(
        out.contains("--rate-limit must be at least 1"),
        "got: {out}"
    );
}
