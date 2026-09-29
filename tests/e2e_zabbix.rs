//! End-to-end tests for the Zabbix historical utilization importer: a fake
//! `curl` answers `host.get`, `item.get` and `history.get` from canned
//! fixtures so the full flow — API call, inventory mapping, idempotent
//! persistence, utilization windows and right-sizing assessment — runs
//! without a network.

mod common;

#[cfg(unix)]
use common::*;
#[cfg(unix)]
use std::path::PathBuf;

/// A fake `curl` implementing a minimal Zabbix JSON-RPC endpoint. It reads the
/// envelope from stdin (exactly how Orbyn sends it) and dispatches on the
/// requested `method`, answering from fixtures in the environment. It logs
/// argv and stdin so secret handling can be asserted.
#[cfg(unix)]
const FAKE_ZABBIX_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
log="${ORBYN_ZBX_LOG}"
# stdin carries the JSON-RPC envelope exactly once; read it before logging.
envelope="$(cat)"
if [[ -n "$log" ]]; then
  printf '%s\n' "$@" >> "$log.argv"
  printf '%s\n' "$envelope" >> "$log.stdin"
fi
method="$(printf '%s' "$envelope" | sed -n 's/.*"method":"\([^"]*\)".*/\1/p')"
result=''
case "$method" in
  host.get)
    result="${ORBYN_ZBX_HOSTS}"
    ;;
  item.get)
    result="${ORBYN_ZBX_ITEMS}"
    ;;
  history.get)
    if [[ "$envelope" == *'"history":0'* ]]; then
      result="${ORBYN_ZBX_FLOAT_HISTORY:-[]}"
    else
      result="${ORBYN_ZBX_UINT_HISTORY:-[]}"
    fi
    ;;
  *)
    printf '{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found","data":"%s"},"id":1}' "$method"
    exit 0
    ;;
esac
printf '{"jsonrpc":"2.0","result":%s,"id":1}' "$result"
"#;

/// A fake `ssh` emitting a Linux host probe without the `###metric`
/// snapshots, so the Zabbix import is the asset's only utilization window.
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

/// One monitored host, resolved by interface IP.
#[cfg(unix)]
fn zabbix_hosts(ip: &str) -> String {
    format!(
        r#"[{{"hostid":"10084","host":"web-01","name":"Web 01",
             "interfaces":[{{"ip":"{ip}","dns":"web-01"}}]}}]"#
    )
}

/// The four supported items: CPU (float), RAM total/available and swap used
/// (unsigned, in bytes).
#[cfg(unix)]
fn zabbix_items() -> String {
    r#"[{"itemid":"28001","hostid":"10084","key_":"system.cpu.util","value_type":0,"units":"%"},
        {"itemid":"28002","hostid":"10084","key_":"vm.memory.size","value_type":3,"units":"B"},
        {"itemid":"28003","hostid":"10084","key_":"vm.memory.size[pavailable]","value_type":3,"units":"B"},
        {"itemid":"28004","hostid":"10084","key_":"vm.memory.size[pswapused]","value_type":3,"units":"B"}]"#
    .to_string()
}

/// History rows for one series: `count` points, `interval_hours` apart,
/// ending now, cycling through `values`.
#[cfg(unix)]
fn zabbix_rows(itemid: &str, count: usize, interval_hours: i64, values: &[f64]) -> Vec<String> {
    let now = chrono::Utc::now().timestamp();
    (0..count)
        .map(|i| {
            let clock = now - i as i64 * interval_hours * 3600;
            let v = values[i % values.len()];
            format!(r#"{{"itemid":"{itemid}","clock":"{clock}","value":"{v:.4}"}}"#)
        })
        .collect()
}

/// One `history.get` result array over the given series.
#[cfg(unix)]
fn zabbix_history(series: &[Vec<String>]) -> String {
    let rows: Vec<String> = series.iter().flatten().cloned().collect();
    format!("[{}]", rows.join(","))
}

#[cfg(unix)]
fn zabbix_env(dir: &TempDir, curl: &PathBuf) -> std::process::Command {
    let mut cmd = orbyn(dir);
    cmd.env("ORBYN_CURL_BIN", curl)
        .env("ORBYN_ZABBIX_TOKEN", "zabbix-secret-token");
    cmd
}

/// One week of low CPU and RAM usage: the same shape the Prometheus
/// importer produces, so the right-sizing outcome is comparable. CPU is
/// float history; RAM total/available and swap are unsigned history.
#[cfg(unix)]
fn week_of_low_utilization() -> (String, String) {
    let cpu = zabbix_history(&[zabbix_rows("28001", 24, 8, &[15.0, 20.0, 25.0])]);
    let memory = zabbix_history(&[
        zabbix_rows("28002", 24, 8, &[16_384.0 * 1024.0 * 1024.0]),
        zabbix_rows("28003", 24, 8, &[14_336.0 * 1024.0 * 1024.0]),
    ]);
    (cpu, memory)
}

/// Import one week of history. The fixtures are passed in rather than
/// regenerated here: sample clocks are relative to "now", so a re-import must
/// reuse the same instants to be recognized as duplicates.
#[cfg(unix)]
fn import_week(
    dir: &TempDir,
    curl: &PathBuf,
    ip: &str,
    history: &(String, String),
    log: Option<&std::path::Path>,
) -> String {
    let (cpu, memory) = history;
    let mut cmd = zabbix_env(dir, curl);
    cmd.args([
        "zabbix",
        "import",
        "--url",
        "https://zabbix/zabbix/api_jsonrpc.php",
    ])
    .env("ORBYN_ZBX_HOSTS", zabbix_hosts(ip))
    .env("ORBYN_ZBX_ITEMS", zabbix_items())
    .env("ORBYN_ZBX_FLOAT_HISTORY", cpu)
    .env("ORBYN_ZBX_UINT_HISTORY", memory);
    if let Some(log) = log {
        cmd.env("ORBYN_ZBX_LOG", log);
    }
    run_ok_combined(&mut cmd)
}

#[cfg(unix)]
#[test]
fn zabbix_import_builds_a_week_of_history() {
    let dir = TempDir::new("zbx");
    let log = dir.path().join("zbx-curl");
    let curl = fake_bin(&dir, "curl", FAKE_ZABBIX_CURL_SCRIPT);
    import_json(&dir, INVENTORY_JSON);

    let out = import_week(
        &dir,
        &curl,
        "10.0.0.2",
        &week_of_low_utilization(),
        Some(&log),
    );
    assert!(
        out.contains("Imported 24 metric samples from Zabbix"),
        "{out}"
    );
    assert!(out.contains("0 duplicates"), "{out}");

    // The window summarizes with its span and right-sizing readiness, and
    // RAM used is derived as total minus available.
    let metrics = run_ok(orbyn(&dir).args(["metrics", "10.0.0.2"]));
    assert!(metrics.contains("24 samples over 184.0h"), "{metrics}");
    assert!(metrics.contains("sufficient for right-sizing"), "{metrics}");
    assert!(metrics.contains("p95 25.00%"), "{metrics}");
    assert!(metrics.contains("p95 2.00 GiB"), "{metrics}");

    // The import is recorded in the audit trail.
    let audit = run_ok(orbyn(&dir).args(["audit", "--format", "csv"]));
    assert!(audit.contains("zabbix.import"), "{audit}");

    // The token reached curl only inside the stdin envelope, never argv.
    let argv = std::fs::read_to_string(log.with_extension("argv")).expect("argv log");
    assert!(
        !argv.contains("zabbix-secret-token"),
        "token leaked to argv: {argv}"
    );
    let stdin_log = std::fs::read_to_string(log.with_extension("stdin")).expect("stdin log");
    assert!(
        stdin_log.contains("\"auth\":\"zabbix-secret-token\""),
        "token must be delivered inside the stdin envelope: {stdin_log}"
    );
    // Every request is a read-only method.
    assert!(stdin_log.contains("\"method\":\"host.get\""), "{stdin_log}");
    assert!(stdin_log.contains("\"method\":\"item.get\""), "{stdin_log}");
    assert!(
        stdin_log.contains("\"method\":\"history.get\""),
        "{stdin_log}"
    );
}

#[cfg(unix)]
#[test]
fn zabbix_reimport_is_idempotent() {
    let dir = TempDir::new("zbx-idempotent");
    let curl = fake_bin(&dir, "curl", FAKE_ZABBIX_CURL_SCRIPT);
    import_json(&dir, INVENTORY_JSON);

    // Built once: both imports must present the same sample clocks.
    let history = week_of_low_utilization();

    assert!(
        import_week(&dir, &curl, "10.0.0.2", &history, None).contains("Imported 24 metric samples")
    );
    let second = import_week(&dir, &curl, "10.0.0.2", &history, None);
    assert!(second.contains("Imported 0 metric samples"), "{second}");
    assert!(second.contains("24 duplicates skipped"), "{second}");

    let metrics = run_ok(orbyn(&dir).args(["metrics", "10.0.0.2"]));
    assert!(metrics.contains("24 samples over"), "{metrics}");
}

#[cfg(unix)]
#[test]
fn zabbix_unmatched_hosts_fail_cleanly() {
    let dir = TempDir::new("zbx-unmatched");
    let curl = fake_bin(&dir, "curl", FAKE_ZABBIX_CURL_SCRIPT);
    import_json(&dir, INVENTORY_JSON);

    let (cpu, memory) = week_of_low_utilization();
    let out = run_fail(
        zabbix_env(&dir, &curl)
            .args([
                "zabbix",
                "import",
                "--url",
                "https://zabbix/zabbix/api_jsonrpc.php",
            ])
            .env("ORBYN_ZBX_HOSTS", zabbix_hosts("10.0.0.99"))
            .env("ORBYN_ZBX_ITEMS", zabbix_items())
            .env("ORBYN_ZBX_FLOAT_HISTORY", cpu)
            .env("ORBYN_ZBX_UINT_HISTORY", memory),
    );
    assert!(
        out.contains("no Zabbix host matched a known asset"),
        "{out}"
    );
    assert!(out.contains("1 unmatched hosts"), "{out}");

    // The failed import is still auditable.
    let audit = run_ok(orbyn(&dir).args(["audit", "--format", "csv"]));
    assert!(audit.contains("failed"), "{audit}");
}

#[cfg(unix)]
#[test]
fn zabbix_api_errors_are_surfaced_without_the_token() {
    let dir = TempDir::new("zbx-error");
    // A fake that fails every method, echoing the error Zabbix would send.
    let curl = fake_bin(
        &dir,
        "curl",
        r#"#!/usr/bin/env bash
cat > /dev/null
printf '{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params.","data":"not authorised"},"id":1}'
"#,
    );
    import_json(&dir, INVENTORY_JSON);

    let out = run_fail(zabbix_env(&dir, &curl).args([
        "zabbix",
        "import",
        "--url",
        "https://zabbix/zabbix/api_jsonrpc.php",
    ]));
    assert!(out.contains("Zabbix host.get failed"), "{out}");
    assert!(out.contains("Invalid params."), "{out}");
    assert!(
        !out.contains("zabbix-secret-token"),
        "the token must never appear in an error: {out}"
    );
}

#[cfg(unix)]
#[test]
fn zabbix_rejects_a_malformed_url() {
    let dir = TempDir::new("zbx-url");
    let curl = fake_bin(&dir, "curl", FAKE_ZABBIX_CURL_SCRIPT);
    import_json(&dir, INVENTORY_JSON);

    let out = run_fail(
        zabbix_env(&dir, &curl)
            .args(["zabbix", "import", "--url", "zabbix.example.com"])
            .env("ORBYN_ZBX_HOSTS", zabbix_hosts("10.0.0.2")),
    );
    assert!(out.contains("invalid Zabbix URL"), "{out}");
}

#[cfg(unix)]
#[test]
fn assess_right_sizes_a_week_of_zabbix_utilization() {
    let dir = TempDir::new("zbx-right-size");
    let ssh = fake_bin(&dir, "ssh", FAKE_SSH_NO_SNAPSHOTS_SCRIPT);
    let curl = fake_bin(&dir, "curl", FAKE_ZABBIX_CURL_SCRIPT);

    // Host-level collection records the allocation (4 cores, ~16 GB).
    run_ok_combined(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.5", "--collector", "ssh"])
            .env("ORBYN_SSH_BIN", &ssh),
    );

    let cpu = zabbix_history(&[zabbix_rows("28001", 24, 8, &[15.0, 20.0, 25.0])]);
    let mib = 1024.0 * 1024.0;
    let unsigned = zabbix_history(&[
        zabbix_rows("28002", 24, 8, &[16_384.0 * mib]),
        zabbix_rows("28003", 24, 8, &[14_336.0 * mib]),
        zabbix_rows("28004", 24, 8, &[4096.0 * mib]),
    ]);
    run_ok_combined(
        zabbix_env(&dir, &curl)
            .args([
                "zabbix",
                "import",
                "--url",
                "https://zabbix/zabbix/api_jsonrpc.php",
            ])
            .env("ORBYN_ZBX_HOSTS", zabbix_hosts("10.0.0.5"))
            .env("ORBYN_ZBX_ITEMS", zabbix_items())
            .env("ORBYN_ZBX_FLOAT_HISTORY", cpu)
            .env("ORBYN_ZBX_UINT_HISTORY", unsigned),
    );

    let assess = run_ok(orbyn(&dir).args(["assess", "--format", "csv"]));
    assert!(assess.contains("rs.cpu-overprovisioned"), "{assess}");
    // 4 physical cores, p99 25%: ceil(4 x 0.25 x 1.5) = 2 cores.
    assert!(assess.contains("4 cores could shrink to 2"), "{assess}");
    // 16384 - 14336 = 2048 MB used: ceil(2048 x 1.5) = 3072 MB.
    assert!(assess.contains("rs.ram-overprovisioned"), "{assess}");
    assert!(assess.contains("= 3072 MB"), "{assess}");
    assert!(
        !assess.contains("rs.window-insufficient"),
        "a ready window must not be called insufficient: {assess}"
    );
    // Swap is imported too, so the paging rule sees a full week of it.
    assert!(assess.contains("rs.swap-pressure"), "{assess}");
    assert!(assess.contains("0.8.0"), "{assess}");
}
