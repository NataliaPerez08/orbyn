//! End-to-end assessment tests: the rule engine runs over a seeded inventory
//! and produces explainable findings, scores and application groups.

mod common;

#[cfg(unix)]
use common::*;

/// A JSON inventory with an EOL OS, plus a linux host discovered via ssh that
/// has a nearly-full disk and an external dependency.
#[cfg(unix)]
const SEED_JSON: &str = r#"{"assets":[
  {"ip":"10.0.0.2","hostname":"db-01","device_class":"server","environment":"prod","os_name":"Ubuntu 18.04.6 LTS","criticality":"critical"},
  {"ip":"10.0.0.9","hostname":"cache-01","device_class":"server","os_name":"Ubuntu 22.04.4 LTS"}
]}"#;

/// A Linux probe with a near-full root filesystem and a connection to db-01
/// plus an external endpoint.
#[cfg(unix)]
const SSH_NEAR_FULL: &str = r#"#!/usr/bin/env bash
cat <<'OUT'
###os
PRETTY_NAME="Ubuntu 22.04.4 LTS"
###kernel
5.15.0-94-generic
###hostname
web-01
###cpu
CPU(s):              4
Core(s) per socket:  4
Socket(s):           1
Model name:          Intel(R) Xeon(R) Silver 4310 CPU @ 2.20GHz
###mem
MemTotal:        8192308 kB
###disk
Filesystem     Type   1024-blocks      Used Available Capacity Mounted on
/dev/sda1      ext4       52425716  48231588   3132634      92% /
###svc
nginx.service                 loaded active running A high performance web server
###conn
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB  0      0      10.0.0.5:54322        10.0.0.2:5432            users:(("postgres",pid=977,fd=6))
ESTAB  0      0      10.0.0.5:49201        203.0.113.9:443          users:(("curl",pid=981,fd=5))
OUT
"#;

#[cfg(unix)]
fn seed(dir: &TempDir) {
    import_json(dir, SEED_JSON);
    let bin = fake_bin(dir, "ssh", SSH_NEAR_FULL);
    run_ok(
        orbyn(dir)
            .args(["discover", "--target", "10.0.0.5", "--collector", "ssh"])
            .env("ORBYN_SSH_BIN", &bin),
    );
    // make db-01 a hub: a second asset depends on it
    run_ok(orbyn(dir).args(["deps", "add", "cache-01", "db-01", "--port", "6379"]));
}

#[cfg(unix)]
#[test]
fn assess_reports_findings_scores_and_groups() {
    let dir = TempDir::new("assess");
    seed(&dir);

    let table = run_ok(orbyn(&dir).args(["assess"]));
    assert!(table.contains("Rules version : 0.5.0"));
    assert!(table.contains("os.eol"), "EOL OS finding: {table}");
    assert!(table.contains("dep.hub"), "hub finding: {table}");
    assert!(table.contains("dep.external"), "external finding: {table}");
    assert!(table.contains("disk.near-full"), "disk finding: {table}");
    assert!(
        table.contains("dep.unconfirmed"),
        "unconfirmed finding: {table}"
    );
    assert!(
        table.contains("capacity.missing"),
        "missing capacity finding: {table}"
    );
    assert!(table.contains("app-1"), "application group: {table}");
}

#[cfg(unix)]
#[test]
fn assess_json_is_parseable_and_complete() {
    let dir = TempDir::new("assess-json");
    seed(&dir);

    let json = run_ok(orbyn(&dir).args(["assess", "--format", "json"]));
    let report: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

    assert_eq!(report["rules_version"], "0.5.0");
    assert_eq!(report["assets_assessed"], 3);
    let score = report["overall_score"].as_u64().expect("score");
    assert!(score <= 100);
    assert!(report["complexity"].is_string());
    assert!(report["findings"].is_array());
    assert!(!report["findings"].as_array().unwrap().is_empty());
    assert_eq!(report["application_groups"].as_array().unwrap().len(), 1);

    // every finding is explainable
    let findings = report["findings"].as_array().unwrap();
    for f in findings {
        assert!(f["rule_id"].is_string());
        assert!(f["severity"].is_string());
        assert!(f["message"].is_string());
        assert!(f["evidence"].is_array());
    }
}

#[cfg(unix)]
#[test]
fn assess_rules_catalog_lists_rules() {
    let dir = TempDir::new("assess-rules");

    let out = run_ok(orbyn(&dir).args(["assess", "--rules"]));
    assert!(out.contains("Rules version: 0.5.0"));
    for rule in [
        "os.missing",
        "os.eol",
        "svc.insecure-protocol",
        "svc.management-exposure",
        "dep.hub",
        "dep.external",
        "dep.unconfirmed",
        "capacity.missing",
        "disk.near-full",
    ] {
        assert!(out.contains(rule), "catalog missing {rule}: {out}");
    }

    // --rules conflicts with --format
    let fail = run_fail(orbyn(&dir).args(["assess", "--rules", "--format", "json"]));
    assert!(fail.contains("cannot be used"), "got: {fail}");
}

#[cfg(unix)]
#[test]
fn empty_inventory_assesses_as_low_complexity() {
    let dir = TempDir::new("assess-empty");
    let out = run_ok(orbyn(&dir).args(["assess"]));
    assert!(out.contains("Assets assessed : 0"));
    assert!(out.contains("0/100 (low)"));
}
