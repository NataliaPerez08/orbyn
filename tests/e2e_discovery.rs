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

#[cfg(unix)]
#[test]
fn snmp_discovery_classifies_network_device() {
    let dir = TempDir::new("snmp");
    let bin = fake_bin(&dir, "snmpwalk", FAKE_SNMPWALK_SCRIPT);

    let out = run_ok(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.8", "--collector", "snmp"])
            .env("ORBYN_SNMP_BIN", &bin),
    );
    assert!(out.contains("switch-core-1"));
    assert!(out.contains("network-device"));

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

    // capacity
    let cap = run_ok(orbyn(&dir).args(["capacity", "10.0.0.5"]));
    assert!(cap.contains("Intel(R) Xeon(R) Gold 6138"));
    assert!(cap.contains("8"));
    assert!(cap.contains("16001 MB"));

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

    let disks = run_ok(orbyn(&dir).args(["disks", "10.0.0.20", "--format", "csv"]));
    assert!(disks.contains("C:,NTFS"));
    assert!(disks.contains("D:,NTFS"));

    let svcs = run_ok(orbyn(&dir).args(["host-services", "10.0.0.20"]));
    assert!(svcs.contains("W3SVC"));
    assert!(svcs.contains("MSSQLSERVER"));
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
