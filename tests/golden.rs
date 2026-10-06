//! Deterministic golden datasets.
//!
//! The import -> graph -> assess -> export pipeline over committed fixtures
//! must produce exactly the committed golden outputs. Any drift in counts,
//! findings, scores, groups or export rows fails the build.
//!
//! Set `ORBYN_GOLDEN_UPDATE=1` to regenerate the golden files after an
//! intended change; the normal run only compares.

mod common;

#[cfg(unix)]
use common::*;
#[cfg(unix)]
use serde_json::json;
#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
const GOLDEN_DIR: &str = "tests/fixtures/golden";

/// A deterministic inventory crafted to exercise several assessment rules:
/// supported and EOL OSes, a missing-OS asset, insecure and management
/// services, multi-interface assets, and rows missing optional fields.
#[cfg(unix)]
fn golden_inventory(n: usize) -> String {
    const OSES: [&str; 4] = [
        "Ubuntu 22.04.4 LTS",
        "Windows Server 2022 Standard",
        "Ubuntu 18.04.6 LTS",
        "Unsupported OS 1.0",
    ];
    let mut assets = Vec::new();
    let mut interfaces = Vec::new();
    let mut services = Vec::new();
    for i in 0..n {
        let ip = format!("192.168.{}.{}", i / 250, i % 250);
        let mut a = serde_json::Map::new();
        a.insert("ip".into(), json!(ip));
        if i % 5 != 0 {
            a.insert("hostname".into(), json!(format!("host-{i:05}")));
        }
        a.insert(
            "device_class".into(),
            json!(["server", "network", "storage", "virtual-machine"][i % 4]),
        );
        if i % 7 != 0 {
            a.insert("os_name".into(), json!(OSES[i % 4]));
        }
        a.insert("environment".into(), json!(format!("env-{}", i % 3)));
        a.insert("owner".into(), json!(format!("team-{}", i % 5)));
        a.insert(
            "criticality".into(),
            json!(["low", "medium", "high"][i % 3]),
        );
        a.insert("tags".into(), json!([format!("tag-{}", i % 4)]));
        assets.push(serde_json::Value::Object(a));

        for k in 0..(1 + i % 3) {
            interfaces.push(json!({
                "asset_id": ip,
                "name": format!("eth{k}"),
                "mac": format!("02:00:00:{:02x}:{:02x}:{:02x}", (i >> 8) & 0xff, (i >> 16) & 0xff, k),
                "ip": ip,
            }));
        }
        services.push(
            json!({"asset_id": ip, "proto": "tcp", "port": 22, "name": "ssh", "state": "open"}),
        );
        let extra = match i % 4 {
            0 => (23, "telnet"),
            1 => (3306, "mysql"),
            2 => (443, "https"),
            _ => (8080, "http-alt"),
        };
        services.push(json!({"asset_id": ip, "proto": "tcp", "port": extra.0, "name": extra.1, "state": "open"}));
    }
    json!({"assets": assets, "interfaces": interfaces, "services": services}).to_string()
}

/// Normalize an export CSV for comparison: drop the per-run discovery
/// timestamps (assets columns 11-12) and sort rows within each section so a
/// stable-order change in the store does not look like content drift.
#[cfg(unix)]
fn normalized_export(csv: &str) -> String {
    let mut out = String::new();
    let mut section: Option<String> = None;
    let mut header: Option<String> = None;
    let mut rows: Vec<String> = Vec::new();
    for line in csv.lines() {
        if let Some(name) = line.strip_prefix('#') {
            if let Some(sec) = section.take() {
                rows.sort();
                out.push_str(&format!(
                    "#{sec}\n{}\n{}\n\n",
                    header.clone().unwrap_or_default(),
                    rows.join("\n")
                ));
            }
            section = Some(name.to_string());
            header = None;
            rows.clear();
        } else if !line.trim().is_empty() {
            let mut fields: Vec<&str> = line.split(',').collect();
            if section.as_deref() == Some("assets") && fields.len() >= 12 {
                fields.truncate(10);
            }
            let joined = fields.join(",");
            if header.is_none() {
                header = Some(joined);
            } else {
                rows.push(joined);
            }
        }
    }
    if let Some(sec) = section {
        rows.sort();
        out.push_str(&format!(
            "#{sec}\n{}\n{}\n",
            header.unwrap_or_default(),
            rows.join("\n")
        ));
    }
    out
}

/// Deterministic edge order for the golden graph compare.
#[cfg(unix)]
fn normalized_graph(csv: &str) -> String {
    let mut lines: Vec<String> = csv.lines().map(String::from).collect();
    lines.sort();
    lines.join("\n")
}

/// Strip the per-run application timestamps so the explain snapshot stays
/// deterministic; everything else (ids, names, confidence, evidence) is a
/// pure function of the inventory.
#[cfg(unix)]
fn normalized_applications(json: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(json).expect("applications json");
    if let Some(obj) = v.get_mut("application").and_then(|a| a.as_object_mut()) {
        obj.remove("created_at");
        obj.remove("updated_at");
    }
    serde_json::to_string_pretty(&v).expect("serialize applications")
}

/// Strip the per-run plan identity (uuid, timestamps) so the plan
/// snapshot stays deterministic; readiness, strategy, targets, blockers
/// and wave are pure functions of the inventory.
#[cfg(unix)]
fn normalized_plan(json: &str) -> String {
    let mut v: serde_json::Value = serde_json::from_str(json).expect("plan json");
    if let Some(obj) = v.get_mut("plan").and_then(|p| p.as_object_mut()) {
        obj.remove("id");
        obj.remove("created_at");
        if let Some(prov) = obj.get_mut("provenance").and_then(|p| p.as_object_mut()) {
            prov.remove("last_seen");
        }
    }
    serde_json::to_string_pretty(&v).expect("serialize plan")
}

/// Import the inventory, add two deterministic manual edges (so the golden
/// output exercises the dependency graph and application grouping),
/// discover applications, and return the graph / assessment / export /
/// application-explain / migration-plan snapshots.
#[cfg(unix)]
fn snapshot(dir: &TempDir, inventory: &str) -> (String, String, String, String, String) {
    let file = dir.path().join("inventory.json");
    std::fs::write(&file, inventory).expect("write inventory");
    run_ok(
        orbyn(dir)
            .args(["import", "--format", "json", "--file"])
            .arg(&file),
    );
    run_ok_combined(orbyn(dir).args(["deps", "add", "host-00002", "host-00001", "--port", "5432"]));
    run_ok_combined(orbyn(dir).args(["deps", "add", "host-00003", "host-00001", "--port", "3306"]));

    let graph = normalized_graph(&run_ok(orbyn(dir).args(["graph", "--format", "csv"])));
    let discovered = run_ok(orbyn(dir).args(["applications", "discover", "--format", "json"]));
    let apps: serde_json::Value = serde_json::from_str(&discovered).expect("discover json");
    let name = apps[0]["application"]["name"]
        .as_str()
        .expect("discovered application")
        .to_string();
    let explain = normalized_applications(&run_ok(orbyn(dir).args([
        "applications",
        "explain",
        &name,
        "--format",
        "json",
    ])));
    let assess = run_ok(orbyn(dir).args(["assess", "--format", "json"]));
    let export = normalized_export(&run_ok(orbyn(dir).args(["export", "--format", "csv"])));
    // Last: `plan` persists an artifact, and the snapshots above must not
    // see it.
    let plan = normalized_plan(&run_ok(orbyn(dir).args([
        "plan",
        &name,
        "--explain",
        "--format",
        "json",
    ])));
    (graph, assess, export, explain, plan)
}

/// Run one golden dataset: compare against committed files, or regenerate them
/// when `ORBYN_GOLDEN_UPDATE=1` is set.
#[cfg(unix)]
fn run_golden(size: &str, count: usize) {
    let update = std::env::var_os("ORBYN_GOLDEN_UPDATE").is_some();
    let dir = TempDir::new(&format!("golden-{size}"));
    let inventory = golden_inventory(count);
    let base = Path::new(GOLDEN_DIR).join(size);
    std::fs::create_dir_all(&base).expect("create golden dir");
    if update {
        std::fs::write(base.join("inventory.json"), &inventory).expect("write inventory fixture");
    }
    let (graph, assess, export, explain, plan) = snapshot(&dir, &inventory);

    if update {
        std::fs::write(base.join("graph.csv"), &graph).expect("write graph golden");
        std::fs::write(base.join("assess.json"), &assess).expect("write assess golden");
        std::fs::write(base.join("export.csv"), &export).expect("write export golden");
        std::fs::write(base.join("explain.json"), &explain).expect("write explain golden");
        std::fs::write(base.join("plan.json"), &plan).expect("write plan golden");
        return;
    }
    let expect_graph = std::fs::read_to_string(base.join("graph.csv")).expect("graph golden");
    let expect_assess = std::fs::read_to_string(base.join("assess.json")).expect("assess golden");
    let expect_export = std::fs::read_to_string(base.join("export.csv")).expect("export golden");
    let expect_explain =
        std::fs::read_to_string(base.join("explain.json")).expect("explain golden");
    let expect_plan = std::fs::read_to_string(base.join("plan.json")).expect("plan golden");
    assert_eq!(graph, expect_graph, "dependency graph drift for {size}");
    assert_eq!(assess, expect_assess, "assessment drift for {size}");
    assert_eq!(export, expect_export, "export drift for {size}");
    assert_eq!(
        explain, expect_explain,
        "application explain drift for {size}"
    );
    assert_eq!(plan, expect_plan, "migration plan drift for {size}");
}

#[cfg(unix)]
#[test]
fn small_golden_dataset_is_stable() {
    run_golden("small", 10);
}

#[cfg(unix)]
#[test]
fn medium_golden_dataset_is_stable() {
    run_golden("medium", 100);
}

#[cfg(unix)]
#[test]
fn large_and_stress_inventories_keep_deterministic_counts() {
    for (size, n) in [("large", 1_000), ("stress", 10_000)] {
        let dir = TempDir::new(&format!("golden-{size}"));
        let file = dir.path().join("inventory.json");
        std::fs::write(&file, representative_inventory(n)).expect("write inventory");
        run_ok(
            orbyn(&dir)
                .args(["import", "--format", "json", "--file"])
                .arg(&file),
        );

        let export = run_ok(orbyn(&dir).args(["export", "--format", "csv"]));
        let mut assets_rows = 0;
        let mut interfaces_rows = 0;
        let mut services_rows = 0;
        let mut section = String::new();
        let mut first = true;
        for line in export.lines() {
            if let Some(name) = line.strip_prefix('#') {
                section = name.to_string();
                first = true;
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            if first {
                first = false; // column header
                continue;
            }
            match section.as_str() {
                "assets" => assets_rows += 1,
                "interfaces" => interfaces_rows += 1,
                "services" => services_rows += 1,
                _ => {}
            }
        }
        assert_eq!(assets_rows, n, "{size} asset rows");
        assert_eq!(
            interfaces_rows,
            n * common::INTERFACES_PER_ASSET,
            "{size} interface rows"
        );
        assert_eq!(
            services_rows,
            n * common::SERVICES_PER_ASSET,
            "{size} service rows"
        );

        let assess: serde_json::Value =
            serde_json::from_str(&run_ok(orbyn(&dir).args(["assess", "--format", "json"])))
                .expect("assess json");
        assert_eq!(assess["assets_assessed"], n as u64, "{size} assessed");
    }
}
