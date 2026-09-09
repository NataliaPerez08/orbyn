//! End-to-end inventory tests: import/export round trips, job history,
//! machine-readable formats and error paths.

mod common;

use common::*;

const THREE_ASSETS_JSON: &str = r#"{"assets":[
  {"ip":"10.0.0.1","hostname":"api-01","device_class":"server","environment":"prod","owner":"platform","criticality":"high","tags":["core","api"]},
  {"ip":"10.0.0.2","hostname":"db-01","device_class":"server","environment":"prod","os_name":"Ubuntu 22.04.4 LTS","criticality":"critical"},
  {"ip":"10.0.0.3","hostname":"web-01","device_class":"server"}
]}"#;

#[cfg(unix)]
#[test]
fn import_export_round_trip_preserves_fields() {
    let a = TempDir::new("roundtrip-a");
    let b = TempDir::new("roundtrip-b");

    import_json(&a, THREE_ASSETS_JSON);

    // export CSV from the first DB
    let csv_path = a.path().join("inventory.csv");
    run_ok(
        orbyn(&a)
            .args(["export", "--format", "csv", "--output"])
            .arg(&csv_path),
    );
    let csv = std::fs::read_to_string(&csv_path).expect("read export");
    assert!(csv.contains("#assets"));
    assert!(csv.contains("api-01"));

    // import that CSV into a second DB
    run_ok(
        orbyn(&b)
            .args(["import", "--format", "csv", "--file"])
            .arg(&csv_path),
    );

    let out = run_ok(orbyn(&b).args(["assets", "--format", "csv"]));
    assert!(out.contains("api-01"));
    assert!(out.contains("db-01"));
    assert!(out.contains("Ubuntu 22.04.4 LTS"), "OS preserved: {out}");
    assert!(out.contains("critical"));

    // annotations preserved across the round trip
    let detail = run_ok(orbyn(&b).args(["asset", "api-01"]));
    assert!(detail.contains("platform"));
    assert!(detail.contains("core"));
}

#[cfg(unix)]
#[test]
fn import_accepts_compact_csv_without_section_header() {
    let dir = TempDir::new("compact-csv");
    let csv = "10.0.0.10,app-01,server,prod,team-a,high,\"a,b\"\n";
    let file = dir.path().join("compact.csv");
    std::fs::write(&file, csv).expect("write csv");

    run_ok(
        orbyn(&dir)
            .args(["import", "--format", "csv", "--file"])
            .arg(&file),
    );

    let detail = run_ok(orbyn(&dir).args(["asset", "10.0.0.10"]));
    assert!(detail.contains("app-01"));
    assert!(detail.contains("team-a"));
    assert!(
        detail.contains("a,b") || detail.contains("a, b") || detail.contains("b"),
        "tags: {detail}"
    );
}

#[cfg(unix)]
#[test]
fn import_deduplicates_rows_by_ip_with_warning() {
    let dir = TempDir::new("dedup-import");
    let json = r#"{"assets":[
      {"ip":"10.0.0.1","hostname":"first-01","device_class":"server"},
      {"ip":"10.0.0.1","hostname":"second-01","device_class":"server"}
    ]}"#;
    let file = dir.path().join("dup.json");
    std::fs::write(&file, json).expect("write json");

    let out = run_ok_combined(
        orbyn(&dir)
            .args(["import", "--format", "json", "--file"])
            .arg(&file),
    );
    assert!(out.contains("Imported 1 assets"), "got: {out}");
    assert!(out.contains("duplicate"), "warning expected: {out}");

    // The first occurrence wins.
    let assets = run_ok(orbyn(&dir).args(["assets", "--format", "csv"]));
    assert!(assets.contains("first-01"));
    assert!(!assets.contains("second-01"));
}

#[cfg(unix)]
#[test]
fn jobs_history_respects_limit_and_csv() {
    let dir = TempDir::new("jobs");
    let bin = fake_bin(&dir, "nmap", FAKE_NMAP_SCRIPT);

    for _ in 0..2 {
        run_ok(
            orbyn(&dir)
                .args(["discover", "--target", "10.0.0.10"])
                .env("ORBYN_NMAP_BIN", &bin),
        );
    }

    let csv = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    let header = csv.lines().next().unwrap();
    assert!(header.contains("id,collector,status,targets"));
    assert_eq!(csv.lines().count(), 3, "header + 2 jobs");

    let limited = run_ok(orbyn(&dir).args(["jobs", "--limit", "1", "--format", "csv"]));
    assert_eq!(limited.lines().count(), 2, "header + 1 job");
}

#[cfg(unix)]
#[test]
fn machine_readable_formats_parse_as_json() {
    let dir = TempDir::new("formats");
    import_json(&dir, THREE_ASSETS_JSON);

    let assets = run_ok(orbyn(&dir).args(["assets", "--format", "json"]));
    let v: serde_json::Value = serde_json::from_str(&assets).expect("assets JSON");
    assert_eq!(v.as_array().unwrap().len(), 3);

    // a full export includes assets, interfaces and services
    let export = run_ok(orbyn(&dir).args(["export", "--format", "json"]));
    let v: serde_json::Value = serde_json::from_str(&export).expect("export JSON");
    for key in ["assets", "interfaces", "services"] {
        assert!(v.get(key).is_some(), "export missing {key}");
    }
}

#[cfg(unix)]
#[test]
fn error_paths_report_clean_failures() {
    let dir = TempDir::new("errors");
    import_json(&dir, THREE_ASSETS_JSON);

    // unknown asset
    let out = run_fail(orbyn(&dir).args(["asset", "10.0.0.99"]));
    assert!(out.contains("no asset matches '10.0.0.99'"));

    // annotate unknown asset
    let out = run_fail(orbyn(&dir).args(["annotate", "nope", "--owner", "x"]));
    assert!(out.contains("no asset matches 'nope'"));

    // bad criticality value
    let out = run_fail(orbyn(&dir).args(["annotate", "10.0.0.1", "--criticality", "bogus"]));
    assert!(out.contains("unknown criticality"), "got: {out}");

    // invalid import JSON
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, "{not json").unwrap();
    let out = run_fail(
        orbyn(&dir)
            .args(["import", "--format", "json", "--file"])
            .arg(&bad),
    );
    assert!(out.contains("invalid JSON import"), "got: {out}");
}
