//! End-to-end migration wave tests: `orbyn waves` turns a seeded inventory
//! into risk-banded waves whose reasoning is exposed, honoring pins/excludes.

mod common;

#[cfg(unix)]
use common::*;

/// JSON inventory: db-01 is production/critical with an EOL OS, cache-01 is
/// unannotated.
#[cfg(unix)]
const SEED_JSON: &str = r#"{"assets":[
  {"ip":"10.0.0.2","hostname":"db-01","device_class":"server","environment":"prod","os_name":"Ubuntu 18.04.6 LTS","criticality":"critical"},
  {"ip":"10.0.0.9","hostname":"cache-01","device_class":"server","os_name":"Ubuntu 22.04.4 LTS"}
]}"#;

/// Couples cache-01 to db-01 so they land in one application group and must
/// migrate as a unit.
#[cfg(unix)]
fn seed(dir: &TempDir) {
    import_json(dir, SEED_JSON);
    run_ok(orbyn(dir).args(["deps", "add", "cache-01", "db-01", "--port", "6379"]));
}

#[cfg(unix)]
#[test]
fn waves_reports_both_assets_in_one_unit() {
    let dir = TempDir::new("waves");
    seed(&dir);

    let table = run_ok(orbyn(&dir).args(["waves"]));
    assert!(table.contains("10-0-0-2"), "db-01 in waves: {table}");
    assert!(table.contains("10-0-0-9"), "cache-01 in waves: {table}");
    // both are members of app-1, so they share a wave (group moves together)
    let db_line = table
        .lines()
        .find(|l| l.contains("10-0-0-2"))
        .expect("db-01 row");
    assert!(db_line.contains("member of app-1"), "{table}");
    // reasons are exposed, not a bare number
    assert!(db_line.contains("production environment prod"), "{table}");
    assert!(db_line.contains("criticality critical"), "{table}");
}

#[cfg(unix)]
#[test]
fn waves_json_is_parseable_and_explains() {
    let dir = TempDir::new("waves-json");
    seed(&dir);

    let json = run_ok(orbyn(&dir).args(["waves", "--format", "json"]));
    let plan: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
    let waves = plan["waves"].as_array().expect("waves array");
    assert!(!waves.is_empty());
    for wave in waves {
        assert!(wave["index"].is_u64());
        assert!(wave["label"].is_string());
        assert!(!wave["assets"].as_array().unwrap().is_empty());
        for asset in wave["assets"].as_array().unwrap() {
            assert!(asset["asset_id"].is_string());
            assert!(asset["score"].is_u64());
            assert!(!asset["reasons"].as_array().unwrap().is_empty());
        }
    }
}

#[cfg(unix)]
#[test]
fn waves_pin_forces_the_whole_group() {
    let dir = TempDir::new("waves-pin");
    seed(&dir);

    let out = run_ok(orbyn(&dir).args(["waves", "--pin", "10-0-0-2=1"]));
    assert!(out.contains("1 (low risk)"), "pinned to wave 1: {out}");
    assert!(out.contains("10-0-0-9"), "partner moved too: {out}");
    assert!(out.contains("pinned to wave 1 via --pin"), "{out}");
}

#[cfg(unix)]
#[test]
fn waves_exclude_and_unknown_pin_are_reported() {
    let dir = TempDir::new("waves-exclude");
    seed(&dir);

    let out = run_ok(orbyn(&dir).args(["waves", "--exclude", "10-0-0-2"]));
    // the asset is listed only in the excluded note, not in any wave row
    let occurrences = out.matches("10-0-0-2").count();
    assert_eq!(occurrences, 1, "excluded asset leaked into a wave: {out}");
    assert!(out.contains("excluded: 10-0-0-2"), "{out}");

    let warn = run_ok(orbyn(&dir).args(["waves", "--pin", "ghost=2"]));
    assert!(warn.contains("pin ignored: ghost"), "{warn}");

    let bad = run_fail(orbyn(&dir).args(["waves", "--pin", "10-0-0-2=nope"]));
    assert!(bad.contains("wave must be"), "bad pin: {bad}");
}

#[cfg(unix)]
#[test]
fn waves_csv_has_a_header() {
    let dir = TempDir::new("waves-csv");
    seed(&dir);

    let csv = run_ok(orbyn(&dir).args(["waves", "--format", "csv"]));
    assert!(csv.starts_with("wave,label,asset,score,reasons"), "{csv}");
    assert!(csv.contains("10-0-0-2"), "{csv}");
}
