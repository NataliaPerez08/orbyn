//! End-to-end coverage for `orbyn targets compare|recommend`: fit
//! scoring, honest not-calculated components, version stamps and the
//! price-never-decides recommendation.

mod common;

use common::{import_json, orbyn, run_fail, run_ok, run_ok_combined, TempDir};

const INVENTORY: &str = r#"{"assets":[
  {"ip":"10.0.0.2","hostname":"frontend01","device_class":"server","environment":"prod","criticality":"high","os_name":"Ubuntu 22.04"},
  {"ip":"10.0.0.3","hostname":"frontend02","device_class":"server","environment":"prod","criticality":"high","os_name":"Ubuntu 22.04"},
  {"ip":"10.0.0.4","hostname":"db01","device_class":"server","environment":"prod","criticality":"critical"}
]}"#;

fn seed(dir: &TempDir) {
    import_json(dir, INVENTORY);
    run_ok_combined(orbyn(dir).args(["deps", "add", "10.0.0.2", "10.0.0.4", "--port", "5432"]));
    run_ok_combined(orbyn(dir).args(["deps", "add", "10.0.0.3", "10.0.0.4", "--port", "5432"]));
    run_ok_combined(orbyn(dir).args(["applications", "discover"]));
}

#[test]
fn compare_shows_every_provider_with_honest_gaps() {
    let dir = TempDir::new("targets-compare");
    seed(&dir);

    let out = run_ok(orbyn(&dir).args(["targets", "compare", "frontend"]));
    assert!(out.contains("Target comparison: frontend"), "{out}");
    assert!(out.contains("strategy rehost"), "{out}");
    // No capacity data in the inventory: fit is penalized, compute stays
    // not calculated instead of a silent zero.
    assert!(out.contains("n/c"), "{out}");
    assert!(out.contains("aws"), "{out}");
    assert!(out.contains("azure"), "{out}");
    assert!(out.contains("gcp"), "{out}");
    assert!(out.contains("target-fit/v1"), "{out}");
    assert!(out.contains("cost/v1"), "{out}");

    let out = run_ok(orbyn(&dir).args(["targets", "compare", "frontend", "--format", "json"]));
    assert!(
        out.contains("\"target_fit_version\": \"target-fit/v1\""),
        "{out}"
    );
    assert!(out.contains("\"cost_model_version\": \"cost/v1\""), "{out}");
    assert!(
        out.contains("\"catalog_version\": \"aws-catalog/2026-10\""),
        "{out}"
    );
    assert!(out.contains("\"not_calculated\""), "{out}");
    assert!(out.contains("\"monthly_total\": null"), "{out}");

    let out = run_ok(orbyn(&dir).args(["targets", "compare", "frontend", "--format", "csv"]));
    assert!(out.contains("provider,region,fit"), "{out}");
    assert!(out.contains("aws,us-east-1"), "{out}");

    // Read-only: no audit events from compare.
    let out = run_ok_combined(orbyn(&dir).args(["audit", "--format", "csv"]));
    assert!(!out.contains("targets"), "{out}");
}

#[test]
fn recommend_explains_and_never_decides_on_price() {
    let dir = TempDir::new("targets-recommend");
    seed(&dir);

    let out = run_ok(orbyn(&dir).args(["targets", "recommend", "frontend"]));
    assert!(out.contains("Recommendation: frontend -> "), "{out}");
    assert!(out.contains("Alternative: "), "{out}");
    assert!(out.contains("Why:"), "{out}");
    assert!(out.contains("never the deciding factor"), "{out}");

    let out = run_ok(orbyn(&dir).args(["targets", "recommend", "frontend", "--format", "json"]));
    assert!(out.contains("\"recommended\""), "{out}");
    assert!(out.contains("\"why\""), "{out}");

    let out = run_fail(orbyn(&dir).args(["targets"]));
    assert!(out.contains("specify compare or recommend"), "{out}");
    let out = run_fail(orbyn(&dir).args(["targets", "compare", "nope"]));
    assert!(out.contains("no application matches 'nope'"), "{out}");
}
