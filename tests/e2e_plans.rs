//! End-to-end coverage for `orbyn plan`: readiness, strategy, targets,
//! blockers, wave assignment and the `--all`/`--explain`/`--target` modes.

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
fn plan_reports_readiness_strategy_blockers_and_wave() {
    let dir = TempDir::new("plan");
    seed(&dir);

    // Readiness: -3 OS (db01), -6 owner, -12 capacity, -12 metrics = 67.
    // Strategy: standard workload -> rehost. Wave: prod+high = 4 -> 2.
    let out = run_ok(orbyn(&dir).args(["plan", "frontend", "--format", "json"]));
    assert!(out.contains("\"strategy\": \"rehost\""), "{out}");
    assert!(out.contains("\"readiness\": 67"), "{out}");
    assert!(out.contains("\"wave\": 2"), "{out}");
    assert!(out.contains("\"severity\": \"blocker\""), "{out}");
    assert!(out.contains("no OS information"), "{out}");
    assert!(out.contains("\"rules_version\": \"0.8.0\""), "{out}");
    assert!(
        out.contains("\"readiness_version\": \"readiness/v1\""),
        "{out}"
    );
    assert!(
        out.contains("\"strategy_version\": \"strategy/v1\""),
        "{out}"
    );

    let out = run_ok(orbyn(&dir).args(["plan", "frontend"]));
    assert!(out.contains("Migration plan: frontend"), "{out}");
    assert!(out.contains("Readiness   : 67/100"), "{out}");
    assert!(out.contains("Wave        : 2 (medium risk)"), "{out}");
    assert!(out.contains("[blocker] inventory-completeness"), "{out}");

    // --explain adds the wave reasoning.
    let out = run_ok(orbyn(&dir).args(["plan", "frontend", "--explain"]));
    assert!(out.contains("Why this wave:"), "{out}");
    assert!(out.contains("production environment prod"), "{out}");

    // --target affects recommendations only: the provider is recorded,
    // and providers without a catalog say so instead of guessing.
    let out = run_ok(orbyn(&dir).args(["plan", "frontend", "--target", "aws", "--format", "json"]));
    assert!(out.contains("\"provider\": \"aws\""), "{out}");
    let out = run_ok(orbyn(&dir).args([
        "plan",
        "frontend",
        "--target",
        "openstack",
        "--format",
        "json",
    ]));
    assert!(out.contains("no openstack catalog"), "{out}");

    // The plan is persisted and audited.
    let out = run_ok_combined(orbyn(&dir).args(["audit", "--format", "csv"]));
    assert!(out.contains("plan.create"), "{out}");

    // Unknown applications and missing arguments fail cleanly.
    let out = run_fail(orbyn(&dir).args(["plan", "nope"]));
    assert!(out.contains("no application matches 'nope'"), "{out}");
    let out = run_fail(orbyn(&dir).args(["plan"]));
    assert!(
        out.contains("specify an application or pass --all"),
        "{out}"
    );
}

#[test]
fn plan_all_covers_every_application() {
    let dir = TempDir::new("plan-all");
    seed(&dir);

    let out = run_ok(orbyn(&dir).args(["plan", "--all"]));
    assert!(out.contains("frontend"), "{out}");
    assert!(out.contains("rehost"), "{out}");

    let out = run_ok(orbyn(&dir).args(["plan", "--all", "--format", "json"]));
    assert!(out.contains("\"plans\""), "{out}");
    assert!(out.contains("\"warnings\""), "{out}");
    assert!(out.contains("\"application_name\": \"frontend\""), "{out}");
}

#[test]
fn bundle_writes_the_migration_handoff() {
    let dir = TempDir::new("bundle");
    seed(&dir);

    let mut cmd = orbyn(&dir);
    cmd.args(["bundle", "frontend"]).current_dir(dir.path());
    let out = run_ok_combined(&mut cmd);
    assert!(
        out.contains("Bundle written to frontend-migration/"),
        "{out}"
    );

    let base = dir.path().join("frontend-migration");
    for name in [
        "inventory.json",
        "inventory.csv",
        "applications.json",
        "dependencies.json",
        "dependencies.mmd",
        "assessment.json",
        "sizing.json",
        "migration-plan.json",
        "migration-plan.md",
        "manifest.json",
    ] {
        assert!(base.join(name).exists(), "missing {name}");
    }

    let manifest = std::fs::read_to_string(base.join("manifest.json")).unwrap();
    assert!(
        manifest.contains("\"readiness_version\": \"readiness/v1\""),
        "{manifest}"
    );
    assert!(manifest.contains("\"orbyn_version\""), "{manifest}");
    assert!(manifest.contains("\"files\""), "{manifest}");

    let plan = std::fs::read_to_string(base.join("migration-plan.md")).unwrap();
    assert!(plan.contains("Migration plan: frontend"), "{plan}");

    let sizing = std::fs::read_to_string(base.join("sizing.json")).unwrap();
    assert!(sizing.contains("\"asset_id\": \"10-0-0-2\""), "{sizing}");

    // Generation is read-only: no plan artifact was persisted or audited.
    let out = run_ok_combined(orbyn(&dir).args(["audit", "--format", "csv"]));
    assert!(!out.contains("plan.create"), "{out}");
}
