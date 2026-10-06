//! End-to-end coverage for `orbyn applications`: inference discovery,
//! the read paths, and the manual-precedence guarantees.

mod common;

use common::{import_json, orbyn, run_fail, run_ok, run_ok_combined, TempDir};

const INVENTORY: &str = r#"{"assets":[
  {"ip":"10.0.0.2","hostname":"frontend01","device_class":"server","environment":"prod","criticality":"high"},
  {"ip":"10.0.0.3","hostname":"frontend02","device_class":"server","environment":"prod","criticality":"high"},
  {"ip":"10.0.0.4","hostname":"db01","device_class":"server","environment":"prod","criticality":"critical"}
]}"#;

/// Three assets with two manual frontend -> db edges: one inference group.
fn seed(dir: &TempDir) {
    import_json(dir, INVENTORY);
    run_ok_combined(orbyn(dir).args(["deps", "add", "10.0.0.2", "10.0.0.4", "--port", "5432"]));
    run_ok_combined(orbyn(dir).args(["deps", "add", "10.0.0.3", "10.0.0.4", "--port", "5432"]));
}

#[test]
fn applications_discover_show_explain_and_manual_precedence() {
    let dir = TempDir::new("applications");
    seed(&dir);

    // Discover infers one application of three members, named after the
    // hostname prefix majority.
    let out = run_ok_combined(orbyn(&dir).args(["applications", "discover", "--format", "json"]));
    assert!(
        out.contains("Applications: 1 discovered (1 created, 0 refreshed, 0 removed)"),
        "{out}"
    );
    assert!(out.contains("\"name\": \"frontend\""), "{out}");
    assert!(out.contains("\"source\": \"inferred\""), "{out}");
    assert!(out.contains("\"members\": 3"), "{out}");

    // Bare `orbyn applications` lists.
    let out = run_ok(orbyn(&dir).args(["applications"]));
    assert!(out.contains("frontend"), "{out}");

    // Show and explain expose members, evidence and the model version.
    let out = run_ok(orbyn(&dir).args(["applications", "show", "frontend", "--format", "json"]));
    assert!(out.contains("\"asset_id\": \"10-0-0-2\""), "{out}");
    assert!(out.contains("\"asset_id\": \"10-0-0-4\""), "{out}");
    let out = run_ok_combined(orbyn(&dir).args(["applications", "explain", "frontend"]));
    assert!(
        out.contains("Model       : application-inference/v1"),
        "{out}"
    );
    assert!(out.contains("manual dependency"), "{out}");

    // Removing a member tombstones it: re-discovery keeps the same
    // application (member-set match) and never re-adds the asset.
    run_ok_combined(orbyn(&dir).args(["applications", "remove", "frontend", "10.0.0.3"]));
    let out = run_ok_combined(orbyn(&dir).args(["applications", "discover", "--format", "json"]));
    assert!(
        out.contains("Applications: 1 discovered (0 created, 1 refreshed, 0 removed)"),
        "{out}"
    );
    assert!(out.contains("\"members\": 2"), "{out}");
    let out = run_fail(orbyn(&dir).args(["applications", "remove", "frontend", "10.0.0.3"]));
    assert!(out.contains("is not a member"), "{out}");

    // Manual applications: duplicate names are rejected, manual members
    // block inference, and unknown keys error cleanly.
    let out = run_fail(orbyn(&dir).args(["applications", "create", "frontend"]));
    assert!(out.contains("already exists"), "{out}");
    run_ok_combined(orbyn(&dir).args(["applications", "create", "payments"]));
    run_ok_combined(orbyn(&dir).args(["applications", "add", "payments", "10.0.0.3"]));
    let out = run_ok_combined(orbyn(&dir).args(["applications", "discover", "--format", "json"]));
    assert!(out.contains("\"members\": 2"), "{out}");
    let out = run_ok_combined(orbyn(&dir).args(["applications", "show", "payments"]));
    assert!(out.contains("frontend02"), "{out}");
    assert!(out.contains("manual"), "{out}");
    let out = run_fail(orbyn(&dir).args(["applications", "show", "nope"]));
    assert!(out.contains("no application matches 'nope'"), "{out}");
}

#[test]
fn graph_application_and_applications_views() {
    let dir = TempDir::new("graph-applications");
    seed(&dir);
    run_ok_combined(orbyn(&dir).args(["applications", "discover"]));

    // --application scopes the graph to edges touching the members.
    let out = run_ok(orbyn(&dir).args(["graph", "--application", "frontend", "--format", "csv"]));
    assert!(out.contains("10-0-0-2,10-0-0-4,tcp,5432"), "{out}");
    assert!(out.contains("10-0-0-3,10-0-0-4,tcp,5432"), "{out}");

    // A second application makes an edge cross a boundary.
    run_ok_combined(orbyn(&dir).args(["applications", "remove", "frontend", "10.0.0.3"]));
    run_ok_combined(orbyn(&dir).args(["applications", "create", "payments"]));
    run_ok_combined(orbyn(&dir).args(["applications", "add", "payments", "10.0.0.3"]));

    let out = run_ok(orbyn(&dir).args(["graph", "--applications", "--format", "csv"]));
    assert!(out.contains("payments,frontend,1"), "{out}");
    let out = run_ok(orbyn(&dir).args(["graph", "--applications", "--mermaid"]));
    assert!(out.starts_with("graph TD"), "{out}");
    assert!(out.contains("payments"), "{out}");

    // Unknown applications and flag conflicts fail cleanly.
    let out = run_fail(orbyn(&dir).args(["graph", "--application", "nope"]));
    assert!(out.contains("no application matches 'nope'"), "{out}");
    run_fail(orbyn(&dir).args(["graph", "--application", "frontend", "--asset", "10.0.0.2"]));
}
