//! End-to-end dependency tests: graph rendering, Mermaid export, manual
//! curation (add/confirm/remove) and the connections evidence view.

mod common;

#[cfg(unix)]
use common::*;

/// Seed two assets and an ssh-discovered host with active connections so
/// dependency edges exist.
#[cfg(unix)]
fn seed_with_edges(dir: &TempDir) {
    import_json(dir, INVENTORY_JSON);
    let bin = fake_bin(dir, "ssh", FAKE_SSH_LINUX_SCRIPT);
    run_ok(
        orbyn(dir)
            .args(["discover", "--target", "10.0.0.5", "--collector", "ssh"])
            .env("ORBYN_SSH_BIN", &bin),
    );
}

#[cfg(unix)]
#[test]
fn deps_lifecycle_add_confirm_remove() {
    let dir = TempDir::new("deps-lifecycle");
    seed_with_edges(&dir);

    // confirm an observed edge (web -> db tcp/5432)
    let out =
        run_ok_combined(orbyn(&dir).args(["deps", "confirm", "web-01", "db-01", "--port", "5432"]));
    assert!(out.contains("Confirmed 1 edge"));

    // now confirmed: confidence 100%
    let graph = run_ok(orbyn(&dir).args(["graph", "--format", "csv"]));
    let line = graph
        .lines()
        .find(|l| l.contains("10-0-0-5,10-0-0-2,tcp,5432"))
        .expect("edge present");
    assert!(line.contains("1,true"), "confirmed edge: {line}");

    // add a manual edge
    run_ok(orbyn(&dir).args(["deps", "add", "cache-01", "db-01", "--port", "5432"]));

    // remove it again
    let out = run_ok_combined(orbyn(&dir).args(["deps", "remove", "cache-01", "db-01"]));
    assert!(out.contains("Removed 1 edge"));

    // confirming a non-existent pair errors
    let fail = run_fail(orbyn(&dir).args(["deps", "confirm", "cache-01", "db-01"]));
    assert!(fail.contains("no observed dependency"), "got: {fail}");
}

#[cfg(unix)]
#[test]
fn graph_mermaid_renders_edges_with_arrows() {
    let dir = TempDir::new("mermaid");
    seed_with_edges(&dir);

    let out = run_ok(orbyn(&dir).args(["graph", "--mermaid"]));
    assert!(out.starts_with("graph TD"));
    assert!(out.contains("web-01 (10.0.0.5)"));
    assert!(out.contains("db-01 (10.0.0.2)"));
    // unconfirmed edges are dotted
    assert!(out.contains("-. tcp/5432"), "dotted arrow expected: {out}");
    // node ids are sanitized (dots -> underscores)
    assert!(out.contains("10_0_0_5"));
    assert!(!out.contains("10-0-0-5"));

    // --mermaid conflicts with --format
    let fail = run_fail(orbyn(&dir).args(["graph", "--mermaid", "--format", "json"]));
    assert!(fail.contains("cannot be used"), "got: {fail}");
}

#[cfg(unix)]
#[test]
fn graph_asset_filter_scopes_edges() {
    let dir = TempDir::new("graph-asset");
    seed_with_edges(&dir);

    let all = run_ok(orbyn(&dir).args(["graph", "--format", "csv"]));
    assert!(all.contains("10-0-0-9"), "both edges present");

    // scoped to db-01: only the web->db edge remains
    let scoped = run_ok(orbyn(&dir).args(["graph", "--asset", "db-01", "--format", "csv"]));
    assert!(scoped.contains("10-0-0-5,10-0-0-2"));
    assert!(
        !scoped.contains("10-0-0-9"),
        "unrelated edge filtered: {scoped}"
    );
}

#[cfg(unix)]
#[test]
fn connections_command_shows_evidence() {
    let dir = TempDir::new("connections");
    seed_with_edges(&dir);

    let out = run_ok(orbyn(&dir).args(["connections", "10.0.0.5", "--format", "csv"]));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines[0],
        "asset_id,proto,local_ip,local_port,remote_ip,remote_port,process"
    );
    assert!(
        out.contains("10.0.0.2,5432,postgres"),
        "process name shown: {out}"
    );
    assert!(
        out.contains("203.0.113.9,443"),
        "external connection kept as evidence: {out}"
    );
    assert!(!out.contains("127.0.0.1"));
}
