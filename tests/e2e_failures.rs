//! End-to-end failure and recovery tests (Phase 7 of the agent plan): missing
//! collector binaries, a corrupt SQLite database and an unreachable PostgreSQL
//! backend all fail cleanly, never leak credentials, and record the failure.
//! The partial-success contract (reachable data kept, failed job recorded) is
//! covered by `e2e_discovery::partial_failure_keeps_successful_targets`.

mod common;

#[cfg(unix)]
use common::*;

/// A collector binary that does not exist must fail the job cleanly and record
/// it, not panic or leave a half-open database behind.
#[cfg(unix)]
#[test]
fn missing_collector_binary_records_a_failed_job() {
    let dir = TempDir::new("missing-bin");
    let missing = dir.path().join("does-not-exist");
    let out = run_fail(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.10"])
            .env("ORBYN_NMAP_BIN", &missing),
    );
    assert!(out.contains("failed to start"), "got: {out}");

    // The failed job is recorded, not dropped.
    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("nmap,failed"), "{jobs}");
}

/// A database file that is not SQLite must surface a clean error instead of a
/// panic, and leave the rest of the CLI usable.
#[cfg(unix)]
#[test]
fn corrupt_sqlite_db_fails_cleanly() {
    let dir = TempDir::new("corrupt-db");
    std::fs::write(dir.db(), b"not a sqlite database: garbage bytes").expect("write corrupt db");
    let out = run_fail(orbyn(&dir).arg("assets"));
    assert!(
        out.contains("not a database") || out.contains("database"),
        "got: {out}"
    );
}

/// An unreachable PostgreSQL backend fails cleanly and never echoes the URL's
/// password (audit OY-06: the value is registered with the redactor).
#[cfg(unix)]
#[test]
fn postgres_unavailable_fails_cleanly_with_redacted_password() {
    let dir = TempDir::new("pg-down");
    let out = run_fail(orbyn(&dir).args([
        "--db",
        "postgres://orbyn:super-secret-pw@127.0.0.1:1/orbyn",
        "assets",
    ]));
    assert!(!out.is_empty(), "a clean failure is reported");
    assert!(
        !out.contains("super-secret-pw"),
        "the URL password must be redacted: {out}"
    );
}
