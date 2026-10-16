//! End-to-end tests for the local profiler agent (`orbyn agent`): the real
//! binary against a throwaway SQLite database, sampling this host's /proc.
//! Unix-only (the e2e harness is shell-script based); unit tests cover the
//! parsers on all platforms.

#![cfg(unix)]

mod common;

use common::{run_ok, TempDir};
use std::process::Command;

fn agent_run(dir: &TempDir, args: &[&str]) -> Command {
    let mut cmd = common::orbyn(dir);
    cmd.arg("agent").arg("run");
    for arg in args {
        cmd.arg(arg);
    }
    cmd
}

#[test]
fn once_samples_are_append_only_across_restarts() {
    let dir = TempDir::new("agent-once");

    // First run: creates the asset row and one sample.
    run_ok(&mut agent_run(&dir, &["--once"]));
    let assets = run_ok(
        common::orbyn(&dir)
            .arg("assets")
            .arg("--format")
            .arg("json"),
    );
    assert!(!assets.trim().is_empty(), "agent must ensure its asset row");

    // Second run (a "restart"): appends, never replaces.
    run_ok(&mut agent_run(&dir, &["--once"]));

    let report = run_ok(
        common::orbyn(&dir)
            .arg("agent")
            .arg("report")
            .arg("--format")
            .arg("json"),
    );
    assert!(report.contains("\"sample_count\": 2"), "report: {report}");
    assert!(report.contains("\"coverage\""), "report: {report}");
    assert!(report.contains("\"largest_gap_secs\""), "report: {report}");
}

#[test]
fn duration_run_exits_cleanly_and_persists() {
    let dir = TempDir::new("agent-duration");
    let output = agent_run(&dir, &["--duration-secs", "1", "--interval-secs", "1"])
        .output()
        .expect("run command");
    assert!(output.status.success(), "duration run must exit cleanly");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("persisted"),
        "run must report its samples: {stderr}"
    );
}

#[test]
fn html_report_renders_window_and_coverage() {
    let dir = TempDir::new("agent-html");
    run_ok(&mut agent_run(&dir, &["--once"]));
    run_ok(&mut agent_run(&dir, &["--once"]));
    let html = run_ok(
        common::orbyn(&dir)
            .arg("agent")
            .arg("report")
            .arg("--format")
            .arg("html"),
    );
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("Utilization window"));
    assert!(html.contains("Coverage"));
}

#[test]
fn invalid_arguments_are_rejected() {
    let dir = TempDir::new("agent-bad-args");
    let mut zero_interval = agent_run(&dir, &["--once", "--interval-secs", "0"]);
    let output = zero_interval.output().expect("run command");
    assert!(!output.status.success(), "zero interval must fail");
    let mut zero_retention = agent_run(&dir, &["--once", "--retention-hours", "0"]);
    let output = zero_retention.output().expect("run command");
    assert!(!output.status.success(), "zero retention must fail");
}

#[test]
fn facts_interval_zero_disables_facts_but_samples_still_flow() {
    let dir = TempDir::new("agent-nofacts");
    run_ok(&mut agent_run(
        &dir,
        &["--once", "--facts-interval-secs", "0"],
    ));
    let report = run_ok(
        common::orbyn(&dir)
            .arg("agent")
            .arg("report")
            .arg("--format")
            .arg("json"),
    );
    assert!(report.contains("\"sample_count\": 1"), "report: {report}");
}
