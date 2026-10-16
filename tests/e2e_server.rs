//! End-to-end tests for the v1.6 ingest server: the real binary pair
//! (`orbyn server` + `orbyn agent sync`) over loopback, with the real
//! curl client. Unix-only (the e2e harness is shell-script based); the
//! server's HTTP handling is covered cross-platform by unit tests.

#![cfg(unix)]

mod common;

use common::{run_ok, TempDir};
use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// `orbyn server run` as a background child; killed on drop.
struct ServerProc {
    child: Child,
}

impl ServerProc {
    fn start(dir: &TempDir, port: u16) -> Self {
        let mut cmd = common::orbyn(dir);
        cmd.arg("server")
            .arg("run")
            .arg("--bind")
            .arg(format!("127.0.0.1:{port}"));
        let child = cmd
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("start ingest server");
        let proc = Self { child };
        proc.wait_ready(port);
        proc
    }

    fn wait_ready(&self, port: u16) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpListener::bind(("127.0.0.1", port)).is_err() {
                return; // port taken: the server is listening
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("ingest server never became ready on {port}");
    }
}

impl Drop for ServerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A free port (bind :0, read it, drop — small race, fine for tests).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

fn enroll(dir: &TempDir, asset_ip: &str) -> String {
    let mut cmd = common::orbyn(dir);
    cmd.arg("server")
        .arg("enroll")
        .arg("--asset-ip")
        .arg(asset_ip);
    run_ok(&mut cmd).trim().to_string()
}

/// Run a command, assert success, return (stdout, stderr).
fn run_both(cmd: &mut Command) -> (String, String) {
    let output = cmd.output().expect("run command");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn enroll_sync_and_revoke_roundtrip() {
    let server_dir = TempDir::new("server");
    let agent_dir = TempDir::new("agent-sync");
    let port = free_port();
    let _server = ServerProc::start(&server_dir, port);

    // Enroll the agent host; the token is printed exactly once.
    let token = enroll(&server_dir, "127.0.0.1");
    assert_eq!(
        token.len(),
        32,
        "token must be a simple UUID: got '{token}'"
    );

    // The agent host samples into its own database...
    run_ok(
        common::orbyn(&agent_dir)
            .arg("agent")
            .arg("run")
            .arg("--once")
            .arg("--asset-ip")
            .arg("127.0.0.1"),
    );
    // ...and syncs it to the server.
    let (sync_out, sync_err) = run_both(
        common::orbyn(&agent_dir)
            .arg("agent")
            .arg("sync")
            .arg("--url")
            .arg(format!("http://127.0.0.1:{port}/v1/ingest"))
            .arg("--token")
            .arg(&token)
            .arg("--asset-ip")
            .arg("127.0.0.1"),
    );
    let sync_all = format!("{sync_out}{sync_err}");
    assert!(
        sync_all.contains("Synced 1 sample"),
        "sync output: {sync_all}"
    );

    // The server database now holds the agent's asset and sample. One
    // sample is below the stats minimum, so assert through the report's
    // coverage (which counts samples directly).
    let assets = run_ok(
        common::orbyn(&server_dir)
            .arg("assets")
            .arg("--format")
            .arg("json"),
    );
    assert!(
        assets.contains("127.0.0.1"),
        "server must know the agent asset: {assets}"
    );
    let report = run_ok(
        common::orbyn(&server_dir)
            .arg("agent")
            .arg("report")
            .arg("--asset-ip")
            .arg("127.0.0.1")
            .arg("--format")
            .arg("json"),
    );
    let parsed: serde_json::Value = serde_json::from_str(&report).expect("report json");
    assert_eq!(
        parsed["coverage"]["sample_count"], 1,
        "server must hold the synced sample: {report}"
    );

    // Revocation: the same token is refused afterwards, and the agent
    // keeps its local buffer.
    run_ok(
        common::orbyn(&server_dir)
            .arg("server")
            .arg("revoke")
            .arg("127-0-0-1"),
    );
    let (list_out, _list_err) = run_both(common::orbyn(&server_dir).arg("server").arg("list"));
    assert!(
        list_out.contains("true"),
        "list must show revocation: {list_out}"
    );

    // The agent keeps sampling after revocation; the next sync must be
    // refused (there is something to send, so the token is exercised).
    run_ok(
        common::orbyn(&agent_dir)
            .arg("agent")
            .arg("run")
            .arg("--once")
            .arg("--asset-ip")
            .arg("127.0.0.1"),
    );
    let mut binding = common::orbyn(&agent_dir);
    let cmd = binding
        .arg("agent")
        .arg("sync")
        .arg("--url")
        .arg(format!("http://127.0.0.1:{port}/v1/ingest"))
        .arg("--token")
        .arg(&token)
        .arg("--asset-ip")
        .arg("127.0.0.1");
    let output = cmd.output().expect("run revoked sync");
    assert!(
        !output.status.success(),
        "revoked sync must fail, stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("rejected"),
        "failure must name the rejection"
    );
}

#[test]
fn sync_is_idempotent_across_runs() {
    let server_dir = TempDir::new("server-idem");
    let agent_dir = TempDir::new("agent-sync-idem");
    let port = free_port();
    let _server = ServerProc::start(&server_dir, port);
    let token = enroll(&server_dir, "127.0.0.1");

    run_ok(
        common::orbyn(&agent_dir)
            .arg("agent")
            .arg("run")
            .arg("--once")
            .arg("--asset-ip")
            .arg("127.0.0.1"),
    );
    let url = format!("http://127.0.0.1:{port}/v1/ingest");
    let (first_out, first_err) = run_both(
        common::orbyn(&agent_dir)
            .arg("agent")
            .arg("sync")
            .arg("--url")
            .arg(&url)
            .arg("--token")
            .arg(&token)
            .arg("--asset-ip")
            .arg("127.0.0.1"),
    );
    let first_all = format!("{first_out}{first_err}");
    assert!(
        first_all.contains("Synced 1 sample"),
        "first sync: {first_all}"
    );

    // Second sync with no new samples: drains nothing, no duplicates.
    let (second_out, second_err) = run_both(
        common::orbyn(&agent_dir)
            .arg("agent")
            .arg("sync")
            .arg("--url")
            .arg(&url)
            .arg("--token")
            .arg(&token)
            .arg("--asset-ip")
            .arg("127.0.0.1"),
    );
    let second_all = format!("{second_out}{second_err}");
    assert!(
        second_all.contains("Synced 0 sample"),
        "second sync: {second_all}"
    );
    let report = run_ok(
        common::orbyn(&server_dir)
            .arg("agent")
            .arg("report")
            .arg("--asset-ip")
            .arg("127.0.0.1")
            .arg("--format")
            .arg("json"),
    );
    let parsed: serde_json::Value = serde_json::from_str(&report).expect("report json");
    assert_eq!(
        parsed["coverage"]["sample_count"], 1,
        "re-sync must not duplicate the sample: {report}"
    );
}

/// `server list` on a fresh database is not an error.
#[test]
fn server_list_empty_is_ok() {
    let dir = TempDir::new("server-empty");
    let (out, err) = run_both(common::orbyn(&dir).arg("server").arg("list"));
    let all = format!("{out}{err}");
    assert!(all.contains("No agents enrolled"), "unexpected: {all}");
}
