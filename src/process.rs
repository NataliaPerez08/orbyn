//! Bounded subprocess execution shared by collectors and integrations.
//!
//! Every external tool (`nmap`, `ssh`, `snmpwalk`, `curl`) runs with piped
//! stdout/stderr. Reading one pipe to completion before the other can
//! deadlock: a child that fills the unread pipe's kernel buffer blocks
//! forever, so the reader never sees EOF and the process timeout is never
//! reached. This module reads both streams (and writes the optional stdin
//! payload) concurrently, applies one timeout to the complete process
//! lifecycle and kills the child when the limit expires.
//!
//! Callers spawn the child themselves — keeping their tailored spawn error
//! context — and should set `.kill_on_drop(true)` so an aborted Orbyn run
//! does not leave the child running.

use std::process::ExitStatus;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use tokio::time::timeout;

/// The captured result of a finished child process.
#[derive(Debug)]
pub struct CapturedProcess {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Run `child` to completion, reading stdout and stderr concurrently under a
/// single lifecycle timeout.
///
/// - `stdin_payload` is written to the child's stdin (when piped) and the
///   pipe is closed; pass `None` to close a piped stdin immediately, or when
///   stdin is null/inherited.
/// - `max_stdout_bytes` caps how much stdout is buffered. The remainder is
///   still drained (and discarded) so a finite response lets the child exit
///   normally; an endless stream is bounded by `limit`.
/// - `limit` bounds the complete lifecycle: concurrent reads plus `wait`.
/// - `timeout_msg` becomes the error when the limit expires; the child is
///   killed (SIGKILL / TerminateProcess) and reaped before returning.
pub async fn run_captured(
    mut child: Child,
    stdin_payload: Option<&str>,
    max_stdout_bytes: Option<u64>,
    limit: Duration,
    timeout_msg: String,
) -> Result<CapturedProcess> {
    let mut stdin = child.stdin.take();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();

    let mut stdout = String::new();
    let mut stderr = String::new();

    let work = async {
        let write_stdin = async {
            match (stdin_payload, stdin.as_mut()) {
                (Some(payload), Some(pipe)) => {
                    pipe.write_all(payload.as_bytes())
                        .await
                        .map_err(|e| anyhow!("writing to child stdin: {e}"))?;
                    let _ = pipe.shutdown().await;
                    // `shutdown` flushes but does not close a tokio child
                    // stdin pipe; drop the handle so the child sees EOF.
                    stdin.take();
                }
                (None, _) => {
                    // Close a piped stdin so the child sees EOF instead of
                    // waiting for input that will never arrive.
                    stdin.take();
                }
                (Some(_), None) => {}
            }
            Ok::<(), anyhow::Error>(())
        };

        let read_stdout = async {
            if let Some(mut pipe) = stdout_pipe.take() {
                match max_stdout_bytes {
                    Some(max) => {
                        let mut limited = pipe.take(max + 1);
                        limited
                            .read_to_string(&mut stdout)
                            .await
                            .map_err(|e| anyhow!("reading child stdout: {e}"))?;
                        // Discard the remainder so a child with a finite
                        // (but oversized) response can still exit; a child
                        // that streams forever is bounded by `limit`.
                        let mut rest = limited.into_inner();
                        let mut discard = [0u8; 8192];
                        loop {
                            match rest.read(&mut discard).await {
                                Ok(0) => break,
                                Ok(_) => continue,
                                Err(e) => return Err(anyhow!("reading child stdout: {e}")),
                            }
                        }
                    }
                    None => {
                        pipe.read_to_string(&mut stdout)
                            .await
                            .map_err(|e| anyhow!("reading child stdout: {e}"))?;
                    }
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        let read_stderr = async {
            if let Some(mut pipe) = stderr_pipe.take() {
                pipe.read_to_string(&mut stderr)
                    .await
                    .map_err(|e| anyhow!("reading child stderr: {e}"))?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let (stdin_res, stdout_res, stderr_res) =
            tokio::join!(write_stdin, read_stdout, read_stderr);
        stdin_res?;
        stdout_res?;
        stderr_res?;
        child
            .wait()
            .await
            .map_err(|e| anyhow!("waiting for child: {e}"))
    };

    match timeout(limit, work).await {
        Ok(Ok(status)) => Ok(CapturedProcess {
            status,
            stdout,
            stderr,
        }),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            // The read futures were dropped; kill and reap the child so no
            // process is left running after the timeout.
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err(anyhow!(timeout_msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[cfg(unix)]
    fn script(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(name);
        std::fs::write(&path, format!("#!/usr/bin/env bash\n{body}")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("orbyn-process-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test temp dir");
        dir
    }

    #[cfg(unix)]
    fn spawn(path: &std::path::Path, stdin: std::process::Stdio) -> Child {
        let mut cmd = tokio::process::Command::new(path);
        cmd.stdin(stdin)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        // A freshly written script can transiently fail to exec with
        // ETXTBSY when many tests write+spawn at once (a known Linux
        // quirk); retry briefly instead of flaking.
        for _ in 0..10 {
            match cmd.spawn() {
                Ok(child) => return child,
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("spawn test child: {e}"),
            }
        }
        cmd.spawn().expect("spawn test child")
    }

    // The exact deadlock regression: a child that floods stderr far beyond
    // the pipe buffer and then hangs must produce a timeout error, not block
    // forever on the unread pipe.
    #[cfg(unix)]
    #[tokio::test]
    async fn stderr_flood_then_hang_times_out_instead_of_deadlocking() {
        let dir = temp_dir("flood-hang");
        let path = script(
            &dir,
            "flood-hang.sh",
            r#"for i in $(seq 1 20000); do echo "noise noise noise noise noise noise noise" >&2; done
sleep 30"#,
        );

        let started = Instant::now();
        let result = run_captured(
            spawn(&path, std::process::Stdio::null()),
            None,
            None,
            Duration::from_secs(2),
            "child timed out".to_string(),
        )
        .await;
        assert!(result.is_err(), "must time out");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "must not deadlock on the full stderr pipe"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Both pipes carry more than the pipe buffer: sequential reads would
    // deadlock, concurrent reads capture everything.
    #[cfg(unix)]
    #[tokio::test]
    async fn captures_large_stdout_and_stderr_concurrently() {
        let dir = temp_dir("both-large");
        let path = script(
            &dir,
            "both-large.sh",
            r#"for i in $(seq 1 20000); do echo "out out out out out out out out"; done
for i in $(seq 1 20000); do echo "err err err err err err err err" >&2; done
echo marker"#,
        );

        let captured = run_captured(
            spawn(&path, std::process::Stdio::null()),
            None,
            None,
            Duration::from_secs(30),
            "child timed out".to_string(),
        )
        .await
        .expect("capture both pipes");
        assert!(captured.status.success());
        assert!(captured.stdout.contains("marker"));
        assert!(
            captured.stdout.len() > 100_000,
            "stdout fully drained: {} bytes",
            captured.stdout.len()
        );
        assert!(
            captured.stderr.len() > 100_000,
            "stderr fully drained: {} bytes",
            captured.stderr.len()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdin_payload_is_delivered_and_closed() {
        let dir = temp_dir("stdin");
        let out_file = dir.join("stdin-received.txt");
        let path = script(
            &dir,
            "reader.sh",
            &format!("cat > '{}'", out_file.display()),
        );

        let captured = run_captured(
            spawn(&path, std::process::Stdio::piped()),
            Some("hello stdin\n"),
            None,
            Duration::from_secs(15),
            "child timed out".to_string(),
        )
        .await
        .expect("child completes once stdin closes");
        assert!(captured.status.success());
        assert_eq!(
            std::fs::read_to_string(&out_file).unwrap(),
            "hello stdin\n",
            "payload must reach the child exactly once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn piped_stdin_without_payload_closes_immediately() {
        let dir = temp_dir("stdin-closed");
        // `cat` only exits once stdin reaches EOF: a piped stdin that is
        // not closed would hang into the timeout instead.
        let path = script(&dir, "eof.sh", "cat > /dev/null");

        let captured = run_captured(
            spawn(&path, std::process::Stdio::piped()),
            None,
            None,
            Duration::from_secs(15),
            "child timed out".to_string(),
        )
        .await
        .expect("child must see EOF on stdin");
        assert!(captured.status.success());
        assert!(
            captured.stdout.is_empty(),
            "nothing was written: {:?}",
            captured
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdout_cap_buffers_max_plus_one_and_drains_the_rest() {
        let dir = temp_dir("cap");
        let path = script(&dir, "big.sh", r#"printf 'x%.0s' $(seq 1 100000)"#);

        let captured = run_captured(
            spawn(&path, std::process::Stdio::null()),
            None,
            Some(10),
            Duration::from_secs(15),
            "child timed out".to_string(),
        )
        .await
        .expect("oversized but finite output still completes");
        assert!(captured.status.success());
        assert_eq!(
            captured.stdout.len(),
            11,
            "at most max+1 bytes are buffered"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exit_status_and_stderr_are_surfaced() {
        let dir = temp_dir("exit");
        let path = script(&dir, "fail.sh", "echo boom >&2; exit 7");

        let captured = run_captured(
            spawn(&path, std::process::Stdio::null()),
            None,
            None,
            Duration::from_secs(15),
            "child timed out".to_string(),
        )
        .await
        .expect("capture failed child");
        assert_eq!(captured.status.code(), Some(7));
        assert_eq!(captured.stderr.trim(), "boom");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
