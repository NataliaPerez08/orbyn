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

use std::io::ErrorKind;
use std::process::ExitStatus;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use tokio::time::timeout;

/// Default cap for captured child stdout (audit OY-08): 16 MiB, matching the
/// NetBox response limit. A child that exceeds it is drained (so finite
/// output still lets the child exit) but the excess is discarded — a hostile
/// device streaming forever can no longer grow the capture without bound.
pub const MAX_STDOUT_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;

/// Default cap for captured child stderr (audit OY-08): diagnostics rarely
/// approach 1 MiB; anything larger is drained and discarded.
pub const MAX_STDERR_CAPTURE_BYTES: u64 = 1024 * 1024;

/// The captured result of a finished child process.
#[derive(Debug)]
pub struct CapturedProcess {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
    /// stdout exceeded `max_stdout_bytes` and was truncated.
    pub stdout_truncated: bool,
    /// stderr exceeded `max_stderr_bytes` and was truncated.
    pub stderr_truncated: bool,
}

/// The error [`run_captured`] returns when the lifecycle limit expires,
/// carrying the caller's `timeout_msg`.
///
/// It is a distinct type so a caller that may replay the call (the external
/// API clients, via [`crate::http`]) can recognize its own timeouts instead of
/// matching on the message; every other failure stays an ordinary
/// [`anyhow::Error`].
#[derive(Debug)]
pub struct Timeout(pub String);

impl std::fmt::Display for Timeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Timeout {}

/// True when `e` is a lifecycle timeout reported by [`run_captured`].
pub fn is_timeout(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Timeout>().is_some()
}

/// Run `child` to completion, reading stdout and stderr concurrently under a
/// single lifecycle timeout.
///
/// - `stdin_payload` is written to the child's stdin (when piped) and the
///   pipe is closed; pass `None` to close a piped stdin immediately, or when
///   stdin is null/inherited.
/// - `max_stdout_bytes` / `max_stderr_bytes` cap how much of each stream is
///   buffered. The remainder is still drained (and discarded) so a finite
///   response lets the child exit normally; an endless stream is bounded by
///   `limit`.
/// - `limit` bounds the complete lifecycle: concurrent reads plus `wait`.
/// - `timeout_msg` becomes the error when the limit expires; the child is
///   killed (SIGKILL / TerminateProcess) and reaped before returning.
pub async fn run_captured(
    mut child: Child,
    stdin_payload: Option<&str>,
    max_stdout_bytes: u64,
    max_stderr_bytes: u64,
    limit: Duration,
    timeout_msg: String,
) -> Result<CapturedProcess> {
    let mut stdin = child.stdin.take();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut stdout_truncated = false;
    let mut stderr_truncated = false;

    let work = async {
        let write_stdin = async {
            match (stdin_payload, stdin.as_mut()) {
                (Some(payload), Some(pipe)) => {
                    if let Err(e) = pipe.write_all(payload.as_bytes()).await {
                        // Child closed stdin without reading (fake curl, or a
                        // tool that never consumed `-H @-`). Not a failure.
                        if e.kind() != ErrorKind::BrokenPipe
                            && e.kind() != ErrorKind::ConnectionReset
                        {
                            return Err(anyhow!("writing to child stdin: {e}"));
                        }
                    }
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
                stdout_truncated =
                    read_capped(&mut pipe, max_stdout_bytes, &mut stdout, "stdout").await?;
            }
            Ok::<(), anyhow::Error>(())
        };

        let read_stderr = async {
            if let Some(mut pipe) = stderr_pipe.take() {
                stderr_truncated =
                    read_capped(&mut pipe, max_stderr_bytes, &mut stderr, "stderr").await?;
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
            stdout_truncated,
            stderr_truncated,
        }),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            // The read futures were dropped; kill and reap the child so no
            // process is left running after the timeout.
            let _ = child.start_kill();
            let _ = child.wait().await;
            Err(Timeout(timeout_msg).into())
        }
    }
}

/// Read up to `max` bytes from `pipe` into `buf`, then drain and discard the
/// remainder so a finite (but oversized) response still lets the child exit.
/// Returns whether the output was truncated.
async fn read_capped<R>(pipe: &mut R, max: u64, buf: &mut String, what: &str) -> Result<bool>
where
    R: AsyncRead + Unpin,
{
    let mut limited = pipe.take(max + 1);
    limited
        .read_to_string(buf)
        .await
        .map_err(|e| anyhow!("reading child {what}: {e}"))?;
    let truncated = buf.len() as u64 > max;
    if truncated {
        let rest = limited.into_inner();
        let mut discard = [0u8; 8192];
        loop {
            match rest.read(&mut discard).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(e) => return Err(anyhow!("draining child {what}: {e}")),
            }
        }
    }
    Ok(truncated)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;
    #[cfg(unix)]
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
            MAX_STDOUT_CAPTURE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
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
            MAX_STDOUT_CAPTURE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
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
            MAX_STDOUT_CAPTURE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
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
    async fn stdin_write_survives_child_that_ignores_stdin() {
        let dir = temp_dir("stdin-epipe");
        let path = script(&dir, "ignore.sh", "echo ok; exit 0");
        // Larger than a typical 64 KiB pipe buffer so write_all hits EPIPE
        // after the child exits without reading.
        let payload = "x".repeat(256 * 1024);

        let captured = run_captured(
            spawn(&path, std::process::Stdio::piped()),
            Some(&payload),
            MAX_STDOUT_CAPTURE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
            Duration::from_secs(15),
            "child timed out".to_string(),
        )
        .await
        .expect("EPIPE on unused stdin is not a failure");
        assert!(captured.status.success());
        assert_eq!(captured.stdout.trim(), "ok");
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
            MAX_STDOUT_CAPTURE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
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
            10,
            MAX_STDERR_CAPTURE_BYTES,
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
        assert!(captured.stdout_truncated, "truncation must be reported");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stderr_cap_buffers_max_plus_one_and_drains_the_rest() {
        let dir = temp_dir("stderr-cap");
        let path = script(
            &dir,
            "big-err.sh",
            r#"for i in $(seq 1 20000); do echo "err err err err err err err err" >&2; done
echo done"#,
        );

        let captured = run_captured(
            spawn(&path, std::process::Stdio::null()),
            None,
            MAX_STDOUT_CAPTURE_BYTES,
            1024,
            Duration::from_secs(15),
            "child timed out".to_string(),
        )
        .await
        .expect("oversized but finite stderr still completes");
        assert!(captured.status.success());
        assert_eq!(
            captured.stderr.len(),
            1025,
            "at most max+1 bytes are buffered"
        );
        assert!(captured.stderr_truncated, "truncation must be reported");
        assert!(!captured.stdout_truncated);
        assert_eq!(captured.stdout.trim(), "done");
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
            MAX_STDOUT_CAPTURE_BYTES,
            MAX_STDERR_CAPTURE_BYTES,
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
