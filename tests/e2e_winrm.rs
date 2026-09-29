//! End-to-end tests for the native WinRM transport: a fake `curl` plays the
//! WS-Man endpoint (create/command/receive/delete) so the full SOAP flow,
//! credential handling and observation persistence run without a network.

mod common;

#[cfg(unix)]
use common::*;

/// Probe output the fake endpoint returns as the command's stdout stream
/// (same shape as the PowerShell-over-SSH fixture).
#[cfg(unix)]
const WINRM_PROBE_OUTPUT: &str = "###os\n\
\"Caption\",\"Version\",\"BuildNumber\",\"CSName\"\n\
\"Microsoft Windows Server 2022 Standard\",\"10.0\",\"20348\",\"WIN-APP01\"\n\
###cpu\n\
\"Name\",\"NumberOfCores\",\"NumberOfLogicalProcessors\"\n\
\"Intel(R) Xeon(R) Silver 4310 CPU @ 2.20GHz\",\"12\",\"24\"\n\
###ram\n\
17179869184\n\
###disk\n\
\"DeviceID\",\"FileSystem\",\"VolumeName\",\"Size\",\"FreeSpace\"\n\
\"C:\",\"NTFS\",\"System\",\"107374182400\",\"53687091200\"\n\
\"D:\",\"NTFS\",\"Data\",\"214748364800\",\"107374182400\"\n\
###svc\n\
\"Name\",\"DisplayName\"\n\
\"W3SVC\",\"World Wide Web Publishing Service\"\n\
\"MSSQLSERVER\",\"SQL Server (MSSQLSERVER)\"\n\
###conn\n\
\"LocalAddress\",\"LocalPort\",\"RemoteAddress\",\"RemotePort\"\n\
\"10.0.0.20\",\"49222\",\"10.0.0.5\",\"443\"\n\
\"10.0.0.20\",\"49223\",\"10.0.0.9\",\"5432\"\n\
###virt\n\
\"Manufacturer\",\"Model\"\n\
\"Microsoft Corporation\",\"Virtual Machine\"\n\
###metric\n\
45.5|16777216|8388608|512\n\
12.0|16777216|12582912|512\n";

/// A fake `curl` implementing a minimal WS-Man endpoint: it dispatches on
/// the SOAP Action inside the `--data-binary` envelope and logs argv, the
/// stdin config and the observed actions for the secret-handling asserts.
#[cfg(unix)]
const FAKE_WINRM_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
log="${ORBYN_WINRM_LOG}"
envelope=""
prev=""
for a in "$@"; do
  if [[ "$prev" == "--data-binary" ]]; then envelope="$a"; fi
  prev="$a"
done
action=$(sed -n 's/.*<a:Action[^>]*>\([^<]*\)<\/a:Action>.*/\1/p' <<< "$envelope")
if [[ -n "$log" ]]; then
  printf '%s\n' "$@" >> "$log.argv"
  cat >> "$log.stdin"
  printf '%s\n' "$action" >> "$log.actions"
fi
case "$action" in
  *transfer/Create)
    printf '%s' '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><rsp:Shell xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:wsmid="http://schemas.dmtf.org/wbem/cim/1/cim-base"><wsmid:Selector Name="ShellId">SHELL-1A2B3C4D</wsmid:Selector><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell></s:Body></s:Envelope>'
    ;;
  *shell/Command)
    printf '%s' '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><rsp:CommandResponse xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><rsp:CommandId>CMD-5678</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>'
    ;;
  *shell/Receive)
    stream=$(printf '%s' "$ORBYN_WINRM_PROBE_OUT" | base64 | tr -d '\n')
    printf '%s' "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body><rsp:ReceiveResponse xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\"><rsp:Stream Name=\"stdout\" CommandId=\"CMD-5678\">$stream</rsp:Stream><rsp:CommandState CommandId=\"CMD-5678\" State=\"rsp:Done\"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>"
    ;;
  *transfer/Delete)
    : # success with an empty body
    ;;
esac
printf '200'
"#;

/// A fake `curl` whose endpoint rejects the credentials (HTTP 401).
#[cfg(unix)]
const AUTH_FAIL_CURL_SCRIPT: &str = r#"#!/usr/bin/env bash
log="${ORBYN_WINRM_LOG}"
if [[ -n "$log" ]]; then
  printf '%s\n' "$@" >> "$log.argv"
  cat >> "$log.stdin"
fi
printf '401'
"#;

#[cfg(unix)]
fn winrm_env(dir: &TempDir, curl: &std::path::Path) -> std::process::Command {
    let mut cmd = orbyn(dir);
    cmd.env("ORBYN_CURL_BIN", curl)
        .env("ORBYN_WINRM_PASSWORD", "topsecret")
        .env("ORBYN_WINRM_PROBE_OUT", WINRM_PROBE_OUTPUT);
    cmd
}

#[cfg(unix)]
#[test]
fn winrm_discovery_collects_windows_host_over_wsman() {
    let dir = TempDir::new("winrm");
    let log = dir.path().join("winrm-curl");
    let curl = fake_bin(&dir, "curl", FAKE_WINRM_CURL_SCRIPT);

    let out = run_ok_combined(
        winrm_env(&dir, &curl)
            .args([
                "discover",
                "--target",
                "10.0.0.20",
                "--collector",
                "winrm",
                "--user",
                "Administrator",
                "--format",
                "csv",
            ])
            .env("ORBYN_WINRM_LOG", log.to_str().unwrap()),
    );
    assert!(out.contains("1 assets"), "{out}");

    // The Windows facts parsed out of the WS-Man stream are persisted.
    let assets = run_ok(orbyn(&dir).args(["assets", "--format", "csv"]));
    assert!(assets.contains("WIN-APP01"), "{assets}");
    assert!(assets.contains("Microsoft Windows Server 2022"), "{assets}");

    let capacity = run_ok(orbyn(&dir).args(["capacity", "10.0.0.20"]));
    assert!(
        capacity.contains("Intel(R) Xeon(R) Silver 4310"),
        "{capacity}"
    );
    assert!(capacity.contains("16384"), "{capacity}");
    assert!(
        capacity.contains("Hypervisor : hyperv"),
        "virtualization metadata: {capacity}"
    );

    let host_services = run_ok(orbyn(&dir).args(["host-services", "10.0.0.20", "--format", "csv"]));
    assert!(host_services.contains("W3SVC"), "{host_services}");

    // The job history records the winrm collector.
    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("winrm"), "{jobs}");

    // The full WS-Man lifecycle ran: create, command, receive, delete.
    let actions = std::fs::read_to_string(log.with_extension("actions")).expect("actions log");
    let lines: Vec<&str> = actions.lines().collect();
    assert_eq!(lines.len(), 4, "{actions}");
    assert!(lines[0].contains("transfer/Create"), "{actions}");
    assert!(lines[1].contains("shell/Command"), "{actions}");
    assert!(lines[2].contains("shell/Receive"), "{actions}");
    assert!(lines[3].contains("transfer/Delete"), "{actions}");

    // The password reached curl only through the stdin config, never argv.
    let argv = std::fs::read_to_string(log.with_extension("argv")).expect("argv log");
    assert!(
        !argv.contains("topsecret"),
        "password leaked to argv: {argv}"
    );
    assert!(
        argv.contains("https://10.0.0.20:5986/wsman"),
        "expected the HTTPS endpoint in argv: {argv}"
    );
    assert!(argv.contains("-K"), "config must come from stdin: {argv}");
    assert!(
        argv.contains("-NoProfile -EncodedCommand "),
        "the probe must travel encoded: {argv}"
    );
    assert!(
        !argv.contains("Get-CimInstance"),
        "raw probe text must not appear in argv: {argv}"
    );

    let stdin_log = std::fs::read_to_string(log.with_extension("stdin")).expect("stdin log");
    assert!(
        stdin_log.contains("user = \"Administrator:topsecret\""),
        "credentials must be delivered through the stdin config: {stdin_log}"
    );
}

#[cfg(unix)]
#[test]
fn winrm_auth_failure_fails_the_job_without_leaking_the_password() {
    let dir = TempDir::new("winrm-auth-fail");
    let log = dir.path().join("winrm-curl");
    let curl = fake_bin(&dir, "curl", AUTH_FAIL_CURL_SCRIPT);

    let out = run_fail(
        winrm_env(&dir, &curl)
            .args([
                "discover",
                "--target",
                "10.0.0.20",
                "--collector",
                "winrm",
                "--user",
                "Administrator",
            ])
            .env("ORBYN_WINRM_LOG", log.to_str().unwrap()),
    );
    assert!(out.contains("WinRM authentication failed"), "{out}");
    assert!(out.contains("401"), "{out}");
    assert!(!out.contains("topsecret"), "password leaked: {out}");

    // The failed job is still recorded for review.
    let jobs = run_ok(orbyn(&dir).args(["jobs", "--format", "csv"]));
    assert!(jobs.contains("failed"), "{jobs}");
}

#[cfg(unix)]
#[test]
fn winrm_requires_user_and_password_before_any_request() {
    let dir = TempDir::new("winrm-validation");

    // No --user: rejected before any subprocess runs.
    let out = run_fail(
        orbyn(&dir)
            .args(["discover", "--target", "10.0.0.20", "--collector", "winrm"])
            .env("ORBYN_WINRM_PASSWORD", "topsecret"),
    );
    assert!(out.contains("requires --user"), "{out}");

    // No password: rejected before any subprocess runs.
    let out = run_fail(orbyn(&dir).args([
        "discover",
        "--target",
        "10.0.0.20",
        "--collector",
        "winrm",
        "--user",
        "Administrator",
    ]));
    assert!(out.contains("requires a password"), "{out}");
    assert!(out.contains("ORBYN_WINRM_PASSWORD"), "{out}");
}

#[cfg(unix)]
#[test]
fn winrm_insecure_warns_and_reaches_curl() {
    let dir = TempDir::new("winrm-insecure");
    let log = dir.path().join("winrm-curl");
    let curl = fake_bin(&dir, "curl", FAKE_WINRM_CURL_SCRIPT);

    let out = run_ok_combined(
        winrm_env(&dir, &curl)
            .args([
                "discover",
                "--target",
                "10.0.0.20",
                "--collector",
                "winrm",
                "--user",
                "Administrator",
                "--winrm-insecure",
            ])
            .env("ORBYN_WINRM_LOG", log.to_str().unwrap()),
    );
    assert!(
        out.contains("--winrm-insecure disables TLS certificate verification"),
        "expected a prominent warning: {out}"
    );

    // The opt-out is forwarded to curl as --insecure.
    let argv = std::fs::read_to_string(log.with_extension("argv")).expect("argv log");
    assert!(argv.contains("--insecure"), "{argv}");
}
