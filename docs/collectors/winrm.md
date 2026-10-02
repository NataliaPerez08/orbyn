# WinRM collector

`--collector winrm` is the **native WS-Man/SOAP transport** for the Windows
collector: it opens a shell on the target, runs the same read-only PowerShell
probe, streams the result back and deletes the shell. No OpenSSH Server is
required on the target.

The SOAP envelopes are driven through the externally installed `curl`:

```text
curl -sS -w %{http_code} -H "application/soap+xml;charset=UTF-8" -K - \
     --data-binary <envelope> https://<ip>:<port>/wsman
```

The flow is `Shell Create → Command → Receive (loop) → Shell Delete` against
`http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd`. PowerShell
travels as `-NoProfile -EncodedCommand <base64(UTF-16LE)>`.

## When to use it

Windows hosts with a WinRM HTTPS listener and no SSH server — the common
enterprise default.

```bash
# password from stdin: never in argv, never in the environment of curl
orbyn discover --target 10.0.0.20 --collector winrm --user administrator \
    --winrm-password - <<< "$ORBYN_WINRM_PASSWORD"

# password from the environment instead
export ORBYN_WINRM_PASSWORD=...
orbyn discover --target 10.0.0.20 --collector winrm --user administrator

# self-signed lab certificate (prints a WARNING)
orbyn discover --target 10.0.0.20 --collector winrm --user administrator \
    --winrm-password - --winrm-insecure < pw.txt

# non-default listener port
orbyn discover --target 10.0.0.20 --collector winrm --user administrator \
    --winrm-port 5986 --winrm-password - < pw.txt
```

!!! danger "`--user` is required"
    `--collector winrm` fails fast without it:
    `--collector winrm requires --user (the Windows account, e.g. Administrator)`.

!!! warning "Single host only"
    A CIDR target is rejected: `Windows collection targets a single host;
    target must be an IP address`.

## Options

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--user <u>` | *(required)* | Windows account |
| `--winrm-password <p>` / `ORBYN_WINRM_PASSWORD` | *(required)* | `-` reads one line from stdin |
| `--winrm-port <p>` | `5986` | WinRM **HTTPS** port |
| `--winrm-insecure` | off | Skip TLS certificate verification (lab certs; warns loudly) |
| `--port <p>` | `22` | Ignored by this collector |
| `ORBYN_CURL_BIN` | `curl` | Binary path |

### Authentication

HTTP **Basic over HTTPS only**. The password reaches `curl` as a config line
`user = "<user>:<pw>"` streamed on stdin (`-K -`), so it never lands in argv,
in a file, or in curl's environment. The value is held in process memory for
the run only — Orbyn does not store credentials. Usernames or passwords
containing newlines or NUL bytes are rejected (curl config injection), and
the password is registered with the redactor before any error can print it.

## Requirements

| Side | Needs |
| --- | --- |
| Orbyn host | `curl` |
| Target | A **WinRM HTTPS listener (5986)** with **Basic authentication** enabled, PowerShell on the box |

!!! warning "Not supported today"
    NTLM/Kerberos and the plaintext HTTP listener (5985) are **not**
    implemented. Basic-over-HTTPS is the only supported combination.

## What it produces

The transport itself produces no observations — the payloads are exactly the
[Windows collector's](windows.md#what-it-produces): Asset, Capacity,
Filesystem, RunningService, Connection and MetricSample.

```bash
orbyn capacity 10.0.0.20
orbyn disks 10.0.0.20
orbyn host-services 10.0.0.20
orbyn metrics 10.0.0.20
orbyn jobs                # job history shows collector "winrm"
```

## Limits and failures

* WS-Man advertises `OperationTimeout` `PT30S` per request; the curl
  lifecycle timeout is 60 s (it must stay above the WS-Man timeout).
* At most **16 receive round trips**; beyond that:
  `the WinRM shell did not report completion within 16 receive rounds`.
* `MaxEnvelopeSize` is set to 153600; stdout is checked against the 16 MiB
  cap inside the receive loop.
* `HTTP 401` reports
  `WinRM authentication failed for <user> against <url> (HTTP 401)`; SOAP
  faults are surfaced as readable messages.
* The shell is deleted best-effort even when the command fails.
* IPv6 endpoints are bracketed (`https://[v6]:5986/wsman`).
* `--winrm-insecure` prints a `WARNING:` to stderr and a tracing warning.
