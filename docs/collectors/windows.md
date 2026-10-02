# Windows collector (over SSH)

`--collector windows` runs one fixed, **read-only** PowerShell probe on a
Windows host and parses the result. Parsing is transport-independent: the
same collector drives either transport, selected by the flag you pass.

| Transport | Flag | Channel |
| --- | --- | --- |
| Windows OpenSSH Server | `--collector windows` | `powershell -NoProfile -Command "<script>"` over `ssh` |
| Native WS-Man/WinRM | `--collector winrm` | see [WinRM collector](winrm.md) |

The probe wraps CIM queries in `ConvertTo-Csv -NoTypeInformation`:

```text
Get-CimInstance Win32_OperatingSystem | Win32_Processor | Win32_ComputerSystem
                | Win32_LogicalDisk | Win32_PageFileUsage
Get-Service        | Where-Object Status -eq Running
Get-NetTCPConnection | Where-Object State -eq Established
```

The metric block samples three times with `Start-Sleep -Seconds 2`.

## When to use it

Windows hosts where the OpenSSH Server feature is enabled — key-based auth,
same operational model as the Linux collector.

```bash
orbyn discover --target 10.0.0.20 --collector windows --user administrator \
    --identity-file ~/.ssh/id_ed25519

# agent-based, default port
orbyn discover --target 10.0.0.20 --collector windows --user administrator

# non-default SSH port
orbyn discover --target 10.0.0.20 --collector windows --user administrator --port 2222
```

!!! warning "Single host only"
    A CIDR target is rejected: `Windows collection targets a single host;
    target must be an IP address`.

## Options

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--user <u>` | current user | Windows account to log in as |
| `--port <p>` | `22` | SSH port (ignored by `--collector winrm`) |
| `--identity-file <path>` | *(none)* | Private key file |
| `ORBYN_SSH_BIN` | `ssh` | Binary path (SSH transport only) |

Authentication is ssh-agent or an identity file, exactly like the Linux
collector — see [SSH](ssh.md#authentication).

## Requirements

| Side | Needs |
| --- | --- |
| Orbyn host | OpenSSH client |
| Target | The **OpenSSH Server** Windows feature, PowerShell 3 or newer, an account allowed to log in |

For native WinRM instead, see [WinRM](winrm.md) — no OpenSSH Server needed,
but a WinRM HTTPS listener with Basic auth.

## What it produces

| Observation | Fields |
| --- | --- |
| `Asset` | `device_class = server`, `os_name` = Caption, `os_version` = `<Version> build <BuildNumber>`, hostname = CSName |
| `Capacity` | model, sockets, cores/threads summed across sockets, `ram_total_mb`, `hypervisor` (see [virt](framework.md#hypervisor-detection)) |
| `Filesystem` | Fixed drives only (`DriveType 3`): size/used/available converted to kB, used % |
| `RunningService` | Service name + display name, state `running` |
| `Connection` | Established TCP connections; loopback and self-connections dropped; no process name (Windows does not expose it to this query) |
| `MetricSample` | CPU %, RAM used/available, pagefile used as swap. **No load averages** on Windows |

```bash
orbyn capacity 10.0.0.20
orbyn disks 10.0.0.20
orbyn host-services 10.0.0.20
orbyn connections 10.0.0.20
orbyn metrics 10.0.0.20
orbyn asset 10.0.0.20
```

Job history records the transport actually used: `windows` (SSH) or `winrm`.

## Limits and failures

* Same bounds as the SSH transport: 60 s per probe, 16 MiB stdout cap.
* CRLF in the CSV output is handled.
* `Get-NetTCPConnection` and `Get-CimInstance` require a modern Windows with
  PowerShell 3+; on older hosts the probe fails for that section.
* Only read-only CIM and `Get-Service` queries are issued — no configuration
  changes, no service control.
