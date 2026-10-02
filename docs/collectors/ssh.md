# SSH collector (Linux)

`--collector ssh` runs one fixed, **read-only** shell probe through the
externally installed OpenSSH client and parses the output in pure Rust. The
probe is a constant — only the host address comes from your input, and it is
passed as an argument vector, never through a shell.

Exact argv:

```text
ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
    -o LogLevel=ERROR -p <port> [-i <identity>] <[user@]ip> <probe>
```

Probe output is split on `###name` markers into sections:
`os`, `kernel`, `hostname`, `cpu`, `mem`, `disk`, `svc`, `conn`, `virt`,
`metric`.

## When to use it

Linux/Unix hosts where you want the full picture: OS and kernel, CPU/RAM
capacity, filesystems, running systemd units, established connections and a
short utilization snapshot.

```bash
# ssh-agent authentication (nothing to pass explicitly)
orbyn discover --target 10.0.0.10 --collector ssh --user deploy

# identity file and non-default port
orbyn discover --target 10.0.0.10 --collector ssh --user deploy \
    --port 2222 --identity-file ~/.ssh/id_ed25519

# a few hosts in parallel
orbyn discover --target 10.0.0.10 --collector ssh --user deploy \
    --target 10.0.0.11 --target 10.0.0.12 --concurrency 8
```

!!! warning "Single host only"
    A CIDR target is rejected: `SSH collects a single host; target must be an
    IP address`.

## Options

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--user <u>` | current user | Login account; must not start with `-` |
| `--port <p>` | `22` | SSH port |
| `--identity-file <path>` | *(none)* | Private key file |
| `ORBYN_SSH_BIN` | `ssh` | Binary path |

### Authentication

Only **ssh-agent or an identity file**. `BatchMode=yes` disables interactive
password prompts, so SSH password authentication is intentionally unsupported
— passing passwords through subprocess arguments or storing them would
violate the security rules in [Security](../security.md). The identity file
path is recorded; the key itself is never read, copied or logged.

## Requirements

| Side | Needs |
| --- | --- |
| Orbyn host | OpenSSH client (`ssh`) |
| Target | `sshd`, plus `lscpu`/`/proc/*`, `df`, `systemctl`, `ss` (or `netstat`) |
| Optional | `systemd-detect-virt` for hypervisor detection; `dig` is unrelated |

The metric block only needs `sed`, `awk`, `cut`, `tr` and `sleep`, so it works
on minimal hosts. Where a tool is missing the probe degrades (for example
`netstat -tn` instead of `ss -tnp`).

!!! note "Host keys"
    `StrictHostKeyChecking=accept-new` trusts a first-seen host key
    automatically. Change it in your SSH config if you need strict
    verification.

## What it produces

| Observation | Fields |
| --- | --- |
| `Asset` | `device_class = server`, OS from `/etc/os-release` `PRETTY_NAME`, `os_version` = kernel (`uname -r`), hostname |
| `Capacity` | CPU model / sockets / cores / threads, `ram_total_mb`, `hypervisor` (see [virt](framework.md#hypervisor-detection)) — emitted if CPU **or** RAM is present |
| `Filesystem` | One row per `df -kPT -x tmpfs -x devtmpfs` line: device, fs type, size/used/available kB, used %, mount |
| `RunningService` | systemd units from `systemctl list-units --type=service --state=running` (only `active` rows) |
| `Connection` | Established TCP connections from `ss -tnp` (or `netstat`); loopback and self-connections dropped; process name when available |
| `MetricSample` | Three snapshots ~2 s apart: CPU %, RAM used/available, swap used, load averages |

```bash
orbyn capacity 10.0.0.10       # CPU/RAM + hypervisor
orbyn disks 10.0.0.10          # filesystem inventory
orbyn host-services 10.0.0.10  # running systemd units
orbyn connections 10.0.0.10    # raw connection evidence
orbyn metrics 10.0.0.10        # utilization window, percentiles, readiness
orbyn asset 10.0.0.10          # everything above in one record
```

Connections are additionally reconciled into dependency edges (evidence
`active-connections`, confidence `0.9`) whenever the remote endpoint matches a
known asset.

## Limits and failures

* 60 s per probe, `ConnectTimeout=10`.
* 16 MiB stdout cap; exceeding it fails the target instead of storing
  partial data.
* Metric samples are collected **on demand only** — there is no scheduler. For
  sustained evidence run discovery on a schedule, or import history with
  [Prometheus/Zabbix](../importers/observability.md).
* OpenSSH's own environment (agent socket, config) is inherited; Orbyn's
  secret variables are scrubbed before spawning.
