# Local profiler agent (v1.5)

The `orbyn agent` samples the local host's CPU, RAM, swap and load averages
into the same database every other Orbyn collector uses, so utilization
windows, right-sizing readiness and assessment work on agent data without
any special handling.

```text
orbyn agent run --once        # one sample, then exit (cron friendly)
orbyn agent run               # sample every 60s until stopped
orbyn agent report            # window stats + sample coverage
orbyn agent report --format html > report.html
```

## What it records

- **Samples** (every `--interval-secs`, default 60):
  - **Linux**: CPU busy % from `/proc/stat` deltas, RAM used/available and
    swap used from `/proc/meminfo`, load averages from `/proc/loadavg`. No
    subprocesses, no privileges.
  - **Windows**: one local PowerShell probe per sample — processor load
    (`Win32_Processor.LoadPercentage`), physical memory
    (`Win32_OperatingSystem`), page-file usage (`Win32_PageFileUsage`) —
    the same `cpu|total|free|page` line the remote Windows collector
    parses. No load averages on Windows.
- **Facts** (every `--facts-interval-secs`, default 3600, `0` disables):
  - **Linux**: filesystems (`df -kPT`) and established connections
    (`ss -tnp`) through the SSH collector's parsers.
  - **Windows**: the full read-only probe (`Get-CimInstance`/`Get-Service`/
    `Get-NetTCPConnection`) run locally, refreshing OS identity, disks,
    running services and connections through the remote collector's
    parser. Its three snapshot samples are dropped — the agent's interval
    samples are the real history.

  Both paths upsert idempotently.

Samples are stored as ordinary `metric_samples` rows keyed by the host's
asset id, so `orbyn metrics <ip>`, `orbyn assess` and the `rs.*`
right-sizing rules see them like any imported history. The agent ensures
its own asset row exists first (keyed by IP); the upsert never overwrites
facts collected by an earlier discovery.

## Identity

Samples are recorded under `--asset-ip` when given, otherwise the
auto-detected primary local address (a connected UDP socket's local
address — no traffic is sent), falling back to loopback on an offline
host. Use `--asset-ip` when the host is known to discovery under a
specific address.

## Restart resilience and retention

Samples are timestamped, append-only rows (idempotent on
`(asset_id, sampled_at)`), so a restarted agent simply resumes appending;
`orbyn agent report` shows the largest gap between consecutive samples,
which is the outage signal. Rows older than `--retention-hours`
(default 720 = 30 days) are pruned on start and hourly.

## Running as a service

`--once` makes the agent a one-shot command, so either a systemd timer or
a service works:

```ini
# /etc/systemd/system/orbyn-agent.service
[Unit]
Description=Orbyn local profiler agent
After=network-online.target

[Service]
ExecStart=/usr/local/bin/orbyn agent run --db /var/lib/orbyn/agent.db
Restart=on-failure
User=orbyn
Group=orbyn
StateDirectory=orbyn

[Install]
WantedBy=multi-user.target
```

`sudo systemctl enable --now orbyn-agent`. For a timer instead, point
`ExecStart` at `orbyn agent run --once` in a `*.timer` unit. The agent
shuts down cleanly on SIGINT/SIGTERM, finishing the in-flight sample.

## Platform status

Linux and Windows are implemented. Windows sampling invokes
`powershell -NoProfile` locally (present on every Windows host); the
probe is read-only and needs no privileges beyond a standard user session.
The Windows code path is compiled and unit-tested by CI on
`windows-latest`; live validation on a real Windows host is tracked in
the backlog.

## Remote sync (v1.6)

`orbyn agent sync` ships the local database to a single-tenant ingest
server; the local database is the buffer, so nothing is lost when the
server is down and every server-side write is idempotent.

```console
# On the operator's machine (default bind 127.0.0.1:7780):
orbyn server enroll --asset-ip 10.0.0.5   # prints the token exactly once
orbyn server run

# On the observed host (cron/systemd timer; sample then ship):
orbyn agent run --once
orbyn agent sync --url http://127.0.0.1:7780/v1/ingest --token <token>
```

- **Cursor-based**: only samples strictly after the last acknowledged
  instant are sent, in batches of 5 000; facts (filesystems,
  connections) ride along as re-upserted snapshots.
- **Enrollment tokens** are random UUIDs printed once at enrollment;
  the server stores only their SHA-256 hashes. `orbyn server revoke
  <asset-id>` refuses future syncs — the agent keeps buffering locally
  until re-enrolled.
- **Transport** is plain HTTP on loopback with Bearer auth per
  [ADR-0002](ADR-0002-platform-scope-privacy-pricing-nmap.md) D3:
  local-first, no at-rest encryption before remote ingest leaves the
  host. Binding beyond loopback is a deliberate operator decision.
- The sync client uses the system `curl` (token streamed via stdin, so
  it never appears in a process listing). One attempt per run — the
  timer is the retry policy.
- Agents may submit only their own asset row, samples, and
  filesystem/connection facts; the server forces every fact's asset id
  from the authenticated batch, so one compromised agent cannot pollute
  another asset's inventory.
