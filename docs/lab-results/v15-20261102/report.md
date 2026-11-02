# v1.5 7-day observation — 2026-11-02

Recorded run of `demo/qemu/check-observation.sh` on the Proxmox KVM host
(100.115.215.49 over Tailscale), validating the v1.5 exit criteria: the
local profiler and agent sustain observation across three heterogeneous
Linux hosts for at least 168 hours without gaps exceeding 600 seconds.

## Environment

| Component | Value |
|-----------|-------|
| Host | Proxmox VE (Debian 13 trixie), 4 cores i3-8109U, 16 GB RAM |
| Binary | orbyn v1.3.0 (Docker build, glibc 2.31, runs on all guest OSes) |
| Lab | `demo/qemu/` on bridge `br0` (192.0.2.0/24, TEST-NET-3) |
| Server | `/usr/local/bin/orbyn --db server.db server run --bind 192.0.2.1:7780` |
| Agent | systemd `orbyn-agent.service` + `orbyn-agent-sync.timer` (5 min) |
| Facts cadence | `--facts-interval-secs` default 3600s (hourly) |
| Observation start | 2026-10-26T05:25Z |
| Observation end | 2026-11-02T05:25Z (180.4 h elapsed) |

## Enrolled hosts

| VM | IP | OS | Agent since |
|----|----|----|-------------|
| web-01 | 192.0.2.11 | Ubuntu 24.04.5 | 2026-10-26T05:25:46Z |
| api-01 | 192.0.2.12 | Ubuntu 22.04.5 | 2026-10-26T05:25:48Z |
| db-01 | 192.0.2.13 | Ubuntu 20.04.6 | 2026-10-26T05:25:50Z |

## Coverage results

`check-observation.sh` — 9/9 passed:

| VM | Samples | Span (h) | Largest gap (s) |
|----|---------|----------|-----------------|
| web-01 | 10,778 | 180.38 | 60.47 |
| api-01 | 10,776 | 180.35 | 60.71 |
| db-01 | 10,780 | 180.42 | 60.49 |

All three hosts exceed the 168-hour minimum span. The largest gap
stays at ~60 s (one missed 60-second sampling interval), well under
the 600-second threshold. No host dropped off the server at any point
during the 7.5-day window.

## Connection evidence

The facts cadence (`ss -tnp`, hourly) collected active connections
from all three hosts. The three expected dependencies were observed
with evidence in the server database:

| Source | Target | Port | Process | Service |
|--------|--------|------|---------|---------|
| api-01 | db-01 | 5432 | python3 | PostgreSQL |
| api-01 | db-01 | 6379 | python3 | Redis |
| web-01 | api-01 | 8080 | nginx | Flask API |

## Dependency graph

```
web-01 ──tcp:8080──→ api-01 ──tcp:5432──→ db-01
                   └──tcp:6379──→ db-01
```

All three edges carry `evidence_source=active-connections` and
`confidence=0.9` in the graph output.

## What this validates

1. **Sustained observation**: the agent's systemd service + sync timer
   kept all three hosts observed through the ingest server for > 168 h
   without manual intervention.
2. **Gap resilience**: the largest sampling gap never exceeded 60 s —
   one missed interval — across the entire window. The 600-second
   threshold (10 missed intervals) was never approached.
3. **Connection mapping**: the facts cadence collected `ss -tnp` output
   hourly and the server built a dependency graph with all three
   expected edges, confirming that the `ss` parser fix (`f6af7c2`)
   works on Ubuntu 20.04, 22.04, and 24.04.
4. **Cross-distro binary**: the glibc 2.31 Docker build ran on all
   three guest OSes (20.04, 22.04, 24.04) without issue.

## Evidence

- [evidence.log](evidence.log) — `check-observation.sh` output + graph
- Server DB: `server.db` on 100.115.215.49:/root/lab/
- Proxmox VMs 102/202/203/204 were stopped during the observation to
  free RAM; restart with `qm start 102 202 203 204` after cleanup.
