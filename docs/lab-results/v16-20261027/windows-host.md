# v1.6 evidence — Windows host (ecs-84b2)

Supplement to [evidence.log](evidence.log): the Linux-side run passed
10/10 on 2026-10-27; this records the Windows host of the "three
heterogeneous hosts (Linux + Windows)" criterion, observed through the
same ingest server.

## Host

- Windows Server 2022 Standard Evaluation (10.0.20348), x64, clean VPS
  (`ecs-84b2`, tailnet 100.105.111.12, LAN 172.20.1.49) — no rustc,
  cargo, or git present (verified via WinRM).
- Engine: `orbyn.exe` 1.3.0 from CI run 40411024002
  (`orbyn-windows-engine` artifact, sha256 6d93e924…, transfer verified
  by hash).
- Reachability: Tailscale subnet route 192.0.2.0/24 (advertised by the
  Proxmox node, approved in the tailnet admin); `Test-NetConnection
  192.0.2.1 -Port 7780` → True.

## Deployment (mirrors the Linux units)

- `C:\orbyn\orbyn.exe`, `C:\orbyn\agent.db`.
- Enrollment token stored in `C:\orbyn\sync.token` (ACL: SYSTEM and
  Administrators only — argv never carries it); `C:\orbyn\sync.ps1`
  reads it into `ORBYN_SYNC_TOKEN` for the sync call.
- Scheduled tasks (SYSTEM):
  - `orbyn-agent` (ONSTART): `orbyn.exe agent run --db C:\orbyn\agent.db
    --asset-ip 172.20.1.49` — status: Running.
  - `orbyn-agent-sync` (every 5 min): sync to
    `http://192.0.2.1:7780/v1/ingest` — status: Ready.

## Observed through the ingest server (2026-10-27 ~19:00Z)

- Asset `172-20-1-49` enrolled with a one-time token; first sync
  shipped the startup sample (facts cadence fires on start).
- `orbyn --db server.db agent report --asset-ip 172.20.1.49`:
  `sample_count: 1` within the first minute, growing on the 60s
  cadence.
- `orbyn --db server.db connections 172.20.1.49 --format csv`:
  14 live connections, real traffic — including the WinRM session
  itself observed from the inside
  (`172.20.1.49:5985 ← 172.20.1.96`) and outbound HTTPS
  (`1.1.1.1:443`, CDN endpoints). Columns:
  `asset_id,proto,local_ip,local_port,remote_ip,remote_port,process`.

## Criterion mapping

| v1.6 requirement | Evidence |
| --- | --- |
| Three heterogeneous hosts (Linux + Windows) | web-01 (noble), api-01 (jammy), db-01 (focal) + ecs-84b2 (Server 2022), all observed through 192.0.2.1:7780 |
| Connections backed by evidence | Linux edges in evidence.log; Windows CSV above (incl. the observer's own session) |
| Revocation verified mid-run | evidence.log (api-01 token revoked: sync refused 401, local buffer retained, re-enroll drains it) |
| Windows agent observed through the server | this file: enrollment, scheduled tasks, samples and connections on server.db |

The Windows host also carries the v1.5 7-day observation (started
2026-10-27 ~19:00Z; validate with `demo/qemu/check-observation.sh`
after ≥168h, ≈2026-11-03).
