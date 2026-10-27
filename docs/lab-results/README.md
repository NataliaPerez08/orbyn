# Lab results — recorded evidence and findings

Recorded runs from the QEMU demo lab (`demo/qemu/`) that satisfy the
lab-gated backlog items, plus the bugs each run caught on the way. The
lab exists precisely because fixture-backed CI cannot catch these
classes of defects: format drift against real tools on real distros,
provisioning drift, and harnesses that were never run end-to-end.

## Recorded runs

| Run | Gates | Result |
| --- | --- | --- |
| [nmap-vs-native-20261025-231625/](nmap-vs-native-20261025-231625/report.md) | NMAP-010 — native-vs-nmap parity, gates the `auto` collector mode and any default flip (ADR-0002 D5) | All checks passed: host recall 4/4 both adapters; TCP port recall native 9/9 vs nmap 8/9 (nmap missed db-01:6379); named ports native 9/9 (fingerprint probes) vs nmap 0/9; runtime 266s vs 32s; UDP observations native-only. Parity holds for Orbyn's use cases. |
| [v16-20261027/](v16-20261027/evidence.log) | v1.6 exit criteria — three heterogeneous hosts (Linux + Windows) observed through the ingest server, connections backed by evidence, revocation verified mid-run | 10/10 passed on the live server (Ubuntu 24.04/22.04/20.04 agents, api-01→db-01:5432/6379 and web-01→api-01:8080 with graph edges, revocation refused + local buffering + re-enroll recovery). Recorded with `v16-evidence.sh`, a variant of `agent-lab.sh` that does not wipe `server.db`, preserving the in-flight 7-day v1.5 observation. Windows host (Server 2022 VPS via Tailscale subnet route) recorded in [windows-host.md](v16-20261027/windows-host.md): enrolled, scheduled tasks, samples + 14 live connections through the same server. |

## What the lab caught, and the fixes

1. **orbyn — `ss` state-filtered output not parsed** (`f6af7c2`).
   iproute2 ≥ 5 omits the State column when a `state` filter is given,
   so `ss -tnp state established` rows start with the queue counters.
   `parse_connections` only accepted `ESTAB`/`tcp`-prefixed rows and
   skipped everything: **zero connection evidence from the agent facts
   cadence and the SSH collector on modern distros** (observed on
   Ubuntu 20.04–24.04; the e2e fakes emit the old shape, so CI was
   green). Fix: accept the filtered row shape — every such row is
   established by construction — with a fixture test from the lab
   output. User-facing: dependency mapping on any current distro was
   silently blind.

2. **Lab cloud-init — provisioning drift** (`221ee18`).
   - db-01: `pg_hba` demanded `scram-sha-256` but focal's PostgreSQL 12
     defaults to `password_encryption = md5`, so the `api` role was
     created with an MD5 verifier and every login failed — the
     api-01→db-01:5432 edge never existed. Fix: force scram in
     `postgresql.conf` before creating the role.
   - api-01: the werkzeug dev server (and gunicorn 20.1's sync worker,
     which closes the socket in `handle()`'s `finally`) sent
     `Connection: close` on every response, so nginx's upstream
     keepalive pool never held a connection — the web-01→api-01:8080
     edge never existed. Fix: serve with the gthread worker
     (`--worker-class gthread`, keep-alive honored) behind a
     `__main__` guard.

3. **Harnesses — self-test debt** (`dad75ff`).
   `agent-lab.sh` and `check-observation.sh` had never passed a real
   run: the JSON greps assumed compact output (`"sample_count":2171`)
   while `--format json` pretty-prints (space after the colon), the
   connection checks matched a dash-form CSV column layout that does
   not exist (real columns:
   `asset_id,proto,local_ip,local_port,remote_ip,remote_port,process`),
   and the revocation check raced the 5-minute sync timer —
   `systemctl start` on an already-active oneshot is a no-op that
   returns success. Fixes: space-tolerant greps, real column patterns,
   and freezing the sync timer around the revocation window
   (`v16-evidence.sh` keeps the same checks against the live server
   without wiping it).

| [v2-20261027/](v2-20261027/clean-machine.md) | v2.0 exit criteria — full workflow on a clean Windows machine with no toolchain | NSIS silent install on a clean Server 2022 VPS (app + sidecar siblings, registry entry); discover (native, /24 lab over the Tailscale subnet route: 6 assets in ~4.5 min) → observe (agent report HTML) → analyze (inventory JSON) → export (CSV, assets + connections) with the installed sidecar; wizard rendering operator-confirmed ([screenshot](v2-20261027/app-wizard.png)). |

## Pending

- v1.5 7-day observation: in flight — Linux since 2026-10-26T05:25Z
  (validate ≈2026-11-02), Windows since 2026-10-27T19:00Z (validate
  ≈2026-11-03); `demo/qemu/check-observation.sh` on both.
