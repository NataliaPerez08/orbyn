# Validation matrix

Status of every integration across fixture, live and scale validation (Phase 4
of `ORBYN_AGENT_PLAN.md`). Labels are honest: **no integration is claimed
production-validated on fixture tests alone** — fixture coverage proves
behavior against recorded responses, not against a real system.

- **Unit**: in-crate `#[cfg(test)]` suites (parsers, signers, renderers, store
  smoke) run by `cargo test` on every push.
- **Fixture Tested**: automated end-to-end suite runs the real binary against
  recorded/scripted tool output (fake `nmap`/`ssh`/`snmpwalk`/`curl`/`dig`).
- **Live Tested**: verified against a real system; where credentials or billing
  make continuous testing impractical this is documented as a manual procedure.
  Every live validation actually performed is recorded in the
  [live validation log](#live-validation-log) below.
- **Scale Tested**: exercised at representative size (import/assess/export of a
  10k-asset estate; discovery fan-out over 1,024 targets; a week of metric
  history over 1.5k assets).
- **CI**: `.github/workflows/ci.yml` — fmt/clippy, full test suite (unit +
  fixture E2E) on Linux, the same on Windows (E2E fakes compile empty there),
  a dedicated `postgres:16` service job for the PostgreSQL store suite,
  RustSec/cargo-deny audits, and a fuzz build + smoke job.

## Matrix

| Integration | Unit | Fixture E2E | Live | Scale | CI | Last Validation | Notes |
|---|---|---|---|---|---|---|---|
| Nmap collector | Yes | Yes | No | Yes (1,024-target fan-out) | Yes | 2026-10-03 | read-only `-sS -sV`; scope validated; timeout/stderr-flood covered |
| SNMP collector | Yes | Yes | No | Yes (estate) | Yes | 2026-10-03 | community via 0600 `snmp.conf`, never argv |
| SSH (Linux) | Yes | Yes | No | Yes (estate) | Yes | 2026-10-03 | ssh-agent/identity only; no credentials stored |
| Windows OpenSSH | Yes | Yes | No | No | Yes | 2026-10-03 | PowerShell probe over SSH |
| WinRM/WS-Man | Yes | Yes | No | No | Yes | 2026-10-03 | HTTPS-only; password via stdin, never persisted |
| DNS evidence | Yes | Yes | No | No | Yes | 2026-10-03 | CNAME/PTR; `dig` option-guard for hostile names |
| NetBox importer | Yes | Yes | No | No | Yes | 2026-10-03 | token via stdin; hostile pagination URLs rejected |
| Prometheus importer | Yes | Yes | No | Yes (1.5k assets × week) | Yes | 2026-10-03 | right-sizing window; idempotent re-import; 429 retried |
| Zabbix importer | Yes | Yes | No | No | Yes | 2026-10-03 | history + right-sizing; token redacted |
| Proxmox VE adapter | Yes | Yes | No | No | Yes | 2026-10-03 | nodes, VMs, LXC, storage, guest agent |
| AWS adapter | Yes | Yes | No | No | Yes | 2026-10-03 | SigV4 no-SDK; pagination; account provenance |
| Huawei Cloud adapter | Yes | Yes | No | No | Yes | 2026-10-03 | AK/SK signer; pagination; flavor capacity |
| OpenStack adapter | Yes | Yes | No | No | Yes | 2026-10-03 | Nova servers + flavors, Cinder volumes |
| GCP adapter | Yes | Yes | No | No | Yes | 2026-10-03 | Compute aggregated API, disks, labels |
| Azure adapter | Yes (thin: 1 parser test + shared cloud suite) | Yes | No | No | Yes | 2026-10-03 | ARM VMs, NICs, disks, VNets |
| Ansible export | Yes | Yes | No | Yes (10k estate) | Yes | 2026-10-03 | INI + YAML; injection-safe host/tag names |
| Terraform export | Yes | Yes | No | Yes (10k estate) | Yes | 2026-10-03 | HCL locals + import blocks; `${}` escaped |
| SQLite backend | Yes (smoke + migrations) | Yes | Yes (local, every run — see log) | Yes (10k estate) | Yes | 2026-10-05 | 0600 file; migrations; corrupt-file clean failure |
| PostgreSQL backend | Yes (smoke + migrations) | Yes (gated) | Partial — 2 recorded live checks (see log) | No | Yes (dedicated `postgres:16` job) | 2026-10-05 | CI runs the suite when a live PG is present |

## Live validation procedures (manual)

Continuous live validation is impractical for cloud/billing-gated providers,
so each is documented as a manual procedure. Run against authorized systems and
verify the assertions listed.

```text
Linux / SSH    orbyn discover --target <ip> --collector ssh
               -> host facts, capacity, filesystems, running services, edges

Windows / WinRM  ORBYN_WINRM_PASSWORD=<pw> orbyn discover --target <ip> --collector winrm
               -> host facts + connections over HTTPS (5986)

NetBox         orbyn netbox import --url https://netbox.example.com --token -
               -> devices/VMs appear; token absent from output and argv

Prometheus     orbyn prometheus import --url http://prometheus:9090
               -> a week of history; `orbyn metrics <id>` shows span + readiness

Zabbix         orbyn zabbix import --url http://zabbix --user <u> --password -
               -> history maps to assets; re-import is idempotent

Proxmox VE     orbyn proxmox import --url https://pve:8006 --token -
               -> nodes, VMs, LXC, datastores, guest-agent interfaces

AWS            AWS_ACCESS_KEY_ID/... orbyn aws import --region <r>
               -> EC2 + EBS + VPC/subnets; provenance tags; detached volumes skipped

Huawei Cloud   HUAWEICLOUD_SDK_AK/... orbyn huawei import --region <r>
               -> ECS + EVS + VPC/subnets; flavor capacity

OpenStack      orbyn openstack import --url <v2.1/project> --token <t> --project <p>
               -> servers, flavors, volumes

GCP            orbyn gcp import --project <p> --endpoint-url <url> --token <t>
               -> instances, disks, machine-type capacity

Azure          orbyn azure import --subscription-id <s> --token <t>
               -> VMs, NICs, disks, VNets

PostgreSQL     ORBYN_PG_PASSWORD=<pw> orbyn --db postgres://user@host:5432/db assets
               -> backend selected, schema migrated, credentials not in argv
```

## Live validation log

Every real-system validation actually performed is recorded here with the
required fields (integration, date, Orbyn version, external version, scenario,
expected result, actual result, limitations). No credentials, tokens, account
IDs or infrastructure identifiers are stored. Entries are append-only: never
edit a past record, add a new one.

### PostgreSQL — 2026-09-30 (security-audit empirical check, OY-06)

- **Integration:** PostgreSQL backend (`--db postgres://...`)
- **Date:** 2026-09-30
- **Orbyn version:** v1.0.2, commit `db7b5af`
- **External version:** local PostgreSQL instance (version not recorded —
  limitation noted below)
- **Scenario:** connect with an incorrect password and with a malformed URL;
  inspect process argv and all error output for leaked credentials
- **Expected:** connection/parse errors never reveal the URL or the password
- **Actual:** as expected — recorded as verified in `SECURITY_AUDIT.md` (OY-06);
  the argv exposure itself was the finding, remediated afterwards with
  `ORBYN_PG_PASSWORD`/`PGPASSWORD` fallback and redactor registration
- **Limitations discovered:** the audit instance's version was not captured;
  TLS negotiation was not exercised

### PostgreSQL — 2026-10-05 (v1.1 baseline store suite)

- **Integration:** PostgreSQL backend
- **Date:** 2026-10-05
- **Orbyn version:** v1.0.4, commit `9f074c5`
- **External version:** `postgres:16` (Docker, local throwaway container)
- **Scenario:** full `postgres_store` suite — observation round-trip for every
  observation type, bulk reads, dependency confirm/remove, annotations,
  jobs/audit, metric window limits
- **Expected:** 7/7 tests pass against the live backend
- **Actual:** 7/7 PASS (recorded in `V1_1_BASELINE.md`)
- **Limitations discovered:** local container, not a production instance — no
  TLS, HA, connection pooling or privilege separation exercised

### SQLite — 2026-10-05 (v1.1 baseline; continuous by nature)

- **Integration:** SQLite backend (default)
- **Date:** continuous — every CLI and test run opens a real SQLite file; last
  full validation 2026-10-05
- **Orbyn version:** v1.0.4, commit `9f074c5`
- **External version:** SQLite 3 bundled via `libsqlite3-sys` (see `Cargo.lock`)
- **Scenario:** full suite including the 10k-asset estate
  import/assess/export and the 1,024-target discovery fan-out
- **Expected:** all tests pass; schema migrations apply on first open
- **Actual:** 513/513 PASS (recorded in `V1_1_BASELINE.md`)
- **Limitations discovered:** single-process, local filesystem only;
  multi-process concurrent-writer behavior not exercised

### Linux release install/upgrade — 2026-10-06 (V1.1-11, clean container)

- **Integration:** released binary distribution (Linux x86_64)
- **Date:** 2026-10-06
- **Orbyn versions:** v1.0.3 and v1.0.4 (published GitHub release artifacts
  only — no locally built binaries)
- **External version:** `ubuntu:24.04` Docker container (clean environment,
  no Rust toolchain); `debian:bookworm-slim` for the negative case
- **Scenario:** follow `docs/INSTALL.md` verbatim — download both release
  archives and their `.sha256` files, verify checksums, install v1.0.3,
  initialize the database, import two assets, annotate one, back up the
  database, replace the binary with v1.0.4, reopen the database, verify
  data integrity, then uninstall
- **Expected:** checksums verify; `--version`/`--help` work; the database
  is created with 0600 file / 0700 directory permissions; the upgrade
  applies pending migrations automatically and preserves all rows; the
  annotation and job history survive; uninstall removes only the binary
- **Actual:** all as expected — checksums OK, 2 assets + `production`
  annotation intact after the v1.0.3 → v1.0.4 upgrade, `data/` untouched
  by uninstall
- **Limitations discovered:** the release binary requires **glibc ≥ 2.39**
  (built on Ubuntu 24.04); on Debian bookworm (glibc 2.36) it fails with
  `GLIBC_2.39 not found`. `INSTALL.md` now states the requirement and
  points older distributions to the build-from-source path. A binary built
  against an older toolchain (or static musl) is a candidate follow-up.

### Windows release artifact — 2026-10-06 (V1.1-11, partial)

- **Integration:** released binary distribution (Windows x86_64)
- **Date:** 2026-10-06
- **Orbyn version:** v1.0.4 (published artifact)
- **External version:** —
- **Scenario:** download the `x86_64-pc-windows-msvc.exe.zip` release
  artifact and verify its published checksum; confirm the archive contains
  `orbyn.exe`, `LICENSE` and `THIRD_PARTY_NOTICES.md`; confirm the CI
  `windows-latest` job (build + unit/store tests on real Windows) is green
- **Expected:** checksum verifies; contents match `INSTALL.md`; CI green
- **Actual:** checksum OK, contents as documented, CI windows job green
- **Limitations discovered:** a full clean-Windows-VM walkthrough (install,
  `--version`, database init, import, upgrade, uninstall) has **not** been
  performed and is not claimed; it remains a manual procedure per the
  INSTALL.md Windows section

## Caveats

- Credentials are never persisted or echoed; the redactor scrubs known values
  from errors and job records.
- A fixture-passing adapter is **not** a production validation: provider API
  drift, network topology and real capacity data are only exercised live.
- Scale numbers are order-of-magnitude expectations from this repository's
  machines; see `docs/PERFORMANCE.md`.