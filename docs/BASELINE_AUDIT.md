# Baseline Audit — Sprint 0 (ROADMAP_V2)

**Date:** 2026-10-13 · **Baseline:** v1.3.0 (tag `v1.3.0`, release commit `e052f2f`;
HEAD `6ede361` is documentation-only on top) · **Auditor:** Sprint 0, per
[ROADMAP_V2.md](ROADMAP_V2.md)

## 1. Pinned baseline

| Item | Value |
|---|---|
| Crate version | `1.3.0` (`Cargo.toml`) |
| MSRV | 1.75 (`rust-version`) |
| CI toolchain | 1.98.1 (pinned by SHA in `ci.yml`) |
| Platforms | Linux (`x86_64-unknown-linux-gnu`), Windows (`x86_64-pc-windows-msvc`) — CI builds+tests both; release artifacts for both (`release.yml`) |
| Releases | `v1.0.1`–`v1.0.4`, `v1.3.0` (tags) |

## 2. Nmap invocation inventory (complete)

Exactly **one** call site: `src/collectors/nmap.rs:65` (`NmapCollector::scan`).

| Aspect | Finding |
|---|---|
| Command | `nmap -oX - -sV --no-stylesheet <target>` |
| Targets | Single IP or CIDR string, passed as argv (never shell); validated upstream by `validate_target_with_policy` (IPv4 floor /16, IPv6 floor /48, `--allow-large-cidr` override, `/0` and `0.0.0.0`/`::` bases always rejected) |
| Output | XML to stdout; streamed `quick-xml` parse (no DOM); stdout/stderr capped (`MAX_*_CAPTURE_BYTES`), truncation is an error |
| Privileges | None requested; SYN vs connect scan is nmap's euid decision. No `sudo`, no raw sockets |
| NSE scripts | None |
| OS detection | No `-O` flag; the parser tolerates `<osmatch>` if present |
| Timing/tuning flags | None (default timing template) |
| Env knobs | `ORBYN_NMAP_BIN` (binary override), `ORBYN_NMAP_TIMEOUT_SECS` (default 1800 s whole-process timeout) |
| Child env hygiene | `ORBYN_SNMP_COMMUNITY`, `ORBYN_NETBOX_TOKEN`, `ORBYN_WINRM_PASSWORD`, `ORBYN_PROMETHEUS_TOKEN`, `ORBYN_DB` stripped from the child environment |
| Lifecycle | `stdin(null)`, `kill_on_drop(true)`, timeout enforced by `run_captured` |

**Nmap features Orbyn actually consumes:** host liveness, TCP port state,
`-sV` service name/product/version, PTR hostname, MAC+vendor (when on-link),
XML report shape. **Not used:** NSE, UDP, OS fingerprinting flag, traceroute,
decoys/fragmentation, output file formats other than XML.

**Parse consumers:** `parse_nmap_xml` → `Observation::Asset` (one per host with
a usable address; down hosts skipped) + `Observation::Interface` (MAC only) +
`Observation::Service` (only `state == "open"`), then `classify_device`,
store reconciliation, assessment/graph/export pipelines. Fuzz target
`nmap_xml` covers the parser; unit fixtures cover ports/OS/MAC/XXE/truncation.

## 3. Crates, storage, API/CLI, CI

- **Direct dependencies:** chrono, clap, quick-xml, serde, sqlx (sqlite +
  postgres, rustls), tokio, tracing/tracing-subscriber, uuid, anyhow,
  async-trait, thiserror. 251 locked crates.
- **Storage:** `Store` trait over SQLite and Postgres (sqlx migrations,
  `schema_migrations` + `postgres_store` suites).
- **Discovery contract:** `Collector` trait (`src/collectors/types.rs:35`) —
  `name()` + `scan(&ScanTarget) -> Vec<Observation>`; `Send + Sync` for the
  bounded worker pool (`src/app/discovery.rs`), `--concurrency`/`--rate-limit`
  pacing, partial-failure persistence with secret redaction.
- **CLI surface:** `discover`, `jobs`, `asset(s)`, `services`, `import`,
  `export`, `graph`, `deps`, `assess`, `metrics`, `applications`, `plan`,
  `bundle`, `targets`, `sku-match`, `waves`, cloud importers, `audit`,
  `completions` (see `docs/cli.md`).
- **CI (`.github/workflows/ci.yml`):** fmt + clippy (`-D warnings`), locked
  build + full test + release build, Postgres store suite, Windows build +
  test, RustSec `audit-check`, `cargo deny` licenses + sources, 8 fuzz targets
  built + smoked (incl. `nmap_xml`).

## 4. Local verification (this audit, Linux)

- `cargo test --locked --all-targets`: **all green** — 404 unit tests plus 23
  test targets (e2e, golden, schema, smoke, postgres-skip).
- `cargo fmt --check`: clean.
- `cargo clippy --all-targets`: clean (CI runs it with `-D warnings`).
- Lab-network run: **not performed here** (no authorized lab in this
  environment); remains the one Sprint 0 item pending live evidence.

## 5. Licenses and redistribution

- Crate is Apache-2.0; `THIRD_PARTY_NOTICES.md` and
  `EXTERNAL_DEPENDENCIES.md` are maintained.
- `cargo deny check licenses` + `sources` run in CI — policy is enforced
  continuously, not per-release.
- Nmap is **invoked, never bundled**; INSTALL.md documents it as an external
  requirement. No Nmap redistribution obligation exists today. (If a future
  release ever bundles Nmap, GPL obligations must be reviewed first.)

## 6. Gaps and risks (feed the v1.4 backlog)

| # | Gap / risk | Disposition |
|---|---|---|
| G-1 | Nmap is the only discovery adapter — required at runtime for port discovery | v1.4 adds a `native` TCP-connect collector behind the existing `Collector` contract |
| G-2 | `-sV` product/version depth is not reproducible with connect+banner only | Native slice records banners; deep probes stay on nmap until parity is measured |
| G-3 | Native liveness = "some port answered"; no ICMP/ARP prefetch yet | Documented difference; ICMP/ARP liveness is the v1.4 follow-up |
| G-4 | IPv6 CIDR ranges are impractical for connect scanning (≥2^64 hosts at /64) | Native refuses oversized expansions with a clear error; single IPv6 hosts work |
| G-5 | No recorded lab comparison native-vs-nmap yet | Required before flipping any default; tracked in BACKLOG |
| G-6 | Live/production validation of cloud adapters still open | Tracked in VALIDATION_MATRIX.md (pre-existing) |

## 7. Sprint 0 outputs

- This audit (`BASELINE_AUDIT.md`).
- Contracts ADR: [ADR-0001 — Discovery backend contract](ADR-0001-discovery-backend-contract.md).
- Updated backlog: [BACKLOG.md](BACKLOG.md) — new "v1.4 — Native discovery" section.
- Nmap XML fixtures: already present (unit fixture + `fuzz/nmap_xml` + golden
  snapshots); the lab-run fixture capture is folded into the G-5 comparison
  task rather than duplicated here.
