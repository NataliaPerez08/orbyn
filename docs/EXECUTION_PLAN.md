# Orbyn — Execution Plan

Tactical plan derived from a review of `docs/ORBYN_AGENT_PLAN.md` against the
current repository. Follows the plan's priority order. Each cycle is
self-contained, testable in CI, and lands as an isolated commit.

## Review summary (current state vs. the 10 phases)

| Phase | State | Evidence |
|---|---|---|
| 1 Version/docs consistency | **Gaps** | `Cargo.toml:3` = `1.0.3`; `README.md:7` says "v1.0 … v1.1 integrations included"; ROADMAP/BACKLOG declare v1.1/v1.2 implemented. `INSTALL.md:57-75` documents macOS downloads but `.github/workflows/release.yml` builds only Linux x86_64 + Windows x86_64 (commit `d8e0bab`). `ROADMAP.md:110` claims "Linux, macOS and Windows" install docs. Tags: `v1.0.0..v1.0.3`. |
| 2 Golden datasets | **Partial** | `tests/e2e_scale.rs:56` generates a deterministic 10k inventory but only time-budget tests exist; no version-controlled golden outputs (counts, groups, findings, scores, right-sizing). |
| 3 Cloud adapter contract | **Partial** | `tests/e2e_cloud.rs` (12 tests) covers auth/retry/pagination per adapter, but not the full HTTP/retry/inventory matrix for all 6 adapters. |
| 4 Real-world validation | **Missing** | No `docs/VALIDATION_MATRIX.md`. |
| 5 Right-sizing scenarios | **Partial** | `src/metrics` unit tests cover percentiles/confidence/span; the 8-scenario deterministic matrix and the 9-field recommendation surface are not asserted as a suite. |
| 6 Perf baselines | **Partial** | `tests/e2e_scale.rs` asserts budgets; no recorded baseline numbers in docs. |
| 7 Failure/recovery | **Partial** | Timeout/stderr-flood/partial-failure covered; SQLite locked/corrupt and PostgreSQL-unavailable not tested. |
| 8 Release hardening | **Partial** | Lock/toolchain/actions pinned; **no release smoke test**. |
| 9/10 SKU matching, migration waves | Deferred | Explicit non-goals until consolidation is stable. |

---

## Cycle 1 — Version and platform consistency (Phase 1)

Goal: one version story and release platforms that match the docs.

### Task 1.1 — Versioning strategy
- Keep SemVer for shipped releases (`Cargo.toml` stays `1.0.x`; next release tag
  bumps it).
- Relabel the roadmap's `v1.1`/`v1.2` capability tiers as internal milestones in
  `docs/ROADMAP.md` and `docs/BACKLOG.md` (e.g. "integr integrations", "metrics
  + right-sizing") so no feature is described with a version number that was
  never released.
- Update `README.md:7` status line to `v1.0.3` and drop the "v1.1 integrations"
  phrasing; re-point the right-sizing mention (README:180) to the milestone name.

### Task 1.2 — macOS platform story
Pick one, do the other:
- **Option A (recommended):** restore macOS targets in `.github/workflows/release.yml`
  matrix (`aarch64-apple-darwin`, `x86_64-apple-darwin`), keeping
  `docs/INSTALL.md` true.
- **Option B:** remove the macOS section from `docs/INSTALL.md` and flip
  `ROADMAP.md:110` to Linux/Windows only.

### Task 1.3 — Cloud adapter maturity labels
- Audit the README integration table and ROADMAP cloud section; label each
  adapter `offline tested` / `live validated` / `production validated`.
- No adapter described as production-ready on fixture tests alone.

**Acceptance:** README and ROADMAP describe the same current release; release
platforms match Actions; no contradictory version numbers; adapter maturity
labeled. Verify: `grep` for `v1.1`/`v1.2`/`macOS` in docs after the change.

---

## Cycle 2 — Golden dataset suite (Phase 2)

Goal: deterministic, version-controlled reference datasets that fail on drift.

### Task 2.1 — Shared generator — **done**
- `representative_inventory(assets)` moved from `tests/e2e_scale.rs` into
  `tests/common/` (shared by scale and golden suites).

### Task 2.2 — Fixtures — **done**
- `tests/fixtures/golden/{small,medium}/` (10 / 100 assets) with the crafted
  input `inventory.json` committed. The crafted dataset exercises EOL OS,
  missing OS, insecure services (telnet), multi-interface assets and rows with
  missing optional fields.
- `large` (1000) / `stress` (10000) are generated at runtime from the shared
  deterministic generator and asserted by count — committing multi-thousand-row
  fixtures adds no drift signal beyond what the generator tests already give.

### Task 2.3 — Expected outputs — **done**
- Committed golden `assess.json`, `graph.csv` and `export.csv` per dataset.
  Assessment JSON carries no timestamps (deterministic); the export CSV is
  normalized (timestamps stripped, rows sorted per section) before compare.

### Task 2.4 — Harness — **done**
- `tests/golden.rs`: import → `deps add` (deterministic edges) → graph →
  assess → export, diffed against the golden files. `ORBYN_GOLDEN_UPDATE=1`
  regenerates after an intended change.

**Acceptance:** datasets committed; outputs deterministic (verified by repeated
runs); CI runs `tests/golden.rs`; drift in counts/findings/scores/exports fails
the build.

---

## Cycle 3 — Cloud adapter contract tests (Phase 3)

Goal: all six adapters (Proxmox, AWS, Huawei, OpenStack, GCP, Azure) share
equivalent guarantees.

### Status — **done**
- The six adapters share the `CurlClient` (`src/integrations/cloud/mod.rs`), so
  the HTTP/retry contract is proven once through the shared path.
- Existing per-adapter e2e already cover auth (missing/invalid, stdin
  credentials, redaction) and inventory normalization (assets/interfaces/
  capacity/filesystems, tags, account/region provenance, stable ids, partial
  failure preservation via "Skipped N resource(s)").
- Added to `tests/e2e_cloud.rs` a scripted fake `curl` (fail-first-then-delegate)
  and contract tests:
  - **Retry:** 429 / 500 / 503 / timeout are replayed and the import then
    succeeds; the failing endpoint is attempted more than once.
  - **No retry:** 401 / 403 / malformed body fail cleanly in one attempt, no
    blind loop, no credential in the output.
  - **Budget:** a persistently 500 provider spends the 3-attempt budget then
    fails explicitly.
  - **Idempotency:** re-importing the same provider state reconciles rows
    instead of duplicating assets.

**Acceptance:** one behavioral contract matrix passes for all adapters (shared
path) — 16 e2e cloud tests green.

---

## Cycle 4 — Right-sizing validation (Phase 5)

### Status — **done**
- Per-scenario unit coverage (overprovisioned/saturated CPU+RAM, swap pressure
  + floor, storage oversized/not-flagged, trend/insufficient window) already
  existed in `src/assessment/rules.rs`.
- Added the missing **evidence contract**:
  - `rs_recommendations_expose_the_full_evidence_contract` asserts every
    right-sizing finding exposes rule id, observation span, sample confidence,
    current capacity, relevant percentile, safety margin/threshold,
    recommendation, and its evidence; the report carries `rules_version`.
  - `e2e_prometheus.rs` parses `assess --format json` after a week of history
    and asserts `rules_version` plus a non-empty evidence array on every `rs.*`
    finding.
- `snapshots_never_drive_right_sizing` keeps the invariant that no snapshot is
  treated as historical evidence.

**Acceptance:** every recommendation exposes the 9 fields; no snapshot drives a
sizing decision.

---

## Cycle 5 — Performance baselines (Phase 6)

### Status — **done**
- `examples/bench_inventory.rs` generates the deterministic reference inventory
  (byte-identical to the scale tests' generator).
- `scripts/bench.sh` (+ `make bench`) measures import/assess/export/graph
  wall-clock and peak RSS via GNU `time` at 100 / 1k / 10k assets on the
  release binary and rewrites `docs/PERFORMANCE.md`, including DB size after
  import.
- Baseline numbers recorded (order-of-magnitude expectations). The scale suite
  (`tests/e2e_scale.rs`) remains the regression gate (wall-clock budgets); a
  >25% change on an identical reference dataset warrants investigation.
- 50k edges / 100k metric samples deferred (the suite already covers metric
  aggregation at 1.5k assets with a week of history).

**Acceptance:** documented, reproducible baselines; regression policy stated.

---

## Cycle 6 — Failure and recovery (Phase 7)

### Status — **done**
- New `tests/e2e_failures.rs`:
  - **Missing collector binary** (`ORBYN_NMAP_BIN=/nonexistent`) fails the job
    cleanly ("failed to start") and records an `nmap,failed` job.
  - **Corrupt SQLite** database file surfaces a clean error instead of a panic.
  - **PostgreSQL unavailable** (unreachable endpoint) fails cleanly with the
    URL password redacted (audit OY-06).
- The partial-failure contract (completed observations persisted, failed job
  recorded with accurate counts, no credentials in errors, DB consistent) was
  already covered by `e2e_discovery::partial_failure_keeps_successful_targets`,
  the timeout/stderr-flood nmap tests, and the malformed/oversized import tests.
- SQLite *locked* is not tested deterministically (busy-timeout handled by
  sqlx); noted as a residual.

**Acceptance:** partial failures keep completed work, record the failure, leak
no credentials, and leave the DB consistent.

---

## Cycle 7 — Release smoke test (Phase 8)

### Status — **done**
- `scripts/release-smoke.sh`: extracts a built artifact (tar.gz or zip), asserts
  `orbyn --version` matches the release tag, renders `--help`, and serves
  `orbyn assets --format csv` from a fresh database (proving migrations run).
- Wired into `.github/workflows/release.yml` as a step after packaging on the
  Linux target (`if: matrix.os != 'windows-latest'`), asserting the artifact
  version equals `${RELEASE_TAG#v}`.
- The rest of Phase 8 (pinned toolchain, `--locked`, pinned actions, checksums,
  LICENSE/THIRD_PARTY_NOTICES in the archive) was already enforced by
  `release.yml` / `ci.yml` and the audit OY-10.

**Acceptance:** the binary version matches the release tag and a fresh database
works, checked in CI on every release.

---

## Cycle 8 — Validation matrix (Phase 4)

### Status — **done**
- `docs/VALIDATION_MATRIX.md`: honest per-integration status across fixture /
  live / scale validation. All collectors, integrations and cloud adapters are
  **fixture tested**; none is claimed production-validated on fixtures alone.
- PostgreSQL is the only backend with documented live coverage (audit OY-06,
  2026-09-30); SQLite is exercised live on every run.
- Live validation procedures documented per integration (manual commands +
  assertions) for the credential/billing-gated providers.

**Acceptance:** the matrix records fixture/live/scale status and the manual live
procedure for every integration.

---

## Cycle 9 — Fuzz execution (Phase 7 extension)

### Status — **done**
- Installed nightly + `cargo-fuzz` and ran all 7 targets (`import`, `parsing`,
  `sanitize`, `netbox_origin`, `device_output`, `structural`, `nmap_xml`) for
  3,000 runs each on the libFuzzer build.
- **Found and fixed a real crash**: `split_http_status` called `split_at(len - 3)`
  on a lossy-decoded `&str`; a curl response whose tail was multi-byte
  (replacement chars) panicked on a non-char-boundary split. Fixed with
  non-panicking `get` ranges (`src/http.rs`), with the fuzz input committed to
  the corpus and a unit regression test added.
- All other targets and all subsequent runs are clean.
- A `fuzz` job was added to `.github/workflows/ci.yml`: builds every target
  (catches API drift in the fuzzed lib) and runs a 500-run smoke per target on
  nightly, so the crash class stays caught in CI.

**Acceptance:** fuzz harness runs in CI; any crash is
reproduced, fixed at the shared root cause, and pinned with a regression test.

---

## Cycle 10 — Cloud SKU matching (Phase 9)

### Status — **done**
- `src/sku/mod.rs`: curated catalogs (AWS EC2, Azure VM sizes, GCP machine
  types) and a pure `match_skus(provider, cores, ram_mb)` — smallest fit
  first, meeting both requirements.
- CLI: `orbyn sku-match --provider aws|azure|gcp --cores <n> --ram-mb <m>
  [--format table|json|csv]`. Kept separate from core right-sizing (the
  baseline comes from the vendor-neutral `rs.*` rules and is passed
  explicitly).
- Unit tests (smallest fit, every candidate meets the requirement, no-fit,
  catalog uniqueness) + `tests/e2e_sku.rs` (all three formats via the binary).
- Docs: `docs/sku.md` + `cli.md` entry + site nav.
- `ponytail:` cost comparison (live pricing) deferred — list prices rot;
  add a pricing source behind the same `match_skus` shape when needed.

**Acceptance:** a baseline produces a deterministic, smallest-fit candidate
list per provider, decoupled from the assessment rules.

---

## Explicitly deferred

Phase 10 (migration waves) is a non-goal until Cycles 1–10 are green. No new
providers, web UI, or agents.

## Execution rules per change

Follow `docs/ORBYN_AGENT_PLAN.md` engineering rules: smallest coherent change,
tests, `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, relevant tests,
docs updated. Report per the Completion Report format.