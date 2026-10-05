# v1.1 final verification (V1.1-13)

**Date:** 2026-10-06
**Tree:** `5dc9534` (all thirteen phases of the v1.1 consolidation plan)

## Verification battery

| Check | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets -- -D warnings` | PASS (0 warnings) |
| `cargo test --locked --all-targets` | PASS (513 tests, 0 failed) |
| `cargo build --locked --release` | PASS (13,629,840 bytes; baseline was 13,539,336 — +0.7%, within noise) |
| `cargo audit` | PASS (0 vulnerabilities, 251 crate dependencies) |
| `cargo deny check` | PASS (advisories, bans, licenses, sources) |
| Fuzz build + smoke (7 targets × 500 runs) | PASS (no crashes) |
| PostgreSQL store suite vs live `postgres:16` | PASS (7/7, `ORBYN_PG_TEST_URL`, 2026-10-06) |
| Windows cross-check (`cargo check --target x86_64-pc-windows-msvc`) | **Blocked locally**: `libsqlite3-sys`'s C build script requires MSVC; not cross-compilable from Linux. CI's `windows-latest` job (build + unit/store tests) is green on every pushed commit and the V1.1 code changes are verbatim moves with no new dependencies; the final Windows gate is the push itself. |

## Definition of Done walkthrough

| # | Criterion | Evidence |
|---|---|---|
| 1 | Baseline documented | `V1_1_BASELINE.md` (all green at `9f074c5`) |
| 2 | `main.rs` decomposed | 2,943 → 252 lines (bootstrap + dispatch only) |
| 3 | CLI / app boundaries | `src/cli/` (args, commands, helpers) + `src/app/` (5 workflow modules; clap-free, never references `cli`) |
| 4 | Tests green | 513/513 at `5dc9534` |
| 5 | CI green (Linux + Windows) | Linux: identical commands pass locally; CI green on all pushed commits. Windows: CI green historically; final gate is the push (see battery) |
| 6 | PostgreSQL tests green | 7/7 against live `postgres:16` (above) |
| 7 | Fuzz builds + smokes | 7 targets, 500 runs each, no crashes |
| 8 | `cargo audit` passes | 0 vulnerabilities |
| 9 | `cargo deny` passes | all policies ok |
| 10 | Architecture docs current | V1.1-04: crate tree matches post-refactor layout; stale claims fixed |
| 11 | Roadmap implemented/future distinction | V1.1-04: every status verified against code |
| 12 | Planning docs archived/marked | V1.1-05: four historical plans banner-marked |
| 13 | External dependency decisions | V1.1-08: `EXTERNAL_DEPENDENCIES.md` (KEEP/INVESTIGATE per tool) |
| 14 | Validation status explicit | V1.1-06: matrix + append-only live log |
| 15 | Performance baselines reproducible | V1.1-07: `make bench`, 8 operations × 3 estate sizes |
| 16 | Installation tested from artifacts | V1.1-11: clean-container install/upgrade/uninstall on published v1.0.3/v1.0.4 |
| 17 | Contributor docs current | V1.1-12: architecture path, layer table, all how-tos |
| 18 | No unnecessary major feature | every commit is refactoring, documentation or bench tooling; the plan's non-goals are untouched |

## Release-candidate readiness

The working tree at `5dc9534` is the v1.1 release candidate. Remaining
maintainer steps (in order):

1. Push `main` — CI runs the full matrix (Linux, Windows, PostgreSQL
   service, audit, fuzz); that push is the final Windows gate.
2. Tag the release — `.github/workflows/release.yml` builds and publishes
   Linux + Windows artifacts with checksums.
3. Prepare release notes and bump the README status line per the release
   expectations in `CONTRIBUTING.md`.
4. After publishing, validate the artifacts per `INSTALL.md` and append
   the result to the validation log.
