# Orbyn v1.1 Baseline

> **Purpose:** Reference point for detecting regressions during the v1.1
> consolidation refactor (see `ORBYN_V1_1_CONSOLIDATION_PLAN.md`, Priority 0).
> Re-record after significant milestones to keep comparisons meaningful.

## Baseline identity

```text
Orbyn version     1.0.4
Git commit        9f074c5cf1b1d95ac5939507b3b33f302b500f88
Commit subject    docs: add test-environment runs page with real captured output
Working tree      clean
Rust (stable)     rustc 1.98.1 (48a229cea 2026-09-01)
Cargo (stable)    cargo 1.98.1 (797e8a9bc 2026-08-05)
Rust (nightly)    cargo 1.101.0-nightly (f3865b2a4 2026-09-29) — fuzz only
MSRV (declared)   1.75
cargo-audit       0.22.2
cargo-deny        0.20.2
cargo-fuzz        0.13.2
Platform          linux x86_64
Date recorded     2026-10-05
```

## Verification results

All commands run with `--locked` against the commit above.

| Check                                          | Result |
| ---------------------------------------------- | ------ |
| `cargo fmt --check`                            | PASS   |
| `cargo clippy --locked --all-targets -- -D warnings` | PASS (0 warnings) |
| `cargo test --locked --all-targets`            | PASS (513 tests, 0 failed, 0 ignored) |
| `cargo build --locked --release`               | PASS   |
| `cargo audit`                                  | PASS (0 vulnerabilities, 251 crate dependencies, advisory DB: 1290 advisories) |
| `cargo deny check`                             | PASS (advisories, bans, licenses, sources all ok) |
| `cargo +nightly fuzz build`                    | PASS   |
| Fuzz smoke (7 targets, 500 runs each)          | PASS (no crashes) |
| PostgreSQL store tests (`ORBYN_PG_TEST_URL` set) | PASS (7 tests) |

### Test count breakdown

```text
513  total (unit + integration, default feature set)
  7  additional PostgreSQL store tests (run separately, env-gated)
```

### Release binary

```text
target/release/orbyn
size  13,539,336 bytes (~12.9 MiB)
```

## Fuzz smoke detail

Per-target smoke matching CI (`.github/workflows/ci.yml`, `fuzz` job):

```text
import          500 runs, max_len=4096    ok
parsing         500 runs, max_len=4096    ok
sanitize        500 runs, max_len=4096    ok
netbox_origin   500 runs, max_len=4096    ok
device_output   500 runs, max_len=8192    ok
structural      500 runs, max_len=4096    ok
nmap_xml        500 runs, max_len=16384   ok
```

## PostgreSQL test environment

```text
postgres:16 container (docker), 127.0.0.1:5432
ORBYN_PG_TEST_URL=postgres://orbyn:orbyn@127.0.0.1:5432/orbyn_test
```

Credentials are local throwaway test credentials only; they grant access to
nothing outside the disposable container used for this baseline run.

## Known state at baseline

- `src/main.rs` is ~112 KB and is the primary refactor target (Priority 1).
- No known failing checks at this commit. No pre-existing failures to document.
- The fuzz workspace is excluded from the main workspace and requires nightly.

## Regression policy during v1.1

After every architectural extraction, re-run at minimum:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

Compare against this document: test count must not decrease, no new warnings,
no new advisories. Any deviation must be explained in the change that
introduces it.
