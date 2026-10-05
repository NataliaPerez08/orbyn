# v1.1 Security regression pass (V1.1-09)

**Date:** 2026-10-06
**Scope:** re-verification of all security-sensitive behavior after the
V1.1-01/V1.1-02 refactoring moved command handlers out of `main.rs` into
`src/cli/commands/` and workflows into `src/app/` (v1.1 plan, Priority 7).
**Tree:** `6c63f14` (orbyn 1.0.4 working tree)

## Verification battery

| Check | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets -- -D warnings` | PASS (0 warnings) |
| `cargo test --locked --all-targets` | PASS (513 tests, 0 failed) |
| `cargo audit` | PASS (0 vulnerabilities, 251 crate dependencies, 1290 advisories in DB) |
| `cargo deny check` | PASS (advisories, bans, licenses, sources all ok) |
| Fuzz smoke (7 targets × 500 runs) | PASS (no crashes) |
| Shell-string scan (`sh -c` / shell interpolation in `src/`) | zero occurrences |

## Checklist vs enforcement vs proof

Each item from the plan's checklist, where it lives **after** the
refactoring, and the test that proves it still holds:

| Item | Enforcement (post-refactor home) | Proof |
|---|---|---|
| Secret propagation | `resolve_secret` in `src/cli/mod.rs`, 15 call sites across `cli/commands/` | `netbox_token_never_leaks_into_output` (e2e_integrations) |
| Environment sanitization | `.env` loaded from CWD only, never parent dirs (OY-01); `ORBYN_*_BIN` non-default warning — both stayed in `main.rs` bootstrap | `main.rs` unit tests |
| Subprocess argv | argv vectors only, no shell strings anywhere; all 28 subprocess sites route through `run_captured` | `snmp_community_from_stdin_reaches_the_walk` conf log (e2e_discovery); WinRM argv log (e2e_winrm) |
| Stdin credential handling | `-` reads secrets from stdin; WinRM password streamed to curl as config on stdin (`-K -`) | `winrm_discovery_collects_windows_host_over_wsman` asserts the password never appears in the curl argv log |
| Temporary files | SNMP `snmp.conf` 0600 + stale-dir cleanup (`collectors/snmp.rs`); NetBox token temp file long removed (OY-05) | snmp.rs unit tests; e2e_discovery |
| Database permissions | SQLite file 0600, parent dir 0700, WAL sidecar 0600 (`store/sqlite.rs`) — untouched by the refactor | store smoke tests |
| CSV injection | formula neutralization (`output/mod.rs` `csv_quote`) — untouched | `csv_neutralizes_formula_injection` (output/mod.rs tests) |
| HTTP response limits | `run_captured` stdout/stderr caps on every call; NetBox pagination + response-size limits | e2e_integrations; `process.rs` tests |
| Timeouts | per-subprocess timeout in `run_captured`; `RetryPolicy` replays only transient failures (`http.rs`) | e2e_failures; http.rs tests |
| TLS verification | WinRM HTTPS-only (5986); PG `sslmode` negotiation (`config.rs`) — both untouched | e2e_winrm; config.rs tests |
| Redaction | `Redactor::from_env()` + `add_value` at every secret entry point: `app/mod.rs` (PG URL password), `app/discovery.rs` (job errors), `cli/commands/{cloud,integrations}.rs` (provider/API tokens) | `postgres_unavailable_fails_cleanly_with_redacted_password` (e2e_failures); `discover_failure_redacts_cli_community` (e2e_discovery) |
| Cloud credentials | each provider handler registers its token/AK-SK with the redactor before any error path (`cli/commands/cloud.rs`) | e2e_cloud: token reaches curl on stdin, never printed |
| PostgreSQL credentials | URL password registered with the redactor in `app::open_store`; `ORBYN_PG_PASSWORD`/`PGPASSWORD` fallback so the password never rides argv (`config.rs`) | `postgres_unavailable_fails_cleanly_with_redacted_password` |

## Refactor-specific findings

- Handler bodies were moved **verbatim**; no security condition was
  rewritten. The redactor seams were re-verified at their new homes
  (`app/mod.rs`, `app/discovery.rs`, `cli/commands/cloud.rs`,
  `cli/commands/integrations.rs`) by locating every `Redactor`
  construction and `add_value` registration — none were dropped.
- The audit-trail path (`begin_audit`/`finish_audit_result`) moved to
  `app/mod.rs` and still records every mutating operation (verified live
  during V1.1-02: a `deps add` produced the expected audit event).
- Environment sanitization and the `ORBYN_*_BIN` guard never moved: they
  are bootstrap concerns and stayed in `main.rs` by design.

## Verdict

No security behavior was weakened by the refactoring. All checks pass;
the security-sensitive E2E suites (discovery secret handling, WinRM
password transport, NetBox/cloud token hygiene, failure redaction) run
green against the post-refactoring binary.
