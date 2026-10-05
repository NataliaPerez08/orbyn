# Contributing to Orbyn

Thanks for your interest in Orbyn.

Orbyn is intended to be community-driven. Contributions around collectors,
infrastructure platforms, dependency detection, assessment rules, documentation
and testing are welcome.

## Getting started

1. Fork the repository.
2. Install a Rust toolchain — the minimum supported version is **Rust 1.75**
   (`rust-version` in `Cargo.toml`); CI currently builds on 1.98.1.
3. External tools (`nmap`, `snmpwalk`, `ssh`, `curl`, `dig`) are needed only to
   collect from real systems. The test suites run the real binary against
   script fakes via `ORBYN_<TOOL>_BIN`, so no tools are needed to develop or
   contribute.
4. Build and verify:

   ```bash
   cargo build
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test --all-targets
   cargo audit
   ```

## Repository architecture

A change should follow the layers top-down; nothing skips a layer:

```text
CLI (src/cli/)                 argument definitions, handlers, terminal output
 ↓
Application workflow (src/app/)  clap-free use cases: store open, audit, persist
 ↓
Collector / Integration          external systems → normalized observations
 ↓
Domain (src/domain/)            the normalized model (Asset, Observation, ...)
 ↓
Store (src/store/)              persistence behind the Store trait
 ↓
Assessment / Metrics / Waves     pure functions over the domain + store reads
 ↓
Output (src/output/)            table / json / csv rendering
```

Where things live after the v1.1 restructuring:

| Layer | Location |
| --- | --- |
| CLI arguments (clap) | `src/cli/args.rs` — the `Command` enum and action enums |
| Command handlers | `src/cli/commands/<family>.rs` — validation, warnings, output |
| CLI-support helpers | `src/cli/mod.rs` — secret resolution, plain-HTTP detection |
| Application workflows | `src/app/` — store opening, audit begin/finish, inventory/discovery/deps/assessment workflows; **no clap, never references `cli`** |
| Collectors | `src/collectors/` — implement the `Collector` trait |
| Integrations | `src/integrations/` — importers and cloud adapters |
| Assessment | `src/assessment/` — versioned rule catalog, grouping |
| Store | `src/store/` — `traits.rs` (contract), `sqlite.rs`, `postgres.rs`, shared `rows.rs` |

Full detail: [ARCHITECTURE.md](ARCHITECTURE.md).

## Test commands

- **Unit + E2E:** `cargo test --all-targets` (513 tests; the E2E suites drive
  the real binary against fake tools — Unix-only, they compile empty on
  Windows).
- **PostgreSQL store suite:** `cargo test --test postgres_store` with
  `ORBYN_PG_TEST_URL` set; skips itself otherwise. CI runs it against a
  `postgres:16` service.
- **Golden stability:** `tests/golden.rs` pins import → graph → assess →
  export output byte-for-byte. Regenerate after an *intended* change with
  `ORBYN_GOLDEN_UPDATE=1 cargo test --test golden`, then review the diff.
- **Fuzz smoke:** `make fuzz-smoke` (nightly toolchain required).
- **Benchmarks:** `make bench` rewrites `docs/PERFORMANCE.md` from a
  deterministic estate (Linux + GNU `time` required).

## How to add a collector

1. Implement `Collector` in `src/collectors/<name>.rs`, returning normalized
   `crate::domain::Observation` values. Never write to the database.
2. Validate targets before invoking anything; pass subprocess arguments as
   argv vectors, never shell strings, and run through
   `crate::process::run_captured` (timeout + capture caps).
3. Wire the CLI: add a variant to `DiscoveryCollector` in
   `src/cli/args.rs` and construct the collector in
   `src/cli/commands/discover.rs`.
4. Add a fixture-backed test: a fake binary via `ORBYN_<TOOL>_BIN` plus an
   end-to-end test in `tests/`.
5. A schema change is needed only if the observation type is genuinely new —
   then ship both dialects (see migrations below).

## How to add an integration

1. Put the client in `src/integrations/<name>.rs`. All HTTP goes through the
   shared plumbing (`src/http.rs` retry/status handling on top of
   `run_captured`) — never a raw subprocess call.
2. Secrets resolve from a dedicated env var or `-` (one line from stdin) via
   `crate::cli::resolve_secret`, travel in request bodies or curl config on
   stdin, and are registered with the `Redactor` before any error path.
3. Normalize into the domain (assets/interfaces/services/observations) and
   persist through `crate::app::inventory` workflows, wrapping the run in
   `begin_audit`/`finish_audit_result` and a provider-named discovery job.
4. Expose it as `orbyn <source> import ...` (see the Conventions section of
   [cli.md](cli.md)).
5. Test with a fake `curl` (`ORBYN_CURL_BIN`) serving recorded responses:
   unit tests for parsing/signing plus an E2E suite in `tests/`.

## How to add an assessment rule

1. Add the rule to the catalog in `src/assessment/rules.rs`: a `Rule` entry
   (stable `id`, `description`, evaluator function) appended to `catalog()`.
2. Evaluators receive `&AssessmentInput` and push `Finding`s carrying rule id,
   severity, rationale and evidence (including the observation window where
   relevant).
3. Bump `RULES_VERSION` in `src/assessment/mod.rs` — findings stay comparable
   across releases only if the version moves with the catalog.
4. Extend the golden fixtures if the rule changes pipeline output, and add a
   focused unit test for the evaluator (insufficient-data behavior included).

## How to add a migration

1. Add the next numbered file to **both** `migrations/` (SQLite) and
   `migrations/postgres/` (PostgreSQL dialects differ: INTEGER vs BIGINT,
   REAL vs DOUBLE PRECISION, etc.).
2. Migrations apply automatically on database open; there is no migration
   command and no down-migration. Never edit an applied migration — add a
   new one.
3. Extend the `Store` trait in `src/store/traits.rs`, implement it in both
   `sqlite.rs` and `postgres.rs`, and share row decoding through
   `src/store/rows.rs`.
4. `tests/schema_migrations.rs` and the store suites must stay green on both
   backends.

## How to update documentation

Each document has one job — put changes where they belong:

| Document | Owns |
| --- | --- |
| `README.md` | current capabilities, quick tour |
| `docs/ARCHITECTURE.md` | current technical design (update in the same change as the code) |
| `docs/ROADMAP.md` | direction and milestone history |
| `docs/BACKLOG.md` | open work parking lot |
| `docs/KnowIssues.md` | known problems and deferrals |
| `docs/VALIDATION_MATRIX.md` | per-integration validation status + append-only live log |
| `docs/PERFORMANCE.md` | benchmark results (regenerate with `make bench`, don't hand-edit numbers) |
| `docs/cli.md` | CLI reference and conventions |
| `RELEASE_NOTES_v*.md` | release history |

Historical plans stay in the repo with their `Historical document` banner —
never present them as current state. A doc change that describes new behavior
belongs in the same commit as the behavior.

## Release expectations

- The full battery must be green: fmt, clippy `-D warnings`, all tests,
  `cargo audit`, `cargo deny check`, fuzz smoke, and the PostgreSQL suite
  against a live server.
- Update `RELEASE_NOTES_v<version>.md` and the README status line.
- Releases are tag-triggered: `.github/workflows/release.yml` builds Linux
  and Windows artifacts and their checksums. The release binary requires
  glibc ≥ 2.39 (see [INSTALL.md](INSTALL.md)).
- Validate the published artifacts per the INSTALL.md walkthrough before
  announcing, and record the result in the validation log.

## EOL OS table cadence

`src/assessment/eol_os.csv` is the end-of-life OS table. It is embedded into
the binary at build time, parsed with loud failure on malformed input, and the
`EOL table version` evidence shown by `os.eol` findings is derived from the
file itself. OSes reach end of life continuously, so:

- Review the table quarterly.
- Bump the `version` line to the review month (`YYYY-MM`) even when no entry
  changes.
- A unit test (`eol_table_version_is_recent`) fails when the version is more
  than six months old, so a stale table cannot ship silently.

## Security

Discovery is security-sensitive. Read [SECURITY.md](SECURITY.md) before
contributing collectors. By default:

- targets are validated and restrictable;
- `0.0.0.0/0`-style unrestricted scans are rejected;
- subprocess arguments are sanitized;
- credentials are not logged.

## Reporting issues

Use the issue tracker. Security issues should follow the process in
[SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the Apache
License 2.0 (see [LICENSE][license]).

[license]: https://github.com/NataliaPerez08/orbyn/blob/main/LICENSE
