# Contributing to Orbyn

Thanks for your interest in Orbyn.

Orbyn is intended to be community-driven. Contributions around collectors,
infrastructure platforms, dependency detection, assessment rules, documentation
and testing are welcome.

## Getting started

1. Fork the repository.
2. Install a Rust toolchain (rust 1.75+ via [rustup](https://rustup.rs)).
3. Ensure `nmap` is available for development against discovery targets.
4. Build and test:

   ```bash
   cargo build
   cargo test
   cargo clippy --all-targets -- -D warnings
   cargo audit
   ```

## Code conventions

- Orbyn is a Rust project. It is not a Go project, and references to Go in
  older documentation are stale.
- Orbyn is CLI-first. Every feature must be reachable (and testable) through a
  subcommand. Add to the `Command` enum in `src/main.rs`, fetch data through
  `crate::store::traits::Store`, and render through `crate::output`.
- New subcommands default to table output and expose `--format table|json|csv`.
  Logs go to stderr; sustained data goes to stdout.
- Domain types live in `src/domain/`. Collectors normalize their output into
  `crate::domain::Observation`. No collector writes directly to the database.
- Storage is behind `crate::store::traits::Store`; SQLite is the reference
  implementation under `src/store/sqlite.rs`.
- A new collector requires:
  - a `Collector` implementation returning normalized observations;
  - validation of targets (never shell-interpolate);
  - a fixture-backed test;
  - a database schema change only if the observation type is genuinely new.
- `cargo fmt` must be clean and `cargo clippy --all-targets -- -D warnings`
  must pass.

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
License 2.0 (see [LICENSE](LICENSE)).
