# Backlog

Priorities use `P0` (blocking), `P1` (important), `P2` (useful), and `P3` (later).

Orbyn is a CLI tool. Server/web concepts apply **only** if a future web layer is
added; today the product surface is `orbyn` subcommands.

## Foundation

- [ ] **P0** Replace placeholder module path with the final GitHub organization/repository.
- [x] **P0** Add database schema versioning/migration runner (sqlx migrations).
- [x] **P0** Add structured logging (tracing, stderr, `-v`/`-vv`).
- [x] **P0** Add CLI framework (clap) and config resolution (env + `--db`).
- [x] **P1** Add repository interfaces between domain and SQLite.
- [x] **P1** Add output format layer (table / JSON / CSV).
- [x] **P1** Add test suite: unit + integration (store/schema) + end-to-end
  (real binary against fake collector binaries).
- [ ] **P1** Add CI: fmt, clippy, test, build.
- [ ] **P1** Add release workflow (binary artifacts + checksums).
- [ ] **P1** Add shell completion scripts (bash/zsh/fish).
- [ ] **P2** Add Docker image.

## Discovery v0.1

- [x] **P0** Define `DiscoveryJob` domain model.
- [x] **P0** Validate IPv4/IPv6/CIDR targets.
- [x] **P0** Add explicit maximum scan scope defaults (unrestricted scopes rejected).
- [x] **P0** Implement Nmap command adapter without shell interpolation.
- [x] **P0** Parse Nmap XML fixtures (quick-xml).
- [x] **P0** Normalize host/port/service observations.
- [x] **P0** Persist/reconcile assets and services.
- [x] **P1** Job status and history CLI (`orbyn jobs`).
- [x] **P1** Asset detail command (`orbyn asset <id-or-ip>`).
- [x] **P1** Services command (`orbyn services <id-or-ip>`).
- [x] **P1** CSV/JSON exports (`orbyn export`).
- [x] **P1** Capture scan metadata and errors (job audit records).
- [ ] **P2** Configurable Nmap profiles.
- [x] **P2** Nmap XML fixtures test coverage.

## Inventory enrichment

- [x] **P1** SNMP collector (system + interface MIB walk via snmpwalk).
- [x] **P1** Interfaces/MAC addresses.
- [x] **P1** Device classification.
- [x] **P1** Environment, owner, criticality and tags (`orbyn annotate`).
- [x] **P1** Import/export hooks (`orbyn import`).
- [x] **P1** SSH Linux collector.
- [ ] **P1** WinRM Windows collector (native WS-Man transport; v0.3 covers Windows hosts via PowerShell-over-SSH).
- [ ] **P2** Virtualization metadata.
- [x] **P2** Disk/filesystem inventory.

## Dependencies

- [x] **P1** Dependency edge schema.
- [x] **P1** Evidence source and confidence model.
- [x] **P1** Dependency persistence + graph CLI.
- [x] **P1** Active connection collector (SSH/Windows probes, reconciled into edges).
- [ ] **P2** Firewall/flow-log importer.
- [x] **P2** Mermaid graph export.
- [ ] **P3** eBPF-based telemetry.

## Assessment

- [x] **P1** Rule engine over the normalized domain (versioned catalog).
- [x] **P1** Migration complexity score (per-asset + overall band).
- [x] **P1** Legacy/unsupported OS checks.
- [x] **P1** Service and dependency risk rules.
- [x] **P1** Application grouping primitives (connected components).
- [x] **P1** Explainable findings and report output.
- [ ] **P2** Additional rule packs (databases, middleware banners, certificates).
- [ ] **P2** Assessment diffing between runs.
- [ ] **P3** User-defined rules / rule pack loading.

## CPU/RAM and right-sizing

- [x] **P1** Linux CPU/RAM capacity collector.
- [x] **P1** Windows CPU/RAM capacity collector (PowerShell-over-SSH).
- [ ] **P1** Resource snapshot collector.
- [ ] **P1** Periodic metric sampling.
- [ ] **P1** p95/p99 aggregation.
- [ ] **P1** Observation quality/confidence model.
- [ ] **P2** Prometheus importer.
- [ ] **P2** Zabbix importer.
- [ ] **P2** Right-sizing rules with evidence.
- [ ] **P3** Cloud SKU adapters.

## Security

- [x] **P0** Document authorized-use requirement.
- [x] **P0** Prevent unrestricted `0.0.0.0/0` scans by default.
- [x] **P0** Ensure scan targets are passed as process arguments, never shell strings.
- [x] **P1** Credential storage design (v0.3 decision: no credential storage; ssh-agent/identity-file credential profiles, no secrets held or logged).
- [ ] **P1** Secret redaction.
- [ ] **P1** Threat model.
- [ ] **P2** RBAC (only if a web/server layer is introduced).