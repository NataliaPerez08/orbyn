# Roadmap

The roadmap describes product capability, not guaranteed release dates.

## v0.1 — Network discovery foundation

Goal: produce a useful inventory from an authorized IP range, driven from the CLI.

- Rust CLI (clap) and SQLite foundation.
- Discovery job model.
- Safe target/CIDR validation.
- Nmap execution adapter.
- Nmap XML parser (quick-xml).
- Host reconciliation by IP/hostname.
- Ports and services persistence.
- Asset list/detail and service commands.
- CSV and JSON export.
- Table output for the terminal.
- Unit/integration tests.

**Exit criterion:** a user can scan an authorized subnet and inspect a persisted inventory.

## v0.2 — Inventory enrichment

**Status:** implemented. Exit criterion met: the inventory is useful beyond raw
port discovery.

- SNMP collector (system + interface MIB walk via `snmpwalk`).
- Interfaces and MAC addresses.
- Device classification.
- Environment, owner, criticality and tags.
- Import/export hooks (`orbyn import` / enriched `orbyn export`).
- Discovery history and changes (`orbyn jobs` CLI with per-job outcome).
- TUI decision: no interactive TUI for v0.2; the CLI remains the product
  surface. A TUI/web layer stays a possible later non-core add-on.

**Exit criterion:** inventory is useful beyond raw port discovery.

## v0.3 — Host-level discovery

**Status:** implemented for Linux (SSH) and Windows (PowerShell over the
OpenSSH Server feature). A native WS-Man/WinRM transport remains a follow-up
adapter over the same credential profile / command-transport abstraction.

- SSH collector for Linux.
- WinRM collector for Windows — ships as read-only PowerShell CIM queries
  over OpenSSH; native WinRM adapter pending.
- OS details.
- Installed CPU/RAM capacity.
- Disk/filesystem inventory.
- Running process/service observations (running services; full process
  listing later).
- Credential profile abstraction (ssh-agent / identity files; Orbyn stores
  no credentials).

**Exit criterion:** authorized credentials enrich assets with host-level facts.

## v0.4 — Dependency mapping

**Status:** implemented.

- Active connection observations (SSH `ss`/`netstat` and Windows
  `Get-NetTCPConnection` probes; remote endpoints reconciled into edges).
- DNS relationship evidence (`orbyn deps dns`; forward resolution of asset
  hostnames, low-confidence alias evidence).
- Dependency graph model.
- Confidence/evidence model (every edge carries its source and confidence;
  unconfirmed edges render dotted in Mermaid output).
- Manual relationship confirmation (`orbyn deps add/confirm/remove`).
- Graph export (JSON/CSV/Mermaid) via the CLI, with `--asset` scoped views.

**Exit criterion:** Orbyn can identify and visualize meaningful asset-to-asset dependencies.

## v0.5 — Migration assessment

**Status:** implemented.

- Rule engine (versioned catalog; `orbyn assess --rules` lists it).
- Migration complexity score (per-asset 0-100, averaged overall with a
  low/medium/high band; severity weights Info 2 / Warning 10 / High 25).
- Legacy/unsupported OS checks (EOL table for Ubuntu/CentOS/RHEL/Debian/SLES/
  Windows Server with vendor-support notes as evidence).
- Service and dependency risk (insecure/management exposure, dependency hubs,
  external endpoints, unconfirmed edges, missing capacity, near-full disks).
- Application grouping primitives (union-find over runtime/manual dependency
  edges; DNS alias evidence excluded).
- Explainable findings and report output (every finding carries rule id,
  severity, rationale and evidence; reports render as table/JSON/CSV).

**Exit criterion:** inventory becomes an actionable migration assessment.

## v1.0 — Stable CLI product

**Status:** complete; the stable CLI is published as `v1.0.2`.

- Stable CLI v1 (subcommand surface frozen with `orbyn <cmd> --help`).
- Command completion scripts (bash/zsh/fish).
- Audit trail surfaced through the CLI.
- Production installation documentation.
- Upgrade/migration mechanism for the database.
- Security review.
- Reproducible release artifacts.

### v1.0 completion plan

- [x] Production installation documentation for Linux, macOS and Windows,
   including dependencies, configuration, completions, verification, upgrade and
   uninstall procedures.
- [x] Database upgrade verification: existing SQLite databases must migrate
   automatically when opened, with a documented backup and rollback procedure
   and integration coverage for an older schema.
- [x] Complete operational audit trail for mutating CLI operations, surfaced by an
   `orbyn audit` command while preserving discovery job history.
- [x] Release hardening: pin the Rust toolchain, build from `Cargo.lock`, verify
   artifact naming and checksums, and publish build provenance where supported.
- [x] Final security and documentation review, including dependency audit and
   consistency between `SECURITY.md`, `THREAT_MODEL.md` and the implementation.

**v1.0 completion checklist:**

- A user can install Orbyn without Rust or development tooling.
- An existing database upgrades without undocumented manual steps.
- Operational audit events are queryable from the CLI.
- CI validates formatting, linting, tests and release builds.
- Release artifacts have stable names, checksums and a pinned toolchain.
- Security documentation matches the current credential and subprocess
  handling.

**Exit criterion:** a CLI can be installed, upgraded and operated without
development tooling or undocumented manual steps.

A web/HTTP interface is a possible later add-on and is explicitly out of scope
for the core product.

## v1.1 — Integrations

**Status:** implemented (NetBox import + Ansible/Terraform exporters + plugin
SDK). vCenter is deferred to a follow-up (large SOAP/session client; the exit
criterion only requires one source-of-truth and one automation export).

- NetBox integration — read-only source-of-truth importer (`orbyn netbox
  import`): devices + virtual machines via the REST API through `curl`, token
  streamed through stdin to `curl` (never written to a file or exposed in
  argv/logs).
- Ansible inventory exporter (`orbyn export --format ansible`, INI grouping by
  device class / environment / tags).
- Terraform-friendly export (`orbyn export --format terraform`, HCL
  `locals.orbyn_inventory`).
- vCenter collector/importer — deferred (BACKLOG).
- Plugin/collector SDK definition — documented `Collector` contract,
  `examples/custom_collector.rs`, and PLUGINS.md.

**Exit criterion:** demonstrated by the automated end-to-end suite (fake
`curl` for NetBox) rather than a CI pipeline, which is not yet configured.

## v1.2 — CPU/RAM utilization

- Snapshot resource collector.
- Periodic CPU/RAM observations.
- Historical metrics ingestion interface.
- Zabbix and/or Prometheus integration.
- Average/max/p95/p99 aggregation.
- Observation-window quality indicator.
- First right-sizing rules.

**Critical rule:** snapshots alone cannot produce a high-confidence right-sizing recommendation.

**Exit criterion:** an asset with one meeting week of utilization can produce an
explainable (evidence + rule version) right-sizing recommendation.

## v1.3+ — Advanced assessment

- Cloud SKU recommendation adapters.
- AWS/Azure/GCP/Huawei target catalogs.
- Cost comparison.
- Application-wave planning.
- Extended dependency telemetry such as flow logs/eBPF.
- Optional distributed collectors.
