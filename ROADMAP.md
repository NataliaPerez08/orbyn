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

- SSH collector for Linux.
- WinRM collector for Windows.
- OS details.
- Installed CPU/RAM capacity.
- Disk/filesystem inventory.
- Running process/service observations.
- Credential profile abstraction.

**Exit criterion:** authorized credentials enrich assets with host-level facts.

## v0.4 — Dependency mapping

- Active connection observations.
- DNS relationship evidence.
- Dependency graph model.
- Confidence/evidence model.
- Manual relationship confirmation.
- Graph export (JSON/Mermaid) via the CLI.

**Exit criterion:** Orbyn can identify and visualize meaningful asset-to-asset dependencies.

## v0.5 — Migration assessment

- Rule engine.
- Migration complexity score.
- Legacy/unsupported OS checks.
- Service and dependency risk.
- Application grouping primitives.
- Explainable findings and report output.

**Exit criterion:** inventory becomes an actionable migration assessment.

## v1.0 — Stable CLI product

- Stable CLI v1 (subcommand surface frozen with `orbyn <cmd> --help`).
- Command completion scripts (bash/zsh/fish).
- Audit trail surfaced through the CLI.
- Production installation documentation.
- Upgrade/migration mechanism for the database.
- Security review.
- Reproducible release artifacts.

**Exit criterion:** a CLI can be installed, upgraded and operated without
development tooling or undocumented manual steps.

A web/HTTP interface is a possible later add-on and is explicitly out of scope
for the core product.

## v1.1 — Integrations

- NetBox integration.
- Ansible inventory exporter.
- Terraform-friendly export format.
- vCenter collector/importer.
- Plugin/collector SDK definition.

**Exit criterion:** at least one third-party source-of-truth and one automation
export are demonstrated in CI without custom code.

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
