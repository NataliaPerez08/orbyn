# Roadmap

The roadmap describes product capability, not guaranteed release dates.

## v0.1 — Network discovery foundation

Goal: produce a useful inventory from an authorized IP range.

- Rust (tokio/axum) API and SQLite foundation.
- Discovery job model.
- Safe target/CIDR validation.
- Nmap execution adapter.
- Nmap XML parser.
- Host reconciliation by IP/hostname.
- Ports and services persistence.
- Asset list/detail API.
- CSV and JSON export.
- CLI command for a discovery job.
- Unit/integration tests.

**Exit criterion:** a user can scan an authorized subnet and inspect a persisted inventory.

## v0.2 — Inventory enrichment

- SNMP collector.
- Interfaces and MAC addresses.
- Device classification.
- Environment, owner, criticality and tags.
- Import/export hooks.
- Discovery history and changes.
- Basic web UI or TUI decision.

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
- Mermaid/JSON graph export.

**Exit criterion:** Orbyn can identify and visualize meaningful asset-to-asset dependencies.

## v0.5 — Migration assessment

- Rule engine.
- Migration complexity score.
- Legacy/unsupported OS checks.
- Service and dependency risk.
- Application grouping primitives.
- Explainable findings and report output.

**Exit criterion:** inventory becomes an actionable migration assessment.

## v1.0 — Stable discovery product

- Stable API v1.
- Authentication for server deployments.
- Roles/permissions.
- Job scheduling.
- Audit trail.
- Production installation documentation.
- Upgrade/migration mechanism for the database.
- Security review.
- Reproducible release artifacts.

**Exit criterion:** a deployment can be installed, upgraded and operated without
development tooling or undocumented manual steps.

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
