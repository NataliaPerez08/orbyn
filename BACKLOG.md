# Backlog

Priorities use `P0` (blocking), `P1` (important), `P2` (useful), and `P3` (later).

## Foundation

- [ ] **P0** Replace placeholder Go module path with the final GitHub organization/repository.
- [ ] **P0** Add database schema versioning/migration runner.
- [ ] **P0** Add structured logging.
- [ ] **P0** Add graceful HTTP shutdown.
- [ ] **P1** Add configuration package and validation.
- [ ] **P1** Add repository interfaces between domain and SQLite.
- [ ] **P1** Add CI: fmt, vet, test, build.
- [ ] **P1** Add release workflow.
- [ ] **P2** Add Docker image.

## Discovery v0.1

- [ ] **P0** Define `DiscoveryJob` domain model.
- [ ] **P0** Validate IPv4/IPv6/CIDR targets.
- [ ] **P0** Add explicit maximum scan scope defaults.
- [ ] **P0** Implement Nmap command adapter without shell interpolation.
- [ ] **P0** Parse Nmap XML fixtures.
- [ ] **P0** Normalize host/port/service observations.
- [ ] **P0** Persist/reconcile assets and services.
- [ ] **P1** Job status API.
- [ ] **P1** Asset detail endpoint.
- [ ] **P1** Services endpoint.
- [ ] **P1** CSV/JSON exports.
- [ ] **P1** Capture scan metadata and errors.
- [ ] **P2** Configurable Nmap profiles.

## Inventory enrichment

- [ ] **P1** SNMP collector.
- [ ] **P1** Interfaces/MAC addresses.
- [ ] **P1** SSH Linux collector.
- [ ] **P1** WinRM Windows collector.
- [ ] **P2** Virtualization metadata.
- [ ] **P2** Disk/filesystem inventory.

## Dependencies

- [ ] **P1** Dependency edge schema.
- [ ] **P1** Evidence source and confidence.
- [ ] **P1** Active connection collector.
- [ ] **P2** Firewall/flow-log importer.
- [ ] **P2** Mermaid dependency export.
- [ ] **P3** eBPF-based telemetry.

## CPU/RAM and right-sizing

- [ ] **P1** Linux CPU/RAM capacity collector.
- [ ] **P1** Windows CPU/RAM capacity collector.
- [ ] **P1** Resource snapshot collector.
- [ ] **P1** Periodic metric sampling.
- [ ] **P1** p95/p99 aggregation.
- [ ] **P1** Observation quality/confidence model.
- [ ] **P2** Prometheus importer.
- [ ] **P2** Zabbix importer.
- [ ] **P2** Right-sizing rules with evidence.
- [ ] **P3** Cloud SKU adapters.

## Security

- [ ] **P0** Document authorized-use requirement.
- [ ] **P0** Prevent unrestricted `0.0.0.0/0` scans by default.
- [ ] **P0** Ensure scan targets are passed as process arguments, never shell strings.
- [ ] **P1** Credential storage design.
- [ ] **P1** Secret redaction.
- [ ] **P1** Audit logs.
- [ ] **P1** Threat model.
- [ ] **P2** RBAC.
