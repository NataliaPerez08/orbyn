# Backlog

Priorities use `P0` (blocking), `P1` (important), `P2` (useful), and `P3` (later).

Orbyn is a CLI tool. Server/web concepts apply **only** if a future web layer is
added; today the product surface is `orbyn` subcommands.

## Foundation

- [x] **P0** Set final GitHub organization/repository (`NataliaPerez08/orbyn`) as the
  crate repository, README clone URL and git remote (no Go module path remains
  after the Rust port).
- [x] **P0** Add database schema versioning/migration runner (sqlx migrations).
- [x] **P0** Add structured logging (tracing, stderr, `-v`/`-vv`).
- [x] **P0** Add CLI framework (clap) and config resolution (env + `--db`).
- [x] **P1** Add repository interfaces between domain and SQLite.
- [x] **P1** Add output format layer (table / JSON / CSV).
- [x] **P1** Add test suite: unit + integration (store/schema) + end-to-end
  (real binary against fake collector binaries).
- [x] **P1** Add CI: fmt, clippy, test, build (GitHub Actions, `.github/workflows/ci.yml`).
- [x] **P1** Add release workflow (binary artifacts + checksums; tag-triggered
  matrix for Linux/macOS/Windows in `.github/workflows/release.yml`).
- [x] **P1** Add shell completion scripts (bash/zsh/fish) via `orbyn completions <shell>`.
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
- [x] **P1** WinRM Windows collector (native WS-Man transport over HTTPS via curl; Basic auth with the password streamed to curl through stdin).
- [x] **P2** Virtualization metadata.
- [x] **P2** Disk/filesystem inventory.

## Integrations (v1.1)

- [x] **P1** NetBox source-of-truth importer (devices + virtual machines via REST).
- [x] **P1** Ansible inventory exporter (INI, configurable grouping).
- [x] **P1** Terraform-friendly export (HCL `locals.orbyn_inventory`).
- [x] **P1** Plugin/collector SDK definition (trait contract + example + PLUGINS.md).
- [ ] **P2** vCenter collector/importer (deferred: SOAP session client).
- [ ] **P2** NetBox export (write Orbyn inventory back to NetBox) — descoped
  by design: Orbyn stays read-only against NetBox (see PLAN_ISSUES.md).
- [x] **P2** Ansible YAML inventory format (`orbyn export --format ansible-yaml`).
- [x] **P3** Terraform `import` block generation (`orbyn export --format terraform --tf-import <type>`).

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
- [x] **P1** Resource snapshot collector (Linux + Windows ssh probes emit 3 samples).
- [x] **P1** Periodic metric sampling (samples persisted as observations to `metric_samples`).
- [x] **P1** p95/p99 aggregation (`orbyn metrics`, avg/p95/p99/peak).
- [x] **P1** Observation quality/confidence model (`SampleConfidence` on count + validity).
- [x] **P1** Observation-window quality indicator (span + confidence; right-sizing
  readiness requires >= 168h with high confidence).
- [x] **P2** Prometheus importer (`orbyn prometheus import`, idempotent re-imports).
- [x] **P2** Zabbix importer.
- [x] **P2** Right-sizing rules with evidence (catalog 0.8.0: `rs.*`).
- [ ] **P3** Cloud SKU adapters.

## Security

- [x] **P0** Document authorized-use requirement.
- [x] **P0** Prevent unrestricted `0.0.0.0/0` scans by default.
- [x] **P0** Ensure scan targets are passed as process arguments, never shell strings.
- [x] **P1** Credential storage design (v0.3 decision: no credential storage; ssh-agent/identity-file credential profiles, no secrets held or logged).
- [x] **P1** Secret redaction (value-based `Redactor` in `src/redact.rs`, applied to
  discovery/NetBox errors before logging and job audit records).
- [x] **P1** Threat model (STRIDE, `THREAT_MODEL.md`, linked from SECURITY.md).
- [ ] **P2** RBAC (only if a web/server layer is introduced).

## Post-v1.0 execution phases

### Phase 1 — Security and operational correctness

- [x] **P1** Hide the SNMP community from process arguments.
- [x] **P1** Add NetBox pagination and response-size limits.
- [x] **P2** Add DNS timeouts and resolution bounds.
- [x] **P2** Make duplicate-hostname resolution deterministic.
- [x] **P2** Prevent Mermaid node-id collisions.
- [x] **P2** Support additional `ss`/`netstat` output variants.
- [x] **P2** Version the EOL operating-system table; maintain the update cadence.

### Phase 2 — Inventory integrity and integrations

- [x] **P1** Preserve interfaces and services during `orbyn import`.
- [x] **P2** Add Ansible YAML inventory export.
- [x] **P2** Include complete supported metadata in Terraform export.
- [ ] **P2** Add optional export to NetBox — descoped by design (read-only
  against NetBox, see PLAN_ISSUES.md).
- [x] **P2** Add virtualization metadata (host probes detect the hypervisor
  into a canonical vocabulary on capacity rows; `orbyn capacity` renders it).
- [x] **P1** Add import/export round-trip coverage for every supported field.

### Phase 3 — Evidence-based right-sizing

- [x] **P1** Add CPU, RAM, swap and storage right-sizing rules. (CPU/RAM shipped
  in v1.2 catalog 0.7.0; `rs.swap-pressure` and `rs.storage-overprovisioned`
  shipped in catalog 0.8.0.)
- [x] **P1** Define minimum observation windows and insufficient-data behavior.
  (168h + high confidence; `rs.window-insufficient` is the explicit warning.)
- [x] **P2** Add Prometheus importer.
- [x] **P2** Add Zabbix importer.
- [x] **P1** Include evidence, confidence and rule version in recommendations.
- [x] **P2** Add utilization-window comparison. (A window spanning two full
  right-sizing weeks is split into prior and recent halves; `rs.utilization-trend`
  fires on >= 20% p95 growth between them.)

### Phase 4 — Scale and operations

- [x] **P1** Remove N+1 queries from assessment and export (bulk reads,
  one query per table).
- [x] **P1** Add batch queries to the store.
- [x] **P2** Add bounded concurrent discovery and rate limiting
  (`--concurrency`, `--rate-limit`).
- [x] **P2** Add response and memory limits for large inventories (NetBox and
  collector response caps, capped import input, incremental discovery
  persistence; audit OY-08/OY-19).
- [x] **P2** Persist complete discovery-job metrics (filesystems, running
  services, connections per job).
- [x] **P2** Add controlled retries for external APIs.
- [x] **P2** Add performance tests with representative inventories.

### Phase 5 — Cloud and platform adapters

The first cloud adapter milestone is Proxmox followed by AWS. All adapters
must be read-only by default, preserve provider provenance, avoid credential
storage, support pagination/rate limiting/timeouts, and include offline
fixtures plus end-to-end tests.

- [x] **P1** Define shared cloud-provider inventory types
  (`CloudProvenance` + `CloudInventory` + shared `CurlClient`).
- [x] **P1** Implement Proxmox VE adapter: nodes, node storage/datastores, QEMU
  VMs, LXC containers, interfaces (guest agent / container API / config
  fallback), guest OS identity, filesystems (agent `get-fsinfo` + LXC `rootfs`)
  and CPU/RAM capacity, with pools mapped to the asset owner and templates
  skipped. (`orbyn proxmox import`.)
- [x] **P1** Implement AWS adapter: EC2 instances, elastic network interfaces,
  EBS volumes (as filesystems on their attached instance), VPCs and subnets
  (as assets keyed by their CIDR network address), tags and STS account
  provenance. (`orbyn aws import`.)
- [x] **P1** Implement Huawei Cloud adapter: ECS instances, network interfaces,
  flavor CPU/RAM capacity, EVS volumes (as filesystems on their attached
  server), VPC/subnet resources (as assets keyed by their CIDR network
  address) and IAM project provenance. (`orbyn huawei import`.)
- [ ] **P2** Implement OpenStack adapter: projects, regions, instances, flavors,
  networks, ports, volumes and images.
- [ ] **P2** Implement GCP adapter: projects, regions/zones, Compute Engine,
  disks, networks, subnets and labels.
- [ ] **P2** Implement Azure adapter: tenants/subscriptions, resource groups,
  regions, VMs, managed disks, VNets, subnets and tags.
- [x] **P2** Add provider provenance to assets and discovery jobs.
  (Provider/account/region tags on assets, a provider-named job; a dedicated
  provenance column remains a possible follow-up.)
- [x] **P2** Add cloud adapter audit events and secret-redaction coverage.
- [x] **P2** Keep vCenter deferred until transport and scope are defined.
