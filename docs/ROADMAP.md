# Roadmap

The roadmap describes product capability, not guaranteed release dates.

Release versions follow SemVer and are tagged (`v1.0.x` through `v1.0.4`,
then `v1.3.0` for the v1.1–v1.3 capability milestones). Headings
below mark capability milestones: their capabilities shipped incrementally
across releases, so a heading is not a promise that a matching release
exists.

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
OpenSSH Server feature, or the native WS-Man/WinRM transport over HTTPS).
NTLM/Kerberos authentication and the plaintext HTTP listener (5985) remain
possible later extensions of the same transport.

- SSH collector for Linux.
- WinRM collector for Windows — read-only PowerShell CIM queries over
  either transport: OpenSSH, or native WS-Man/WinRM (Basic auth over
  HTTPS through `curl`; the password is sourced from
  `ORBYN_WINRM_PASSWORD` or stdin, held in memory only, streamed to curl
  through stdin and never persisted, logged or exposed in argv).
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

**Status:** complete; the stable CLI is published as `v1.0.4`.

- Stable CLI v1 (subcommand surface frozen with `orbyn <cmd> --help`).
- Command completion scripts (bash/zsh/fish).
- Audit trail surfaced through the CLI.
- Production installation documentation.
- Upgrade/migration mechanism for the database.
- Security review.
- Reproducible release artifacts.

### v1.0 completion plan

- [x] Production installation documentation for Linux and Windows,
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

## Integrations milestone

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
`curl` for NetBox) in CI.

## Historical metrics and right-sizing milestone

**Status:** implemented. Snapshots ship with host-level discovery (3 samples
per SSH/WinRM probe); a week of history comes from the Prometheus importer
(`orbyn prometheus import`). Zabbix followed in Phase 3 (the milestone
required "Zabbix and/or Prometheus"; `orbyn zabbix import` is delivered —
see Phase 3 below). Periodic *scheduling* of collection is
intentionally out of scope for the CLI product: run the importer from
cron/systemd timers.

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

- Windows carry their temporal span; `orbyn metrics` reports span, sample
  confidence and right-sizing readiness (>= 168h of history with high
  confidence). Snapshots never qualify on their own.
- `orbyn prometheus import` pulls a week of CPU/RAM history
  (`/api/v1/query_range` through `curl`, node_exporter queries by default,
  overridable) and maps series onto assets by the `instance` label
  (IP or hostname). Re-imports are idempotent (one sample per asset and
  instant). A bearer token, when needed, travels through curl stdin
  (`-H @-`), never argv.
- Rule catalog 0.8.0 adds `rs.window-insufficient` (guidance when evidence
  is too weak), `rs.cpu-overprovisioned` / `rs.ram-overprovisioned`
  (p99 + 50% headroom suggestions, only from a ready window) and
  `rs.cpu-saturated` / `rs.ram-saturated` (p95 >= 90% warnings), plus
  `rs.swap-pressure`, `rs.utilization-trend` and `rs.storage-overprovisioned`.
  Every finding carries the observation window as evidence.

## Post-v1.0 — Evolution phases

The following phases are ordered by operational risk and product value. Cloud
adapters start with Proxmox and AWS to validate the common provider contract in
private infrastructure and a public cloud before expanding coverage.

### Phase 1 — Security and operational correctness

**Status:** implemented.

**Goal:** remove known security and reliability risks before expanding
integrations.

- Hide the SNMP community from process arguments.
- Add pagination and response-size limits to NetBox imports.
- Add timeouts and bounds to DNS resolution.
- Make duplicate-hostname resolution deterministic.
- Prevent collisions in Mermaid node identifiers.
- Improve compatibility with `ss`/`netstat` output variants.
- Keep the EOL operating-system table current and versioned.

**Exit criterion:** every critical known risk has an implementation, an
automated test, or an explicitly accepted exception.

### Phase 2 — Inventory integrity and integrations

**Status:** implemented (import round-trip, Ansible YAML, Terraform
metadata, virtualization metadata). Export back to NetBox is descoped by
design (Orbyn stays read-only against NetBox).

**Goal:** ensure import/export cycles do not silently lose inventory data.

- Preserve interfaces and services during `orbyn import`.
- Add Ansible YAML inventory export.
- Include complete supported metadata in Terraform export.
- Add optional export back to NetBox.
- Add virtualization metadata (host probes detect the hypervisor —
  `systemd-detect-virt`/DMI on Linux, `Win32_ComputerSystem` on Windows —
  and normalize it into a canonical vocabulary stored on capacity rows).
- Expand round-trip and format compatibility tests.

**Exit criterion:** exporting and importing an inventory preserves every
supported field without silent loss.

### Phase 3 — Evidence-based right-sizing

**Status:** implemented.

**Goal:** produce explainable recommendations with sufficient confidence.

- Implement CPU, RAM, swap and storage right-sizing rules.
- Define minimum observation windows.
- Reject recommendations with insufficient or invalid samples.
- Add Prometheus and Zabbix importers.
- Include evidence, confidence and rule version in every recommendation.
- Separate manual snapshots from periodic sampling.
- Compare utilization across observation windows.

**Exit criterion:** an asset with sufficient utilization data produces a
reproducible recommendation; an asset without sufficient data produces an
explicit warning.

Shipped in this phase:

- Rule catalog **0.8.0** adds `rs.swap-pressure` (sustained swap over a ready
  window: the working set does not fit in RAM), `rs.utilization-trend`
  (p95 grew >= 20% between the prior and the recent week, so the current week
  is not a stable baseline) and `rs.storage-overprovisioned` (a >= 100 GiB
  volume at <= 20% used). The storage rule is explicitly labelled a
  point-in-time observation rather than a utilization window, because disk
  usage is only sampled at discovery.
- Windows summarize swap alongside CPU and RAM, and a window spanning two
  full right-sizing weeks is split into a prior and a recent half
  (`orbyn metrics` shows the trend, and its CSV carries `prior_p95` /
  `recent_p95` rows). A single week produces no comparison.
- `orbyn prometheus import --swap-query` imports swap used, so the swap rule
  is reachable from Prometheus. A swap query the endpoint cannot answer is
  skipped with a warning rather than failing the import.
- `orbyn zabbix import` pulls a week of CPU, RAM and swap history through the
  Zabbix JSON-RPC API (`host.get`, `item.get`, `history.get` through `curl`),
  mapping hosts onto assets by interface IP then name. The API token travels
  inside the JSON-RPC envelope on curl stdin (`--data-binary @-`), never argv.
  Memory items are only accepted when Zabbix reports their unit as bytes.

### Phase 4 — Scale and operations

**Status:** complete.

**Goal:** support large inventories and long-running discovery operations.

- Remove N+1 queries from assessment and export.
- Add batch queries to the store.
- Enforce memory and response-size limits.
- Add bounded concurrent discovery with rate limiting.
- Persist complete discovery-job metrics.
- Add controlled retries for external APIs.
- Add performance tests with representative inventories.
- Document operational limits and partial-failure behavior.

**Exit criterion:** assessment, export and import have predictable time and
resource usage for representative large inventories.

Shipped in this phase:

- Discovery persists each completed target batch before accepting more work,
  bounding retained observations by the worker pool and one collector result.
- `tests/e2e_scale.rs` covers representative large inventories, bulk
  assessment/export reads, import round-trips, utilization history and
  bounded concurrent discovery.
- External API retries use bounded attempts and exponential backoff; response,
  subprocess output and import input are capped.
- Operational limits and partial-failure behavior are documented in the README.

### Phase 5 — Cloud and platform adapters

**Status:** complete. Proxmox VE, AWS, Huawei Cloud, OpenStack, GCP and Azure
use the common read-only adapter contract.

**Maturity:** all six adapters are **offline tested** (fixture-backed
end-to-end coverage). None is claimed **production validated**; live validation
is tracked in the validation matrix (Phase 4).

**Goal:** bring private infrastructure and public clouds into Orbyn's common
normalized model.

#### Delivery order

1. Proxmox VE.
2. AWS.
3. Huawei Cloud.
4. OpenStack.
5. GCP.
6. Azure.

Shipped in this phase:

- `src/integrations/cloud/mod.rs` defines shared cloud inventory types,
  `CloudProvenance` (provider, account, region, observation time), and a shared
  `CurlClient` that streams request headers (including credentials) to `curl`
  on stdin, caps requests/response size/timeouts, and replays only transient
  failures.
- `orbyn proxmox import` reads nodes, QEMU VMs and LXC containers from a
  Proxmox VE cluster (`/cluster/status`, `/cluster/resources`, `/nodes`).
  Interfaces and addresses come from the QEMU guest agent or the container API,
  falling back to the guest config (`netN`/`ipconfigN` static addresses) so
  stopped containers and agent-less VMs are still imported. Guest OS identity
  comes from the agent (`agent/get-osinfo`) or the config `ostype`; disk usage
  comes from the agent (`agent/get-fsinfo`) and the LXC `rootfs` volume; each
  node's active datastores (`/nodes/{node}/storage`) are attributed to the node.
  CPU/RAM allocation comes from the guest config (resources as fallback), and
  pools become the asset owner. Templates are skipped, and a guest with no
  address anywhere is skipped with a note. Authentication uses a Proxmox API
  token, streamed to `curl` on stdin.
- `orbyn aws import` reads EC2 instances, their elastic network interfaces, EBS
  volumes (as filesystems on their attached instance) and VPC/subnet resources
  (as assets keyed by their CIDR network address) from the EC2 query API, signed
  with SigV4 implemented from the specification (no SDK). The AWS account id is
  resolved from STS when permitted. Credentials come from
  `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` (or flags); the
  session token and signature travel to `curl` on stdin.
- `orbyn huawei import` reads ECS instances and their network interfaces from
  the Huawei Cloud ECS API, signed with the AK/SK `SDK-HMAC-SHA256` scheme
  implemented from the specification (no SDK). CPU/RAM capacity comes from the
  `flavors/detail` catalogue, and the project id is resolved from IAM
  (`v3/projects`, preferring the project named after the region) when
  `--project-id` is not given. Credentials come from `HUAWEICLOUD_SDK_AK`/
  `HUAWEICLOUD_SDK_SK` (or flags); the signature travels to `curl` on stdin.
- `orbyn openstack import` reads scoped Nova servers and flavors, with best-effort
  Cinder volumes, preserving server addresses, ports, metadata and availability
  zones as normalized assets, interfaces, capacity and filesystems.
- `orbyn gcp import` reads Compute Engine instances and persistent disks through
  the aggregated Compute API, including NICs, labels, zones and machine-type
  capacity.
- `orbyn azure import` reads ARM virtual machines, NICs, managed disks and
  virtual networks/subnets, including tags, regions and best-effort VM capacity.
- All adapters attach provenance tags (`cloud:<provider>`,
  `cloud-account:<id>`, `cloud-region:<region>`) to every imported asset,
  record a provider-named discovery job and an audit event, and never persist a
  credential. Imported rows feed the same assessment, graph and export
  pipelines as any other source.

#### Common adapter contract

- Read-only operation by default.
- Credentials obtained from profiles, agents or environment variables and
  never persisted by Orbyn.
- Pagination, rate limiting, retries and timeouts.
- Normalization into assets, services, interfaces, capacity, dependencies and
  tags.
- Provider, account/project/subscription, region and observation timestamp
  provenance.
- Offline fixtures and end-to-end tests with simulated APIs.
- Audit events for imports and errors without exposing secrets.

#### Provider coverage

- Proxmox VE: nodes, pools, VMs, containers, disks, interfaces and storage.
- AWS: accounts, regions, EC2, EBS, VPC, subnets, interfaces and tags.
- Huawei Cloud: projects, regions, ECS instances, flavors, EVS volumes, VPCs,
  subnets, interfaces and tags.
- OpenStack: projects, regions, instances, flavors, networks, ports, volumes
  and images.
- GCP: organizations/projects, regions/zones, Compute Engine, disks, networks,
  subnets and labels.
- Azure: tenants/subscriptions, resource groups, regions, VMs, managed disks,
  VNets, subnets and tags.

vCenter remains deferred until its transport and integration scope are defined.

**Exit criterion:** each adapter imports a representative read-only inventory,
preserves provider provenance and feeds the same graph, assessment and export
pipelines as existing discovery sources. Offline parser coverage is included;
live provider credentials are not required by the test suite.

### Future assessment capabilities

- Extended dependency telemetry such as flow logs/eBPF.
- Optional distributed collectors.

## v1.1–v1.3 — Application intelligence, planner, targets

**Status:** implemented. The capability milestones described in
[Orbyn — Roadmap v1.1 to v1.3.md](Orbyn%20—%20Roadmap%20v1.1%20to%20v1.3.md)
are complete and covered by deterministic fixtures, golden snapshots and
end-to-end tests:

- **v1.1 Application intelligence:** applications are first-class persisted
  entities inferred from dependency evidence with per-member confidence and
  explainability; manual curation overrides inference; application graphs,
  application-level assessment rollups and wave planning on persisted
  applications.
- **v1.2 Migration planner:** readiness (0–100, separate from complexity,
  every factor explainable), deterministic migration strategies
  (rehost/replatform/refactor/retain/retire, or `unknown` — never fabricated
  certainty), per-application plans persisted as audited artifacts with full
  provenance, and self-contained migration bundles.
- **v1.3 Target & cost intelligence:** provider-neutral versioned catalogs
  (capability and pricing data separate, embedded at build time),
  application-level fit scoring with explainable inputs, an estimated
  monthly cost baseline where unknown components are never silently zero,
  multi-cloud comparison and a recommendation engine where price never
  automatically decides.

Exit criteria for each milestone are mapped to concrete tests (see the
roadmap document); the deferred items — online pricing APIs, Huawei/OpenStack
catalog data, storage and managed-database cost calculation — are recorded as
known `not_calculated` paths, not silent gaps.
