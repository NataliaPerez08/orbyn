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
  matrix for Linux/Windows in `.github/workflows/release.yml`).
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

## Integrations milestone

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
- [x] **P3** Cloud SKU matching (`orbyn sku-match`, static catalogs for
  AWS/Azure/GCP; on-demand pricing deliberately not embedded).

- [ ] **P3** Record file/stdin `import` in the audit trail for parity with
  API imports (currently job-history only; see docs/cli.md variances).

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
  in the metrics milestone (catalog 0.7.0); `rs.swap-pressure` and
  `rs.storage-overprovisioned`
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
- [x] **P2** Implement OpenStack adapter: projects, regions, instances, flavors,
  networks, ports, volumes and images.
- [x] **P2** Implement GCP adapter: projects, regions/zones, Compute Engine,
  disks, networks, subnets and labels.
- [x] **P2** Implement Azure adapter: tenants/subscriptions, resource groups,
  regions, VMs, managed disks, VNets, subnets and tags.
- [x] **P2** Add provider provenance to assets and discovery jobs.
  (Provider/account/region tags on assets, a provider-named job; a dedicated
  provenance column remains a possible follow-up.)
- [x] **P2** Add cloud adapter audit events and secret-redaction coverage.
- [x] **P2** Keep vCenter deferred until transport and scope are defined.

## v1.4 — Native discovery (ROADMAP_V2)

Baseline and contracts come out of Sprint 0
([BASELINE_AUDIT.md](BASELINE_AUDIT.md),
[ADR-0001](ADR-0001-discovery-backend-contract.md)): the `Collector` trait is
the backend contract, `--collector` is the selector, and the target parser
with scope floors already exists.

- [x] **P0** Ratify the discovery backend contract (ADR-0001; no new
  abstraction — the existing `Collector` trait stands).
- [x] **P0** Target parser with scope policy (shipped in v0.1; re-verified by
  the audit).
- [x] **P0** Native TCP-connect collector behind `Collector` (top-ports sweep,
  bounded concurrency, connect timeout, basic banner grab, service naming,
  CIDR expansion with a hard host cap; IPv6 ranges refused beyond the cap).
  (`src/collectors/native.rs`.)
- [x] **P0** `--collector native` selector wired through `discover`.
- [x] **P1** ICMP liveness prefetch (system `ping`, multi-host targets only,
  clean no-reply skips like nmap's default host discovery, errors fail open;
  `ORBYN_NATIVE_LIVENESS=0` sweeps everything). ARP liveness stays deferred
  (needs a raw-socket privilege story).
- [x] **P1** Optional reverse DNS for discovered hosts (`dig +short -x` via the
  shared `dns::resolve_ptr`, graceful without dig;
  `ORBYN_NATIVE_REVERSE_DNS=0`).
- [ ] **P1** Recorded lab comparison native-vs-nmap on an authorized network
  (hosts found, ports found, services named, runtime) — gates any default
  flip.
- [x] **P2** Per-feature parity matrix published in the docs
  (NMAP_REPLACEMENT_PLAN.md §6).
- [x] **P2** Launch jitter knob (`ORBYN_NATIVE_JITTER_MS`, random 0..N pause
  per host; fixed pacing stays with the job-level `--rate-limit`).

## v1.5 — Local profiler & agent (ROADMAP_V2)

- [x] **P0** Agent sampling loop (`orbyn agent run`, Linux: /proc/stat,
  /proc/meminfo, /proc/loadavg; no subprocesses for sampling), `--once`
  mode, graceful SIGINT/SIGTERM shutdown, restart-resilient append-only
  samples. (`src/agent/mod.rs`.)
- [x] **P0** Retention prune (`--retention-hours`, default 30d, on start +
  hourly; `Store::delete_metric_samples_before` on SQLite and Postgres).
- [x] **P0** Agent asset identity (`--asset-ip` or auto-detected local
  address; ensures its asset row without clobbering discovered facts).
- [x] **P1** HTML/JSON report with sample coverage
  (`orbyn agent report --format html|json|table`; coverage = count, span,
  largest gap).
- [x] **P1** Facts cadence: filesystems (`df -kPT`) and connections
  (`ss -tnp`) through the shared SSH-collector parsers, idempotent upserts
  (`--facts-interval-secs`, `0` disables).
- [x] **P1** systemd unit example and service documentation
  (docs/agent.md).
- [x] **P0** Windows sampling (PowerShell/WMI probes): one local
  `powershell -NoProfile` metric probe per sample reusing the remote
  collector's `cpu|total|free|page` parser; the facts cadence runs the
  full read-only `WINDOWS_PROBE_SCRIPT` locally through
  `parse_windows_probe`/`windows_observations`, dropping its snapshot
  samples so only interval samples form the history. Compiled and
  unit-tested on `windows-latest` CI.
- [ ] **P1** 7-day recoverable-observation validation on live Linux and
  Windows hosts (lab-gated).

## v1.6 — Remote profiling & dependencies (ROADMAP_V2)

Scope per ROADMAP_V2: agent enrollment, mTLS or short-lived credentials,
buffer/retries and revocation; merge agent observations with the shipped
agentless SSH/WinRM evidence and connection graph. Local-first,
single-tenant — multi-tenancy is explicitly postponed (risk table).

- [x] **P0** Minimal single-tenant ingest server (`orbyn server run`):
  `POST /v1/ingest`, Bearer auth, hand-rolled HTTP/1.1 (Content-Length
  only, chunked refused, head/body caps, sequential handling, loopback
  bind by default). No framework, no new dependencies.
  (`src/server/mod.rs`.)
- [x] **P0** Enrollment: random UUID tokens minted by `orbyn server
  enroll`, printed exactly once, stored as SHA-256 hashes only
  (migration 0012, `agent_tokens`). Bearer-over-loopback-HTTP chosen
  per ADR-0002 D3; mTLS revisited when ingest leaves the host.
- [x] **P0** Agent sync (`orbyn agent sync`): cursor-based batches of
  5 000 samples plus re-upserted fact snapshots; the local database is
  the buffer (nothing is deleted until acknowledged); curl client with
  the token streamed via stdin (`-H @-`, never on argv); one attempt
  per run — the timer is the retry policy. (`src/agent/sync.rs`.)
- [x] **P0** Revocation: `orbyn server revoke <asset-id>`; ingest
  answers 403 (unknown and revoked indistinguishable); the agent keeps
  buffering locally until re-enrolled. Verified mid-run in e2e.
- [ ] **P1** Evidence merge: agent connections land in the same
  connections table the SSH/WinRM collectors write, so the connection
  graph covers both modes. Provenance (agent vs agentless) is not yet
  recorded — needs a source column when someone actually needs to
  filter by it.
- [x] **P1** Transport security decision + docs: plain HTTP on
  loopback with Bearer tokens per ADR-0002 D3 (local-first, no
  at-rest encryption before remote ingest); documented in agent.md.
- [ ] **P1** Exit criteria (lab-gated): three heterogeneous hosts
  (Linux + Windows) observed through the server; connections backed by
  evidence; revocation verified mid-run.

## v1.7 — Native discovery II (ROADMAP_V2)

- [x] **P0** Active service fingerprinting, versioned as
  `native-fingerprints/v1` (`src/collectors/fingerprint.rs`): HTTP `GET`
  probe on silent open ports (status line + `Server` header, capped
  banners); TLS handshake via rustls (ring provider, already in the tree)
  on known TLS ports with the post-handshake greeting peek (smtps/imaps/
  pop3s) or HTTP `GET` inside the tunnel (https). Certificates are not
  verified — identification, not authentication, nmap's posture; probes
  are read-only and unprivileged. Evidence overrides the port table: a
  parsed HTTP response renames the service `http`/`https`. Hermetic
  tests: parser fixtures, fake HTTP listener, sync rustls test server
  with a committed self-signed DER fixture.
- [x] **P0** UDP top-ports sweep (the applicable half of SYN/UDP): 8
  discovery-relevant ports (SNMP 161, DNS 53, NTP 123, NetBIOS-NS 137,
  IKE 500, syslog 514, UPnP 1900, zeroconf 5353) via unprivileged
  connected-datagram probes — response = `open`, ICMP unreachable =
  closed (no observation), silence = `open|filtered`, never a bare
  `open` from silence (plan §9). New capability: the nmap baseline is
  TCP-only. Feeds SNMP enrichment with candidate hosts.
  `ORBYN_NATIVE_UDP=0` disables.
- [ ] **P2** SYN scanning — deferred: raw sockets need privileges, do
  not port to Windows, and add nothing over TCP connect scan for
  authorized inventory (nmap itself falls back to connect scan when
  unprivileged). Revisit only with NMAP-010 lab data showing a need.
- [ ] **P2** Traceroute / IPv6 ranges — deferred until a validated use
  case exists (plan §5 wording).
- [ ] **P1** `auto` collector mode — gated on NMAP-010 parity data.

## v2.0 — Desktop & distributed platform (ROADMAP_V2)

Scope per ROADMAP_V2: Tauri Desktop, multi-agent server, install and
update, wizard UX. The Desktop MVP starts in parallel from v1.5; it does
not wait for v2.0. Exit criteria: Windows install without a toolchain;
CLI intact; full workflow with export.

- [x] **P1** Tauri Desktop MVP: read-only Discover/Observe/Export views
  (`desktop/`, standalone workspace like `fuzz/`). The desktop adds no
  engine logic: every view drives the stable, e2e-tested CLI surface
  (`discover`/`assets`/`agent report`/`export`) — one model, three
  interfaces. Engine binary located via `ORBYN_BIN` → app sibling →
  PATH; DB anchored in the user profile (`ORBYN_DB` wins). No editing
  in the MVP — scope-creep mitigation from the risk table. CI builds
  and tests it on Linux (webkit2gtk) and Windows (WebView2); a
  frontend↔command contract test pins the invoke names.
- [x] **P1** Wizard UX: the desktop is a four-step guided flow
  (scope → discover → observe → export); steps unlock as reached,
  first run starts at step 1, returning operators land on their
  inventory, engine errors surface under plain-language lead lines
  (cross-cutting DoD).
- [ ] **P1** Windows installer without a toolchain (MSI/NSIS built in
  CI); signed binaries where applicable; SBOM + dependency scanning
  carried over from the CLI pipeline.
  Progress: the engine ships as a Tauri sidecar next to the app
  (sibling lookup, verified end-to-end via the local `.deb` bundle:
  both binaries in `/usr/bin`, app boots stripped-env and finds the
  engine); `desktop-installer` CI job builds the NSIS installer on
  main pushes (first green run pending); `cargo deny` now covers the
  desktop lockfile (MPL-2.0 + compile-time proc-macro-error allowances
  documented in deny.toml). Decided per ADR-0003: NSIS only (D7 — no MSI
  variant), installers upload as workflow artifacts on main pushes (D8,
  step added to the `desktop-installer` job); signing waits on a
  code-signing certificate (D8 revisit trigger). Remaining: a green
  installer build.
- [x] **P1** Native save dialog for exports (`tauri-plugin-dialog`,
  capability `dialog:default`): **Choose location…** fills the path
  field, which stays as the fallback when the plugin is unavailable.
- [x] **P1** Update notifications (ADR-0003 D9, notifications-only,
  offline-first): when `ORBYN_UPDATE_MANIFEST_URL` is set the app
  fetches a two-line version manifest with `curl` at startup and shows
  a dismissible banner when a newer version is offered; no
  auto-download, silent on any failure. Signed auto-update only after
  D8's signing infrastructure exists.
- [ ] **P0** CLI intact: desktop and server consume the same core APIs;
  no CLI regressions (exit criterion, checked by the existing e2e
  suites).
- [ ] **P2** Updater: update notifications and a signed update path
  (P2 per roadmap; keep an offline path — catalogs and prices update via
  packages/versions). Decided per ADR-0003 D9: notifications-only,
  offline-first — the app checks a version manifest and notifies; signed
  auto-update only after D8's signing infrastructure exists.
  Progress: notifications shipped (above); the signed update path waits
  on D8.
- [ ] **P2** Multi-agent server: harden the v1.6 ingest server —
  aggregation TTL, quotas, and explicit sampling for connection
  cardinality (risk table); multi-tenancy still postponed. Decided per
  ADR-0003 D10: deferred until a real deployment shows the need
  (measured-then-build).
- [ ] **P1** Exit criteria (lab-gated): full workflow (discover →
  observe → analyze → export) on a clean Windows machine with no
  toolchain installed.

## Intelligence track — catalog freshness (ROADMAP_V2 track C)

Track C remainder after v1.3.0: catalog freshness. Every report already
carries source, date, version, currency, and assumptions — keep that.

- [x] **P2** Catalog freshness as versioned data packages (ADR-0002 D4):
  runtime catalog directory (`ORBYN_CATALOG_DIR`, default
  `./data/catalogs/`) overrides the embedded catalogs per provider with
  validated packages; `orbyn catalog status|install --file|update --url`
  (manifest-driven, explicit, never at report time); invalid packages are
  skipped with a warning, never silently loaded; `retrieved_at` flows into
  compare CSV/table output.
- [x] **P2** Huawei Cloud / OpenStack catalog data completion: huawei
  ships ECS flavors + on-demand prices + gpSSD storage tier
  (ap-southeast-1, USD snapshot); openstack ships reference flavors
  without prices (sizing works, cost stays honestly `not_calculated`).
  Provider loops are catalog-driven — no hardcoded provider list remains
  (`sku-match --provider` accepts any loaded provider).
- [x] **P2** Storage costs: observed member filesystem capacity is
  priced at each catalog's curated general-purpose SSD tier (aws gp3
  $0.08, azure standard-ssd $0.075, gcp pd-balanced $0.10 per
  GiB-month, 2026-10 curation); no disk sizing or no storage pricing
  stays honestly `not_calculated`, never zero. The total sums
  calculated components only and the reasons name what is missing.
- [x] **P2** Managed-database costs (first cut, postgres + mysql): the
  catalog carries per-engine service tiers (RDS / Azure Database for
  PostgreSQL+MySQL / Cloud SQL); a detected database workload is priced
  as the smallest managed tier covering its host — labeled `estimated`,
  excluded from the total (the members' compute already covers
  self-hosting). Engines without tiers (sqlserver, oracle, mongodb)
  stay `not_calculated` until their catalog data is curated.

## Pending decisions (ROADMAP_V2 — all closed, see ADR-0002 and ADR-0003)

- [x] Officially supported operating systems and binary architectures:
  Linux x64 + Windows x64 tier-1 (what CI proves); ARM64/macOS
  best-effort.
- [x] Scanner consent/scope model and raw-socket permissions:
  unprivileged-only, permanent; explicit `--target`/`--scope-cidr` is the
  consent record; SYN/ARP only if NMAP-010 data demands them.
- [x] Retention policy, process-name/IP privacy, and local encryption:
  30-day default, no at-rest encryption before v1.6 remote ingest lands
  (local-first trust model, documented).
- [x] Online pricing source and versioning: versioned catalog packages,
  no live API calls at report time; `not_calculated` honesty preserved.
- [x] Exact conditions for marking Nmap optional or removing it:
  measured-then-default (NMAP-010 ≥ parity for Orbyn's profiles flips the
  default; removal one regression-free minor release later).
- [x] Desktop engine contract: subprocess over the stable CLI, no
  engine code linked; the stable-command test pins the surface (ADR-0003
  D6; revisit only when a view needs live streaming).
- [x] Windows installer format: NSIS only; MSI revisited when an
  enterprise deployment demands it (ADR-0003 D7).
- [x] Installer distribution: workflow artifacts on main pushes now,
  tagged GitHub Releases at the release milestone; signing waits on a
  code-signing certificate, whose acquisition is the revisit trigger
  (ADR-0003 D8).
- [x] Updater: notifications-only, offline-first; signed auto-update
  only after D8's signing infrastructure exists (ADR-0003 D9).
- [x] Multi-agent server hardening: deferred until a real deployment
  shows the need — measured-then-build (ADR-0003 D10); multi-tenancy
  stays postponed.
