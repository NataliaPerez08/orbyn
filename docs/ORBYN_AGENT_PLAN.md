# Orbyn — Agent Execution Plan

> **Historical document — executed in full.** All ten phases of this plan
> shipped across the v1.0.x series (SKU matching was Phase 9, migration waves
> Phase 10). It is kept as a record and does not describe current project
> state. Current direction: [ROADMAP.md](ROADMAP.md). Current design:
> [ARCHITECTURE.md](ARCHITECTURE.md). Known issues: [KnowIssues.md](KnowIssues.md).

## Objective

Consolidate Orbyn as a reliable, production-grade infrastructure discovery and migration assessment CLI.

The current project already has broad feature coverage. The next development cycle must prioritize correctness, reproducibility, real-world validation, adapter consistency, performance, failure handling, and release consistency.

Do **not** expand the project with additional cloud providers, UI layers, or unrelated collectors until the current feature set is validated and hardened.

## Current Project State

Orbyn currently includes:

- Nmap, SNMP, SSH, Windows OpenSSH, native WinRM/WS-Man, and DNS-based discovery/evidence.
- Assets, interfaces, services, host services, CPU/RAM, filesystems, virtualization metadata, tags, environment, owner, and criticality.
- SQLite and PostgreSQL persistence with migrations, batching, and incremental discovery persistence.
- Runtime, DNS, and manual dependency relationships with confidence and graph export.
- Migration assessment with explainable findings, complexity scoring, lifecycle/service/dependency rules, application grouping, and rule versioning.
- Snapshot metrics plus Prometheus and Zabbix historical imports.
- CPU/RAM/swap/storage right-sizing rules with observation-window confidence and trend analysis.
- NetBox, Proxmox VE, AWS, Huawei Cloud, OpenStack, GCP, Azure, Ansible, and Terraform integrations.
- Bounded concurrency, rate limiting, retries, subprocess limits, input/response caps, audit events, and discovery history.
- CI for fmt, clippy, Linux/Windows tests, PostgreSQL integration tests, RustSec, cargo-deny licenses/sources, and release artifacts.

## Main Goal

Move Orbyn from:

> broad implementation coverage

to:

> trusted migration-assessment software with predictable behavior.

The project should now be evaluated primarily by:

- accuracy;
- deterministic output;
- test coverage;
- performance;
- interoperability;
- failure recovery;
- real infrastructure validation.

Feature count is no longer a useful primary metric.

# Phase 1 — Documentation and Version Consistency

## Goal

Remove inconsistencies between package version, roadmap, README, release workflow, and supported platforms.

## Tasks

### 1. Normalize versioning

Review:

- `Cargo.toml`
- `README.md`
- `docs/ROADMAP.md`
- `docs/BACKLOG.md`
- release tags

Current problem:

- package version is `1.0.4`;
- roadmap declares v1.1 and v1.2 capabilities implemented;
- post-v1 phases are also marked complete.

Choose and document a consistent versioning strategy.

Recommended direction:

```text
1.0.x  stable discovery / inventory / assessment
1.1.0  integrations
1.2.0  historical metrics + right-sizing
1.3.0  cloud / platform adapters
```

Alternative: keep SemVer strictly for releases and rename roadmap versions into internal milestones/phases.

### 2. Fix platform documentation

Current release workflow builds:

- Linux x86_64
- Windows x86_64

Ensure documentation no longer promises macOS binaries unless macOS release builds are restored.

### 3. Review status labels

For cloud adapters, distinguish:

- implemented;
- offline tested;
- live validated;
- production validated.

Do not describe an adapter as production-ready solely because fixture tests pass.

## Acceptance Criteria

- README and ROADMAP describe the same current release.
- Supported release platforms match GitHub Actions.
- No feature is described using contradictory version numbers.
- Cloud adapter maturity is clearly documented.

# Phase 2 — Golden Dataset Test Suite

## Goal

Create deterministic reference datasets that detect regressions across the whole Orbyn pipeline.

## Required datasets

Create at least:

```text
small     10 assets
medium   100 assets
large   1000 assets
stress 10000 assets
```

Each dataset should include combinations of:

- Linux
- Windows
- routers/switches
- databases
- web servers
- application servers
- cloud VMs
- hypervisor guests
- multiple interfaces
- multiple filesystems
- runtime connections
- DNS relationships
- manual relationships
- incomplete inventory
- unsupported OS examples
- high CPU
- low CPU
- high RAM
- low RAM
- swap pressure
- storage pressure

Store deterministic expected outputs for:

- asset count
- interface count
- service count
- dependency edge count
- application groups
- assessment findings
- complexity scores
- metric readiness
- right-sizing recommendations
- export row counts

## Acceptance Criteria

- Golden datasets are version controlled.
- Expected outputs are deterministic.
- CI validates them.
- Unexpected graph or assessment drift causes test failure.

# Phase 3 — Cloud Adapter Contract Tests

## Goal

Ensure all cloud/platform adapters behave consistently.

Target adapters:

- Proxmox
- AWS
- Huawei Cloud
- OpenStack
- GCP
- Azure

## Contract Requirements

Every adapter should cover:

### Authentication

- missing credentials
- invalid credentials
- secret redaction
- credentials never persisted
- credentials never exposed through argv where avoidable

### HTTP behavior

- success
- pagination
- timeout
- response-size limit
- malformed payload
- partial response
- 401
- 403
- 404 where applicable
- 429
- 500
- 502 / 503

### Retry behavior

Expected:

```text
429 -> retry
500 -> retry
503 -> retry
timeout -> retry
401 -> no retry
403 -> no retry
invalid payload -> no blind retry loop
```

### Inventory behavior

Verify:

- asset normalization
- interface normalization
- CPU/RAM capacity
- filesystem/disk mapping
- provider tags
- account/project/subscription provenance
- region provenance
- stable identifiers
- idempotent re-import
- partial failure preservation

## Acceptance Criteria

All adapters share equivalent behavioral guarantees even when provider APIs differ.

# Phase 4 — Real Infrastructure Validation

## Goal

Validate fixture-tested functionality against real systems.

## Environment Matrix

At minimum validate:

```text
Linux host
Windows Server
Proxmox VE
PostgreSQL
Prometheus
Zabbix
AWS
Azure
GCP
Huawei Cloud
OpenStack
```

Document manual validation where credentials or billing make continuous testing impractical.

## Required End-to-End Flow

```text
discover/import
      ↓
inventory
      ↓
dependency graph
      ↓
metrics
      ↓
assessment
      ↓
export
```

Confirm:

- asset identity remains stable;
- duplicate assets are not created;
- re-import is idempotent;
- credentials are not persisted;
- failures do not corrupt previous data;
- partial successes remain available.

## Acceptance Criteria

Create `docs/VALIDATION_MATRIX.md` with:

| Integration | Fixture Tested | Live Tested | Scale Tested | Last Validation | Notes |
|---|---|---|---|---|---|

# Phase 5 — Right-sizing Validation

## Goal

Turn right-sizing into one of Orbyn's most trustworthy capabilities.

Create deterministic test scenarios for:

### CPU overprovisioned

```text
capacity: 8 vCPU
window: >= 168 h
CPU p99: 20%
```

### CPU saturated

```text
capacity: 4 vCPU
CPU p95: 95%
```

### RAM overprovisioned

```text
capacity: 32 GB
RAM p99: 10 GB
```

### RAM saturated

Validate sustained high memory usage behavior.

### Insufficient evidence

```text
window: 4 h
```

Must not produce a high-confidence sizing recommendation.

### Trend instability

```text
week 1 p95: 40%
week 2 p95: 65%
```

Validate trend warning.

### Swap pressure

Validate sustained swap utilization.

### Storage

Test:

- large underutilized volume
- nearly full volume
- small volume
- missing filesystem information

## Acceptance Criteria

Every right-sizing recommendation must expose:

- rule id;
- rule version;
- observation span;
- sample confidence;
- current capacity;
- relevant percentile;
- safety margin;
- recommendation;
- evidence.

No recommendation may silently treat a snapshot as historical evidence.

# Phase 6 — Performance and Scale Baselines

## Goal

Establish measurable performance expectations.

Measure:

- imports;
- exports;
- assessment;
- dependency graph generation;
- metric aggregation;
- cloud imports;
- discovery persistence.

Record results for:

```text
100 assets
1,000 assets
10,000 assets
```

Where feasible also test:

```text
50,000 dependency edges
100,000 metric samples
```

Track:

- wall-clock duration;
- peak memory;
- database size;
- number of SQL queries where measurable.

Investigate regressions greater than roughly 25% on identical reference datasets.

# Phase 7 — Failure and Recovery Testing

## Goal

Ensure Orbyn fails predictably.

Test:

### Process failures

- Nmap missing
- snmpwalk missing
- ssh missing
- curl missing
- command timeout
- oversized stdout/stderr

### Database failures

- SQLite locked
- unreadable/corrupt SQLite
- PostgreSQL unavailable
- PostgreSQL connection interrupted
- migration failure

### API failures

- request timeout
- TLS error
- invalid certificate
- rate limit
- transient provider failure
- malformed response

### Data failures

- malformed Nmap XML
- malformed JSON import
- oversized import
- duplicate hostnames
- duplicate IPs
- missing optional fields
- invalid metric values

## Acceptance Criteria

For partial failures:

- completed observations remain persisted;
- discovery job records failure accurately;
- no credentials appear in errors;
- database remains consistent.

# Phase 8 — Release Hardening

## Goal

Make every release reproducible and self-consistent.

Validate:

- `Cargo.lock` used everywhere;
- toolchain pinned;
- GitHub Actions pinned;
- artifact names stable;
- checksums valid;
- `LICENSE` included;
- `THIRD_PARTY_NOTICES.md` included;
- RustSec clean;
- cargo-deny licenses clean;
- cargo-deny sources clean.

Add a release smoke test:

```text
extract artifact
orbyn --version
orbyn --help
create temporary database
orbyn assets
```

The binary version must match the release tag.

# Phase 9 — Next Product Capability: Cloud SKU Matching

Start only after the consolidation phases are stable.

## Goal

Convert vendor-neutral right-sizing recommendations into target infrastructure candidates.

```text
Current capacity
      ↓
Historical utilization
      ↓
Right-sizing baseline
      ↓
Provider SKU catalog
      ↓
Candidate instances
      ↓
Cost comparison
```

Keep SKU matching separate from core right-sizing.

Correct:

```text
Orbyn baseline:
4 vCPU
24 GB RAM
```

Then:

```text
AWS adapter -> matching instance types
Azure adapter -> matching VM sizes
GCP adapter -> matching machine types
```

Do not embed provider-specific SKUs inside core right-sizing rules.

# Phase 10 — Future Capability: Migration Waves

Inputs:

- dependency graph
- application groups
- criticality
- migration complexity
- external dependencies
- manual constraints

Goal:

```text
Wave 1
- development systems
- low-risk internal tools

Wave 2
- web
- API
- cache

Wave 3
- ERP
- legacy DB
- tightly coupled integrations
```

Wave suggestions must expose their reasoning.

# Explicit Non-Goals for the Current Cycle

Do not implement unless separately approved:

- web UI
- REST API purely for UI convenience
- Kubernetes discovery
- Oracle Cloud
- DigitalOcean
- Hetzner
- Linode
- Alibaba Cloud
- Nutanix
- Hyper-V
- additional generic cloud providers
- embedded monitoring platform
- custom agent
- eBPF runtime collector

# Engineering Rules

## Maintain Orbyn's architecture

```text
Source
  ↓
Collector / Adapter
  ↓
Normalized Domain
  ↓
Store
  ↓
Graph / Metrics / Assessment / Export
```

## Read-only by default

External infrastructure integrations must remain read-only unless a future feature explicitly requires mutation.

## Secrets

Never:

- persist API tokens;
- print credentials;
- include secrets in logs;
- expose secrets in process arguments when avoidable.

## Failure model

Prefer:

```text
partial success + explicit failure record
```

over discarding all work when safe and semantically correct.

## Explainability

Every assessment or recommendation must expose its evidence.

Avoid opaque scores or unexplained recommendations.

# Definition of Done

A task is complete only when:

- implementation exists;
- unit tests exist where appropriate;
- integration tests exist where appropriate;
- error cases are covered;
- documentation is updated;
- security implications are reviewed;
- output is deterministic where required;
- existing behavior does not regress;
- CI passes.

For external integrations also require:

- offline fixtures;
- contract tests;
- at least one documented live validation where practical.

# Agent Priority Order

Execute work in this order unless a blocking defect requires otherwise:

```text
1. Version/documentation consistency
2. Golden datasets
3. Cloud adapter contract tests
4. Real-world validation matrix
5. Right-sizing validation
6. Performance baselines
7. Failure/recovery tests
8. Release smoke tests
9. Cloud SKU matching
10. Migration-wave planning
```

Do not skip directly to new product features while earlier reliability work remains incomplete.

# Expected Agent Behavior

Before modifying code:

1. inspect existing implementation;
2. inspect related tests;
3. inspect roadmap/backlog documentation;
4. identify whether the requested behavior already exists;
5. avoid duplicate abstractions.

For each change:

1. make the smallest coherent modification;
2. add or update tests;
3. run formatting;
4. run clippy;
5. run relevant tests;
6. update documentation;
7. report changed files and remaining risks.

Avoid large rewrites unless the current architecture demonstrably blocks correctness or maintainability.

# Completion Report Format

At the end of each execution batch report:

```text
Completed
- ...

Tests
- ...

Files changed
- ...

Behavioral changes
- ...

Known limitations
- ...

Next recommended task
- ...
```

Do not mark an item complete when only scaffolding, placeholder code, or fixture-only behavior exists.

# Final Direction

Orbyn already has sufficient breadth.

The current goal is not:

> add more integrations.

The current goal is:

> make the existing discovery, inventory, graph, assessment, metrics, and cloud capabilities trustworthy enough to use during a real migration project.

Optimize future work for confidence rather than feature count.
