# Orbyn v1.1 — Consolidation, Architecture & Validation Plan

> **Completed — all thirteen phases executed (V1.1-00 through V1.1-13).**
> The Definition of Done below is checked off with evidence in
> [`V1_1_FINAL_VERIFICATION.md`](V1_1_FINAL_VERIFICATION.md). This plan is
> now a historical record; current direction lives in
> [ROADMAP.md](ROADMAP.md). Remaining maintainer steps for the release
> itself: push (final CI gate), tag, release notes — see the final
> verification document.

> **Purpose:** Consolidate the current Orbyn v1.0.x codebase before expanding the product surface with additional collectors, providers, or major features.

## 1. Context

Orbyn has reached a point where the primary engineering risk is no longer lack of functionality.

The current product already provides:

- Network discovery with Nmap.
- SNMP discovery.
- Linux host discovery over SSH.
- Windows discovery over SSH and WinRM.
- DNS relationship evidence.
- Normalized infrastructure inventory.
- SQLite and PostgreSQL persistence.
- Dependency mapping.
- Migration assessment.
- Historical metrics ingestion.
- Right-sizing analysis.
- Migration waves.
- Cloud SKU matching.
- NetBox integration.
- Prometheus and Zabbix integration.
- Proxmox, AWS, Huawei Cloud, Azure, GCP and OpenStack integration.
- Ansible and Terraform exports.
- Audit records.
- JSON/CSV output.
- Linux and Windows release artifacts.
- CI, dependency auditing, license checks and fuzzing.

The objective of v1.1 is therefore **not feature expansion**.

The objective is:

> Make the existing product easier to maintain, validate, operate and extend safely.

---

# 2. v1.1 Engineering Principles

All work performed during this milestone MUST follow these principles.

### 2.1 Do not change behavior unnecessarily

Refactoring MUST preserve existing CLI behavior unless a change is explicitly documented and approved.

Existing commands, output contracts and database compatibility should remain stable.

### 2.2 Prefer architecture work over new features

Do not add new:

- cloud providers;
- collectors;
- inventory platforms;
- assessment engines;
- major CLI commands;

unless required to complete or validate an existing capability.

### 2.3 Tests are part of the contract

Existing tests MUST continue passing.

New architectural boundaries SHOULD have dedicated unit or integration coverage.

### 2.4 Keep the core provider-neutral

Assessment, inventory, metrics and dependency logic MUST remain independent from specific cloud providers or discovery tools.

Provider-specific behavior belongs under adapters/integrations.

### 2.5 External tools are adapters, not the architecture

Nmap, SNMP tools, SSH and similar external programs are implementation details of collectors.

The domain model MUST NOT depend on their output structures.

---

# 3. Priority 0 — Establish the v1.1 Baseline

Before modifying architecture, establish a reproducible baseline.

Record:

```text
Orbyn version
Git commit
Rust version
cargo test results
cargo clippy results
cargo audit results
cargo deny results
release build result
test count
binary size
```

Run:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
cargo audit
cargo deny check
```

Also run the existing fuzz smoke suite where the required toolchain is available.

Create:

```text
docs/V1_1_BASELINE.md
```

The document should record the baseline and become the reference point for detecting regressions during the refactor.

### Exit criteria

- Current `main` builds successfully.
- Existing test suite passes.
- Security/dependency checks pass.
- Baseline commit is documented.
- Any existing failure is documented before refactoring begins.

---

# 4. Priority 1 — Decompose `src/main.rs`

## Problem

`src/main.rs` has grown into a very large CLI/orchestration module.

The domain and infrastructure layers are reasonably modular, but the application boundary is increasingly concentrated in `main.rs`.

This increases:

- cognitive load;
- merge conflicts;
- regression risk;
- difficulty testing individual commands;
- difficulty onboarding contributors;
- cost of adding future capabilities.

## Goal

Reduce `main.rs` to CLI bootstrap and dispatch.

Target architecture:

```text
src/
├── main.rs
├── cli/
│   ├── mod.rs
│   ├── args.rs
│   └── commands/
│       ├── mod.rs
│       ├── discover.rs
│       ├── inventory.rs
│       ├── dependencies.rs
│       ├── assessment.rs
│       ├── metrics.rs
│       ├── integrations.rs
│       ├── cloud.rs
│       ├── sku.rs
│       ├── waves.rs
│       └── audit.rs
│
├── app/
│   ├── mod.rs
│   ├── discovery.rs
│   ├── assessment.rs
│   ├── inventory.rs
│   ├── dependencies.rs
│   ├── metrics.rs
│   └── migration.rs
│
├── collectors/
├── integrations/
├── domain/
├── store/
├── assessment/
├── metrics/
├── sku/
├── waves/
└── output/
```

This layout is a target, not a requirement to mechanically create every listed file.

Use module boundaries that match actual responsibilities.

## Important distinction

`cli/` owns:

- clap definitions;
- CLI argument validation;
- command dispatch;
- terminal-facing errors;
- translation from CLI arguments into application requests.

`app/` owns:

- use-case orchestration;
- coordination between collectors, store and domain services;
- workflows that should be callable independently of clap.

Existing modules continue owning their respective domain logic.

For example:

```text
CLI
 ↓
app::assessment
 ↓
assessment engine
 ↓
Store
```

instead of:

```text
main.rs
 ↓
everything
```

## Refactoring strategy

Do NOT rewrite `main.rs` in one large change.

Move one command family at a time.

Recommended sequence:

```text
1. read-only inventory commands
2. audit/jobs
3. assessment
4. metrics
5. dependencies/graph
6. SKU matching
7. waves
8. imports/integrations
9. cloud operations
10. discovery
```

After every extraction:

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

### Exit criteria

- `main.rs` contains primarily initialization and dispatch.
- Command handlers are grouped by responsibility.
- Business/application workflows do not depend directly on clap types where avoidable.
- Existing CLI behavior remains compatible.
- Existing E2E tests pass.

---

# 5. Priority 2 — Documentation Consistency Audit

## Problem

Some documentation describes already implemented functionality as planned or future work.

This creates ambiguity about the actual product state.

## Goal

Establish clear ownership for documentation.

Use the following rule:

```text
README.md
    Current product capabilities and entry point.

docs/
    Current user and operator documentation.

ARCHITECTURE.md
    Current architecture.

ROADMAP.md
    Future direction and historical milestone status.

CHANGELOG / release notes
    Historical changes.

GitHub Issues
    Actionable pending work.
```

## Required audit

Review at minimum:

```text
README.md
docs/ARCHITECTURE.md
docs/ROADMAP.md
docs/INSTALL.md
docs/KnowIssues.md
docs/PERFORMANCE.md
docs/PLUGINS.md
docs/SECURITY.md
docs/VALIDATION_MATRIX.md
docs/sku.md
docs/waves.md
docs/collectors/*
docs/importers/*
```

Search for language such as:

```text
planned
future
TODO
not implemented
later
upcoming
deferred
```

Verify each statement against the current implementation.

Do not blindly delete historical information. Move historical information to the appropriate document when useful.

### Exit criteria

A reader should be able to answer:

> What can Orbyn do today?

without contradictions between README, architecture documentation and roadmap.

---

# 6. Priority 3 — Documentation Governance

Reduce the number of competing planning documents.

Review:

```text
BACKLOG.md
EXECUTION_PLAN.md
ORBYN_AGENT_PLAN.md
PLAN_ISSUES.md
ROADMAP.md
PRE_RELEASE_PLAN.md
```

Classify each document as:

```text
CURRENT
HISTORICAL
MERGE
REMOVE
```

Prefer:

```text
ROADMAP.md
    strategic direction

GitHub Issues
    actionable engineering work

SECURITY.md
    vulnerability/security policy

CHANGELOG.md / release notes
    release history

ARCHITECTURE.md
    current technical design
```

Historical agent plans may remain in the repository when useful, but MUST be clearly marked as historical and MUST NOT appear to be authoritative project state.

---

# 7. Priority 4 — Integration Validation Matrix

Mocked tests are necessary but insufficient for external systems.

Expand `docs/VALIDATION_MATRIX.md`.

Use a matrix conceptually similar to:

| Integration  | Unit | Fake E2E | Real-system smoke | CI |
| ------------ | ---: | -------: | ----------------: | -: |
| Nmap         |    ✓ |        ✓ |               TBD |  ✓ |
| SNMP         |    ✓ |        ✓ |               TBD |  ✓ |
| SSH          |    ✓ |        ✓ |               TBD |  ✓ |
| WinRM        |    ✓ |        ✓ |               TBD |  ✓ |
| NetBox       |    ✓ |        ✓ |               TBD |  ✓ |
| Prometheus   |    ✓ |        ✓ |               TBD |  ✓ |
| Zabbix       |    ✓ |        ✓ |               TBD |  ✓ |
| Proxmox      |    ✓ |        ✓ |               TBD |  ✓ |
| AWS          |    ✓ |        ✓ |               TBD |  ✓ |
| Huawei Cloud |    ✓ |        ✓ |               TBD |  ✓ |
| Azure        |    ✓ |        ✓ |               TBD |  ✓ |
| GCP          |    ✓ |        ✓ |               TBD |  ✓ |
| OpenStack    |    ✓ |        ✓ |               TBD |  ✓ |

Do not mark a real-system validation as complete unless it has actually been performed.

For every real-system test, record:

```text
integration
date
Orbyn version
external product/API version when applicable
scenario
expected result
actual result
limitations discovered
```

Do NOT place credentials, tokens, account IDs or sensitive infrastructure information in the repository.

---

# 8. Priority 5 — Performance Baseline

Orbyn should have reproducible performance expectations.

Create benchmark scenarios for approximately:

```text
100 assets
1,000 assets
10,000 assets
```

Measure relevant operations:

```text
inventory import
asset listing
dependency graph generation
assessment
metrics aggregation
migration waves
export
database startup/migration
```

Record:

```text
wall-clock time
peak memory where practical
database size
asset count
service count
dependency count
metric sample count
```

Prefer deterministic synthetic fixtures.

Do not optimize based on intuition alone.

First establish measurements.

Then optimize demonstrated bottlenecks.

Create or expand:

```text
docs/PERFORMANCE.md
```

### Exit criteria

- A developer can reproduce the benchmark.
- Results for at least 100 and 1,000 assets are documented.
- 10,000 assets either completes successfully or has a documented bottleneck.
- Performance regressions can be compared against a known baseline.

---

# 9. Priority 6 — External Dependency Review

Current optional/collector functionality relies on external executables including:

```text
nmap
snmpwalk
ssh
curl
dig
```

Do NOT replace external dependencies merely for architectural purity.

Evaluate each dependency using:

```text
implementation complexity
security impact
cross-platform behavior
licensing
binary size
maintenance burden
operational dependency
feature completeness
```

## Expected direction

### Nmap

Keep Nmap as an external collector.

Do not attempt to reproduce Nmap's scanning and fingerprinting engine inside Orbyn.

### SNMP

Evaluate native Rust SNMP support separately.

Replacement is optional and requires evidence that it improves deployment or reliability.

### SSH

Keep the current implementation unless a native implementation produces a measurable operational benefit.

### curl

Investigate migration of HTTP-based integrations to a Rust HTTP client.

Potential benefits:

```text
fewer runtime dependencies
better typed errors
direct timeout control
direct TLS configuration
simpler cross-platform installation
```

Any migration MUST preserve current secret-handling guarantees.

### dig

Investigate native DNS resolution.

This is a reasonable candidate for eliminating an external executable.

## Deliverable

Create:

```text
docs/EXTERNAL_DEPENDENCIES.md
```

with a decision for each dependency:

```text
KEEP
REPLACE
INVESTIGATE
```

Include rationale.

---

# 10. Priority 7 — Security Regression Pass

After architectural refactoring, repeat the security-sensitive tests.

Pay particular attention to:

```text
secret propagation
environment sanitization
subprocess argv
stdin credential handling
temporary files
database permissions
CSV injection
HTTP response limits
timeouts
TLS verification
redaction
cloud credentials
PostgreSQL credentials
```

Run:

```bash
cargo audit
cargo deny check
```

and the relevant fuzz targets.

Do not weaken existing security behavior while moving command code out of `main.rs`.

---

# 11. Priority 8 — CLI UX Review

Do not redesign the CLI.

Instead, perform a consistency pass.

Review:

```text
orbyn --help
orbyn <command> --help
```

Check:

- terminology;
- flag naming;
- output format behavior;
- error messages;
- exit codes;
- destructive/mutating operations;
- secret-input behavior;
- examples;
- JSON/CSV stability.

Commands performing similar operations SHOULD follow similar conventions.

Document intentional inconsistencies rather than silently breaking compatibility.

---

# 12. Priority 9 — Installation and Distribution Review

Current release targets include Linux and Windows.

Verify from clean environments that installation instructions actually work using only published artifacts and documented prerequisites.

Test:

```text
clean Linux VM/container
clean Windows VM
```

Validate:

```text
download
checksum verification
installation
orbyn --version
orbyn --help
database initialization
basic import/discovery
upgrade
uninstall
```

After the existing platforms are verified, evaluate additional distribution channels separately.

Possible future options:

```text
Homebrew
Scoop
WinGet
deb/rpm repositories
container image
macOS binaries
```

These are NOT mandatory for v1.1.

---

# 13. Priority 10 — Contributor Experience

A new contributor should be able to understand the repository without reading the entire codebase.

Update `CONTRIBUTING.md` with:

```text
repository architecture
local development setup
required Rust version
test commands
how to add a collector
how to add an integration
how to add an assessment rule
how to add a migration
how to update documentation
release expectations
```

Provide a short architecture path:

```text
CLI
 ↓
Application workflow
 ↓
Collector / Integration
 ↓
Domain
 ↓
Store
 ↓
Assessment / Metrics / Graph
 ↓
Output
```

---

# 14. Explicit Non-Goals for v1.1

Unless necessary to fix or validate existing functionality, do NOT add:

- VMware/vCenter support.
- Kubernetes discovery.
- OCI support.
- ServiceNow integration.
- Additional public cloud providers.
- Web UI.
- TUI.
- GraphQL.
- Remote management server.
- Distributed agents.
- Embedded Nmap replacement.
- Automatic migration execution.
- AI-generated migration recommendations.

These may be evaluated after consolidation.

---

# 15. Definition of Done

Orbyn v1.1 consolidation is complete when:

- [x] Current v1.0.x behavior has a documented baseline.
- [x] `main.rs` has been substantially decomposed.
- [x] CLI and application orchestration have clear module boundaries.
- [x] Existing tests remain green.
- [x] CI remains green on Linux and Windows.
- [x] PostgreSQL tests remain green.
- [x] Fuzz targets build and smoke successfully.
- [x] `cargo audit` passes.
- [x] `cargo deny` passes.
- [x] Architecture documentation describes current behavior.
- [x] Roadmap clearly distinguishes implemented and future capabilities.
- [x] Obsolete planning documents are archived, merged or marked historical.
- [x] External dependencies have documented keep/replace decisions.
- [x] Integration validation status is explicit.
- [x] Performance baselines are reproducible.
- [x] Installation has been tested from published artifacts.
- [x] Contributor documentation reflects the refactored architecture.
- [x] No unnecessary major feature has been introduced during consolidation.

---

# 16. Agent Execution Rules

When executing this plan:

1. Inspect the current implementation before modifying it.
2. Do not assume documentation is correct; verify against code and tests.
3. Make small, reviewable changes.
4. Run relevant tests after every architectural extraction.
5. Preserve public CLI behavior unless explicitly instructed otherwise.
6. Do not remove functionality to simplify the refactor.
7. Do not introduce abstractions without a concrete current use.
8. Prefer existing project patterns over introducing new frameworks.
9. Add regression tests for bugs discovered during the work.
10. Update documentation in the same change that changes behavior.
11. Never commit credentials, infrastructure identifiers or test secrets.
12. Stop and document unexpected architectural problems instead of hiding them with compatibility hacks.

---

# 17. Recommended Execution Order

Execute the milestone in this order:

```text
V1.1-00  Establish baseline

V1.1-01  Extract CLI command modules
V1.1-02  Introduce/refine application orchestration boundary
V1.1-03  Reduce main.rs to bootstrap/dispatch

V1.1-04  Audit architecture documentation
V1.1-05  Consolidate planning documentation

V1.1-06  Expand validation matrix
V1.1-07  Establish performance baseline

V1.1-08  Review external executable dependencies
V1.1-09  Perform security regression pass

V1.1-10  Review CLI consistency
V1.1-11  Validate clean installation/upgrade

V1.1-12  Update contributor documentation
V1.1-13  Final CI/release-candidate verification
```

Do not perform all phases as one giant commit.

Each phase should leave the repository in a buildable and testable state.

---

# 18. Desired Outcome

At the end of this milestone Orbyn should not necessarily have more features.

It should instead be:

```text
easier to understand
easier to test
easier to install
easier to validate
easier to extend
harder to accidentally break
```

The success metric for v1.1 is not the number of new integrations.

The success metric is whether a future developer can safely add the next integration **without needing to understand a 100+ KB `main.rs` or guess which document describes the real system**.

Only after this milestone should significant feature expansion resume.
