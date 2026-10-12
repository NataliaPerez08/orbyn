# Orbyn — Technical Roadmap v1.1 → v2.0

**Status:** Proposal for review · **Date:** 2026-10-12 · **Stated baseline:** Orbyn v1.0.4 (to be confirmed against HEAD)

> This plan builds on the project's history and agreed goals; it is not an audit of the current repository. Before executing tasks, verify the code, Nmap commands, CI, licenses, and actually implemented features.

## Vision

**Discover → Observe → Analyze → Optimize → Plan.** A local-first platform for inventory, time-series observation, dependencies, and explainable migration recommendations. Two collection modes: **agent-based** and **agentless**. Three interfaces over one engine: CLI, Desktop, and Server.

## Principles and boundaries

- One model for assets, observations, and evidence; CLI, Desktop, and Server consume the same core APIs.
- Nmap remains an optional adapter until parity is demonstrated **for Orbyn's use cases**, not for all of Nmap.
- The agent must operate disconnected, with storage limits and safe synchronization.
- Recommendations are justified candidates; they never replace capacity, compatibility, or load-test validation.
- Scanning and remote collection only on authorized assets, with explicit scope, rate limits, and auditing.
- Keep an offline path; cloud catalogs and prices can be updated via packages/versions.

## Starting point: mandatory audit (Sprint 0, 1–2 weeks)

1. Pin the commit SHA, version, platform matrix, and actual releases.
2. Inventory **every actual Nmap invocation**: arguments, profiles, output formats, permissions, scripts, parsing paths, and consumers.
3. Identify existing crates, collectors, storage interfaces, API/CLI, and CI pipelines.
4. Run tests, lint, Windows/Linux builds, and runs on an authorized lab network.
5. Review dependency licenses and redistribution obligations; don't assume bundling Nmap is obligation-free.
6. Publish a `BASELINE_AUDIT.md` with evidence, gaps, risks, and an updated backlog.

**Output:** a reproducible baseline, Nmap result fixtures, a prioritized list of features in use, and an ADR on internal contracts.

## Milestones and deliverables

| Milestone | Scope | Depends on | Verifiable exit criteria |
|---|---|---|---|
| **v1.1 — Core & Application Intelligence** | DiscoveryBackend contracts, entities/evidence; application grouping, confidence, and explanation | Sprint 0 | Nmap decoupled; fixtures pass through the common model; groupings with traceability |
| **v1.2 — Native Discovery I** | Target parser, DNS, TCP connect, ICMP/ARP per platform, basic banners and services; rate limiting | v1.1 | Basic TCP discovery without Nmap; benchmarks and differences documented |
| **v1.3 — Local Profiler & Agent** | Windows/systemd service, CPU/RAM/disk/processes/network, SQLite, duration and frequency, restarts | v1.1 | Recoverable 7-day observation; HTML/JSON report; sample coverage |
| **v1.4 — Remote Profiling & Dependencies** | Agent enrollment, mTLS or short-lived credentials, buffer/retries; SSH/WinRM agentless; connection graph | v1.3 | Three heterogeneous hosts observed; connections backed by evidence; revocation verified |
| **v1.5 — Native Discovery II** | SYN/UDP where applicable, service detection/versions, IPv6, traceroute, gradual fingerprinting | v1.2 | Parity matrix per feature actually used; documented Nmap fallback |
| **v1.6 — Right-sizing & Migration Planner** | P50/P95/peaks, observation quality, headroom, applications and waves, reports | v1.4 | Every proposal includes data, assumptions, uncertainty, and constraints |
| **v1.7 — Target & Cost Intelligence** | AWS/Azure/GCP/Huawei/OpenStack adapters, SKU matching, regions, costs, and freshness | v1.6 | Reproducible comparisons with catalog date/source and itemized costs |
| **v2.0 — Desktop & Distributed Platform** | Tauri Desktop, multi-agent server, install and update, wizard UX | v1.3–v1.7 | Windows install without a toolchain; CLI intact; full workflow with export |

**Important:** the Desktop MVP starts in parallel from v1.3; it does not wait for v2.0. Versions are product milestones, not date promises.

## Four parallel tracks

**A. Discovery:** abstraction → native TCP → ICMP/ARP → service fingerprints → SYN/UDP/IPv6 → Nmap retirement evaluation.

**B. Observability:** local agent → time-series storage → remote agent → agentless SSH/WinRM → process/connection dependencies.

**C. Intelligence:** application grouping → evidence/confidence → right-sizing → waves → SKU/cost.

**D. Experience:** stable CLI → Desktop MVP (Discover/Observe/Export) → dashboards → server and agent management.

## First 90 days plan (target, not commitment)

| Weeks | Work | Evidence |
|---|---|---|
| 1–2 | Audit, ADRs, contracts, and fixtures | `BASELINE_AUDIT.md`, green CI |
| 3–4 | Native TCP connect and backend selector | Lab comparison against Nmap |
| 5–6 | Local agent and CPU/RAM/disk metrics | Service and persisted samples |
| 7–8 | Scheduler, retention, restarts, and statistics | Continuity test and P95 |
| 9–10 | Desktop MVP with wizard | Windows test installer |
| 11–12 | Integration, security, and documentation | Reproducible end-to-end demo |

**Excluded from the 90-day MVP:** full Nmap replacement, definitive cloud estimation, automatic migration, enterprise multi-tenancy.

## Cross-cutting definition of done

- Unit, integration, and regression tests; versioned fixtures and Windows/Linux runs.
- Quality metrics: coverage, false positives, sample loss, agent overhead, and job success rate.
- Structured logs without secrets, recoverable errors, cancellation, and permission handling.
- Documentation of installation, least privilege, privacy, limits, and recovery.
- SBOM, dependency scanning, license review, and signed binaries where applicable.
- UX: understandable messages for non-technical users and reproducible export.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Nmap reimplementation grows without bound | Exact matrix of commands used and bounded parity |
| Insufficient metrics produce misleading recommendations | Quality score, minimum observation, and abstention |
| Elevated privileges in scanner/agent | Capability-based degradation, least privilege, and opt-in |
| Connection cardinality/volume | Aggregation, TTL, quotas, and explicit sampling |
| Stale cloud catalogs | Source, date, version, currency, and assumptions in every report |
| Central server complexity | Start local-first and postpone multi-tenancy |

## First GitHub backlog

**P0:** Nmap baseline; contracts ADR; XML/JSON fixtures; Windows/Linux CI; target parser; TCP connect; local service; metrics schema.

**P1:** service detection; HTML reports; Tauri MVP; quality score; process→destination connections; secure enrollment; SSH/WinRM.

**P2:** SYN/UDP, OS fingerprints, provider adapters, cost comparison, updater, and multi-agent server.

## Pending decisions

- Officially supported operating systems and binary architecture.
- Scanner consent/scope model and raw-socket permissions.
- Retention policy, process-name/IP privacy, and local encryption.
- SKU source/versioning and pricing model.
- Exact conditions for marking Nmap optional or removing it.
