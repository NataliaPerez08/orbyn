# Orbyn — Technical Roadmap v1.4 → v2.0

**Status:** Proposal for review · **Date:** 2026-10-13 · **Baseline:** Orbyn v1.3.0 (verified against HEAD, tag `v1.3.0`)

> The baseline below is verified against HEAD. Before executing tasks, still verify Nmap invocations, CI, and licenses locally; this plan is not an audit of every code path.

## Baseline: what v1.3.0 already ships

Shipped and covered by deterministic fixtures and end-to-end tests:

- Application intelligence, migration planner and target & cost intelligence (the v1.1–v1.3 capability milestones, release `v1.3.0`).
- Right-sizing with observation windows and readiness/confidence; snapshot collector; Prometheus and Zabbix history importers.
- Agentless host-level collection (SSH/WinRM), dependency evidence and the connection graph, waves, bundles, audit trail.
- Cloud adapters (Proxmox VE, AWS, Huawei Cloud, OpenStack, GCP, Azure) — offline fixture-tested; SKU matching over versioned embedded catalogs; multi-cloud compare/recommend where missing pricing is reported `not_calculated`, never silently zero.

Not in the baseline at plan time (2026-10-13); shipped since, per the
backlog checkboxes:

- Native discovery (`--collector native`, v1.4) and the fingerprint/UDP
  slice of v1.7 — Nmap remains the default collector pending NMAP-010.
- The local profiling agent (v1.5) with remote enrollment/sync (v1.6).
- The Desktop MVP (read-only Discover/Observe/Export wizard) and the
  single-tenant ingest server; the CLI remains the primary surface.

Because releases `v1.0.x`–`v1.3.0` are taken, the remaining milestones are renumbered from **v1.4**.

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

1. Confirm the v1.3.0 baseline against HEAD: commit SHA, platform matrix, and actual releases.
2. Inventory **every actual Nmap invocation**: arguments, profiles, output formats, permissions, scripts, parsing paths, and consumers.
3. Identify existing crates, collectors, storage interfaces, API/CLI, and CI pipelines.
4. Run tests, lint, Windows/Linux builds, and runs on an authorized lab network.
5. Review dependency licenses and redistribution obligations; don't assume bundling Nmap is obligation-free.
6. Publish a `BASELINE_AUDIT.md` with evidence, gaps, risks, and an updated backlog.

**Output:** a reproducible baseline, Nmap result fixtures, a prioritized list of features in use, and an ADR on internal contracts.

## Milestones and deliverables

| Milestone | Scope | Depends on | Verifiable exit criteria |
|---|---|---|---|
| **v1.4 — Native Discovery I** | DiscoveryBackend contracts, target parser, DNS, TCP connect, ICMP/ARP per platform, basic banners and services; rate limiting | Sprint 0 | Nmap decoupled; fixtures pass through the common model; basic TCP discovery without Nmap; benchmarks and differences documented |
| **v1.5 — Local Profiler & Agent** | Windows/systemd service, CPU/RAM/disk/processes/network, SQLite, duration and frequency, restarts | Sprint 0 | Recoverable 7-day observation; HTML/JSON report; sample coverage |
| **v1.6 — Remote Profiling & Dependencies** | Agent enrollment, mTLS or short-lived credentials, buffer/retries and revocation; merge agent observations with the shipped agentless SSH/WinRM evidence and connection graph | v1.5 | Three heterogeneous hosts observed; connections backed by evidence; revocation verified |
| **v1.7 — Native Discovery II** | SYN/UDP where applicable, service detection/versions, IPv6, traceroute, gradual fingerprinting | v1.4 | Parity matrix per feature actually used; documented Nmap fallback |
| **v2.0 — Desktop & Distributed Platform** | Tauri Desktop, multi-agent server, install and update, wizard UX | v1.5–v1.7 | Windows install without a toolchain; CLI intact; full workflow with export |

**Important:** the Desktop MVP starts in parallel from v1.5; it does not wait for v2.0. Versions are product milestones, not date promises.

## Four parallel tracks

**A. Discovery:** abstraction → native TCP → ICMP/ARP → service fingerprints → SYN/UDP/IPv6 → Nmap retirement evaluation.

**B. Observability:** local agent → agent time-series storage → remote enrollment/sync, merged with the shipped agentless SSH/WinRM probes and Prometheus/Zabbix importers.

**C. Intelligence:** shipped through v1.3.0 (grouping, evidence/confidence, right-sizing, waves, SKU/cost). Catalog freshness shipped as versioned data packages (runtime catalog dir + `orbyn catalog status|install|update`, huawei/openstack catalogs, postgres/mysql managed-database tiers); remaining: more engines and providers as catalog data, and a hosted manifest when distribution needs one.

**D. Experience:** stable CLI (shipped) → Desktop MVP (Discover/Observe/Export) → dashboards → server and agent management.

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

**P0:** Nmap usage baseline; contracts ADR; XML/JSON fixtures; target parser; TCP connect; local agent service; agent metrics schema.

**P1:** service detection; HTML reports; Tauri MVP; secure enrollment; agent→server sync.

**P2:** SYN/UDP, OS fingerprints, online pricing/catalog freshness, updater, and multi-agent server.

## Pending decisions

All pending decisions are **closed** — see
[ADR-0002](ADR-0002-platform-scope-privacy-pricing-nmap.md) (D1–D5:
platforms, unprivileged-only scanning with explicit scope, 30-day
retention without pre-v1.6 encryption, versioned pricing catalog
packages, measured-then-default Nmap retirement) and
[ADR-0003](ADR-0003-desktop-installer-updater-hardening.md) (D6–D10:
desktop subprocess-over-CLI contract, NSIS-only installer, artifacts-
now distribution with signing on cert availability, notifications-only
updater, deferred multi-agent hardening).
