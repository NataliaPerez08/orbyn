# Orbyn — Target Technical Architecture v2

**Status:** Accepted by implementation (Collector trait, Store, app layer shipped; see ADR-0001–0003) · **Date:** 2026-10-12

> Target design, not a verified inventory of the code. Crate and table names are proposals; reconcile them with the repository before refactoring.

## 1. Context and objectives

Orbyn integrates asset discovery, time-series profiling, dependency analysis, right-sizing, and migration planning. It must offer a CLI for automation, Desktop for non-technical users, and Server for distributed observation, with a shared Rust core and offline operation whenever possible.

### Non-functional requirements

- Windows and Linux as priority platforms; macOS as a later target.
- Least privilege, target authorization, and auditing of actions.
- Robust local persistence and recovery after restarts.
- Evidence, provenance, timing, and confidence for every inference.
- Versioned APIs, cancellable jobs, and backpressure.
- An interface that explains measurement and inference limitations.

## 2. Component diagram

```text
CLI ───────┐
Desktop ───┼──> Application Service / Use Cases ──> Orbyn Core
Server ────┘                │                            │
                            │              ┌─────────────┼──────────────┐
                            │              │             │              │
                            ▼              ▼             ▼              ▼
                        Job Manager   Discovery      Profiler       Intelligence
                            │         (native/       (local/        (apps, sizing,
                            │          nmap)          remote)        migration)
                            │              │             │              │
                            └──────────────┴──────┬──────┴──────────────┘
                                                  ▼
                                       Evidence + Storage API
                                                  │
                                        SQLite local / server DB*
                                                  │
                                      Exports HTML/JSON/CSV

Agent (Windows/Linux) ── authenticated transport ──> Server
Agentless collector (SSH/WinRM/SNMP) ──────────────> Server
```

`*` SQLite for the MVP and small deployments. Evaluate a server database only once concurrency, volume, or multi-tenancy needs are demonstrated; do not introduce it preemptively.

## 3. Module boundaries (proposed)

| Module | Responsibility | Must not do |
|---|---|---|
| `orbyn-core` | Entities, errors, capabilities, events, and contracts | Execute system commands |
| `orbyn-discovery` | Targets, scheduler, probes, normalization | Compute cloud costs |
| `orbyn-nmap-adapter` | Controlled Nmap invocation and parsing | Stream XML directly to consumers |
| `orbyn-profiler` | Sampling, aggregation, and quality | Infer SKUs without context |
| `orbyn-agent` | Service, buffer, identity, and telemetry | Expose an arbitrary remote shell |
| `orbyn-intelligence` | Grouping, inferences, recommendations | Treat hypotheses as facts |
| `orbyn-storage` | Repositories, migrations, retention | Business logic |
| `orbyn-cli` | Commands and machine/human output | Duplicate core logic |
| `orbyn-server` | Auth, jobs, ingestion, agents | Depend on Desktop |
| `orbyn-desktop` | Tauri, wizard, dashboards, export | Run privileged scans in the frontend |

## 4. Discovery contracts

```rust
#[async_trait::async_trait]
pub trait DiscoveryBackend: Send + Sync {
    fn capabilities(&self) -> DiscoveryCapabilities;
    async fn discover(
        &self,
        request: DiscoveryRequest,
        context: JobContext,
    ) -> Result<DiscoveryResult, DiscoveryError>;
}
```

`DiscoveryRequest`: authorized targets, ports, profile, rate budget, timeout, credentials by secure reference, and options. `JobContext`: cancellation, progress, audit ID. `DiscoveryResult`: assets, services, evidence, warnings, coverage, timestamps, and backend/versions.

**Backend selector:** `native`, `nmap`, `auto`; in `auto`, degradation is explicit and logged — never a silent change of semantics. `capabilities()` lets Desktop explain features unavailable due to permissions or platform.

## 5. Canonical data model

```text
Asset(id, addresses, hostname, os_candidates, observed_at)
Service(id, asset_id, protocol, port, product_candidate, version_candidate)
Observation(id, source, subject, kind, value, unit, timestamp, provenance)
MetricSample(asset_id, metric, value, unit, timestamp, collector_version)
ProcessObservation(asset_id, pid, start_time, executable, metrics, timestamp)
ConnectionObservation(src_asset, src_process?, dst_address, dst_port,
                      protocol, first_seen, last_seen, count)
DependencyEdge(src, dst, evidence_ids[], confidence, explanation)
ApplicationGroup(id, asset_ids[], evidence_ids[], confidence)
Assessment(id, window, coverage, assumptions, findings[])
Recommendation(id, target, proposal, evidence_ids[], assumptions[], confidence)
MigrationWave(id, assets[], constraints[], rationale)
Job(id, type, status, progress, created_at, checkpoint, errors[])
```

Use stable identifiers and UTC timestamps; keep time zones for display only. Separate **observation**, **inference**, and **recommendation** to avoid turning a guess into a fact.

## 6. Observability pipeline

1. The user selects assets and an observation window (24 h, 7, 14, 30 days, or custom).
2. A scheduler persists the job before starting; it resumes after a restart.
3. Collectors obtain CPU, RAM, disk capacity and I/O, network, and process data depending on platform and permissions.
4. Every sample carries a timestamp, unit, source, and status; missing data does not equal zero.
5. Aggregation by interval and tiered retention (raw → hourly → daily) with quotas.
6. The analyzer computes P50/P95/peaks, coverage, and observation quality.
7. Right-sizing produces options conditioned on headroom, seasonality, licensing, and constraints.

### Observation quality

Record `expected_samples`, `received_samples`, day/hour coverage, gaps, restarts, variability, and a representative window. The quality score is distinct from a recommendation's confidence. If evidence is insufficient, **abstain** and request more observation.

## 7. Agent-based and agentless

**Local agent:** Windows service or systemd, versioned configuration, SQLite buffer, disk quota, clean shutdown, health, controlled updates, and offline-exportable data.

**Distributed agent:** explicit enrollment, per-agent identity, authenticated TLS, rotation/revocation, idempotent ingestion, retries with backoff, compression, and batch limits.

**Agentless:** SSH/WinRM/SNMP adapters with protected credentials and least privilege; record unavailable metrics and semantic differences. Never store passwords in reports or logs.

## 8. Dependencies and Application Intelligence

Merge scan findings, observed connections, processes, and metadata. A TCP connection alone does not prove a functional dependency. Every `DependencyEdge` must preserve source, window, frequency, method, evidence, and explanation. Avoid grouping by port coincidence without corroboration.

## 9. Security and privacy

- CIDR/target validation, exclusions, consent, and per-network limits.
- Keep privileged processes separate from the UI and the HTTP server; never run arbitrary commands from the interface.
- Sanitize inputs; use structured process arguments, never interpolated shell.
- Credentials in OS secure stores or a configured secrets manager; TLS and mutual authentication for agents.
- Data minimization: processes, hostnames, IPs, and connections can be sensitive; define retention and export.
- Auditable logs and secret redaction; signed updates and version control.
- Dependency license review and SBOM per release.

## 10. User experience

**Discover:** targets/profiles wizard, permission validation, and progress.

**Observe:** choose local/remote, duration, interval, and data; the service keeps running if the window is closed.

**Analyze:** trends, coverage, dependencies with explanations and confidence levels.

**Plan:** right-sizing candidates, waves, and cloud destinations with assumptions and constraints.

**Export:** self-contained HTML, structured JSON, and CSV. Avoid categorical conclusions from incomplete data.

## 11. External interfaces and versioning

Propose a local HTTP API for Desktop/Server only if it simplifies reuse; Tauri can call the core directly through typed commands. Define the storage schema version, agent protocol version, and export format separately. Reversible migrations where feasible, and backups before destructive changes.

## 12. Test strategy

- Unit: target parsers, aggregations, quality score, inferences.
- Contract: the same fixture produces the same normalized result across compatible adapters.
- Integration: Windows/Linux lab with controlled hosts/services, limited permissions, and connectivity loss.
- End-to-end: wizard → job → storage → report.
- Performance: agent CPU/RAM/disk overhead, connection and job scalability.
- Security: scope limits, authentication, revocation, sanitization, and recovery.

## 13. ADRs to open

1. Evidence contract and model.
2. SQLite persistence and retention policy.
3. Agent transport, enrollment, and credentials.
4. Tauri integration: native commands vs local API.
5. `auto` backend policy and Nmap retirement.
6. Privileges and per-OS connection-capture limits.
