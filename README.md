# Orbyn

**Open-source infrastructure discovery, dependency mapping, and migration assessment.**

Orbyn helps teams discover infrastructure, build an accurate asset inventory, understand how systems depend on each other, and generate the data needed to plan migrations and right-size target environments.

> **Status:** Early development — v0.1 bootstrap.

## Why Orbyn?

Infrastructure projects often begin with incomplete spreadsheets, outdated CMDB entries, undocumented dependencies, and tribal knowledge.

Before moving or modernizing infrastructure, teams need to answer some deceptively simple questions:

* What infrastructure actually exists?
* Which services are running?
* How are systems connected?
* Which assets belong to the same application?
* Which dependencies could affect a migration?
* What infrastructure is difficult or risky to move?
* How much CPU and RAM are provisioned?
* How much CPU and RAM are actually being used?
* What target infrastructure would appropriately fit each workload?

Orbyn aims to build that picture automatically.

## What Orbyn is

Orbyn is designed as a vendor-neutral discovery and assessment layer.

It collects infrastructure information from multiple sources, normalizes it into a common model, builds relationships between assets and services, and makes that information available for inventory, dependency analysis, migration assessment, and right-sizing.

```text
                  Infrastructure

                       │
                       ▼
              ┌─────────────────┐
              │    Discovery    │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │    Inventory    │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │   Orbyn Graph   │
              │  Dependencies   │
              └────────┬────────┘
                       │
             ┌─────────┼─────────┐
             ▼         ▼         ▼
          Metrics   Assessment  Reports
             │         │
             └────┬────┘
                  ▼
             Right-sizing
                  │
                  ▼
           Migration Planning
```

## What Orbyn is not

Orbyn is **not intended to become another general-purpose monitoring platform**.

Telemetry is collected when it contributes to:

* infrastructure discovery;
* dependency mapping;
* migration assessment;
* capacity analysis;
* right-sizing;
* migration planning.

Existing monitoring platforms such as Prometheus and Zabbix should eventually be usable as telemetry sources rather than replaced.

## Architecture

Orbyn follows a collector-based architecture in Rust: `tokio` for async runtime, `axum` for the HTTP API, `sqlx` for SQLite persistence, and `quick-xml` for Nmap output parsing.

```text
+-------------+
| CLI/Web/API |
+------+------+
       |
       v
+------+-------+
| Discovery   |
| Coordinator |
+------+-------+
       |
       +-------------------------------+
       |          |          |         |
       v          v          v         v
     Nmap        SNMP       SSH      WinRM
       |          |          |         |
       +----------+----------+---------+
                  |
                  v
          +-------+--------+
          | Normalization  |
          +-------+--------+
                  |
                  v
          +-------+--------+
          | SQLite / Store |
          +-------+--------+
                  |
           +------+------+
           |             |
           v             v
      Orbyn Graph    Metrics Engine
           |             |
           +------+------+
                  |
                  v
          Assessment Engine
                  |
                  v
          Exporters / Reports
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed architecture.

## Current bootstrap

The repository currently provides:

* Rust crate scaffold (single binary: `serve` / `discover`).
* axum HTTP API.
* SQLite persistence via `sqlx` with versioned migrations.
* Initial asset, service, discovery job, capacity, dependency and metric sample domain model.
* Schema reserved for CPU/RAM capacity and utilization (`asset_capacity`, `metric_samples`, `dependencies`).
* `/healthz` endpoint.
* `/api/v1/assets` endpoint.
* Collector framework with target validation (unrestricted scopes rejected).
* Nmap collector adapter and XML fixture parsing skeleton.
* Initial architecture documentation.
* Roadmap and backlog.

The first functional discovery milestone is the **Nmap collector**.

## Requirements

Current development requirements:

* Rust 1.75+ (via [rustup](https://rustup.rs))
* A C toolchain for the bundled SQLite build (standard for Rust SQLite drivers)
* Nmap for network discovery

No other external services are required for a local install.

## Run locally

```bash
git clone https://github.com/NataliaPerez08/orbyn.git
cd orbyn

cp .env.example .env

cargo run -- serve
```

By default, the API listens on:

```text
http://localhost:8080
```

Verify that Orbyn is running:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/api/v1/assets
```

The SQLite database is created and migrated automatically at:

```text
./data/orbyn.db
```

Run a single Nmap discovery job:

```bash
cargo run -- discover --target 10.0.0.0/24
```

Prefer `make` for common tasks — see the `Makefile` (build, test, lint, fmt, run).

## Configuration

| Variable     | Default           | Purpose              |
| ------------ | ----------------- | -------------------- |
| `ORBYN_ADDR` | `:8080`           | HTTP listen address  |
| `ORBYN_DB`   | `./data/orbyn.db` | SQLite database path |
| `ORBYN_LOG`  | `orbyn=info,tower_http=info` | tracing filter |
| `ORBYN_NMAP_BIN` | `nmap`        | Nmap binary path     |

## Repository layout

```text
orbyn/
├── Cargo.toml
├── src/
│   ├── main.rs                  # CLI executable (serve / discover)
│   ├── lib.rs
│   ├── config.rs                # env-based configuration
│   ├── api/                     # axum HTTP API
│   ├── assessment/              # migration assessment
│   ├── collectors/              # discovery collectors
│   ├── domain/                  # normalized domain model
│   ├── graph/                   # dependency graph
│   ├── metrics/                 # capacity/utilization processing
│   └── store/                   # store traits + SQLite
│
├── migrations/                  # versioned SQL migrations (sqlx)
│
├── Makefile
├── .env.example
├── .gitignore
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
└── README.md
```

## Guiding principles

### Vendor neutral

Discovery and assessment must not depend on a particular cloud or infrastructure provider.

AWS, Azure, Google Cloud, Huawei Cloud, VMware, OpenStack, bare metal and other platforms should ultimately feed the same normalized model.

### Agentless first

Prefer existing protocols and APIs before requiring software installation.

Initial collection methods include:

* Nmap
* SNMP
* SSH
* WinRM
* infrastructure APIs
* existing monitoring systems

Agents should only be introduced when they provide information that cannot reasonably be obtained agentlessly.

### Read-only by default

Discovery should not modify the systems being inspected.

Collectors must operate with the minimum privileges necessary.

### Explainable assessment

Orbyn should never produce a mysterious migration score or right-sizing recommendation.

Recommendations must expose the evidence and rules that produced them.

### Composable collectors

Every collector should transform its observations into the same normalized domain model.

Collectors discover facts.

The rest of Orbyn should not need to care whether those facts came from Nmap, SSH, VMware, Prometheus or another source.

### Local-first

A user should be able to start Orbyn with:

```text
one binary
+
one SQLite database
```

Large-scale deployment can come later.

### Scale without rewriting the domain

Storage, scheduling and telemetry infrastructure may evolve independently as Orbyn grows.

The underlying asset and dependency model should remain portable.

## Planned collectors

| Collector  | Information                           | Target |
| ---------- | ------------------------------------- | ------ |
| Nmap       | Hosts, ports and service fingerprints | v0.1   |
| SNMP       | Network and device metadata           | v0.2   |
| SSH        | Linux inventory and capacity          | v0.3+  |
| WinRM      | Windows inventory and capacity        | v0.3+  |
| VMware     | VM and hypervisor inventory           | Later  |
| NetBox     | Source-of-truth import/export         | Later  |
| Prometheus | Historical utilization                | v1.2+  |
| Zabbix     | Historical utilization                | v1.2+  |
| eBPF       | Runtime dependency observations       | Later  |

## Orbyn Graph

The dependency graph is intended to become one of Orbyn's core capabilities.

Assets, services and observed relationships can be represented conceptually as:

```text
                Internet
                    │
                    ▼
              Load Balancer
                 /      \
                ▼        ▼
             web-01    web-02
                \        /
                 ▼      ▼
                  api-01
                 /      \
                ▼        ▼
            postgres    redis
```

Instead of treating infrastructure as a flat spreadsheet, Orbyn should be able to answer questions such as:

* What depends on this server?
* Which systems communicate with this database?
* What would be affected if this host moved?
* Which assets appear to belong to the same application?
* Which dependency crosses a migration boundary?
* Which systems should probably migrate together?

## CPU and RAM assessment

Orbyn distinguishes between **capacity** and **utilization**.

### Capacity

Examples include:

* CPU model
* architecture
* sockets
* physical cores
* logical CPUs / threads
* installed RAM

Capacity can often be discovered through SSH, WinRM, hypervisor APIs or cloud APIs.

### Utilization

Examples include:

* CPU average
* CPU peak
* CPU p95
* CPU p99
* RAM average
* RAM peak
* RAM p95
* RAM p99
* swap utilization
* Linux load averages

A single observation must always be identified as a **snapshot**.

It must never be presented as sufficient historical evidence for right-sizing.

Historical metrics can eventually be collected directly or imported from existing telemetry systems.

## Right-sizing

A future Orbyn assessment could transform:

```text
Current infrastructure

8 vCPU
32 GB RAM
```

and observed utilization:

```text
CPU p95: 38%
RAM p95: 18 GB
```

into an explainable recommendation:

```text
Recommended baseline

4 vCPU
24 GB RAM

Risk: Low
```

Recommendations should include the observations, safety margins and rules used to produce the result.

## API direction

Initial namespace:

```text
GET  /healthz

GET  /api/v1/assets
GET  /api/v1/assets/{id}
GET  /api/v1/assets/{id}/services
GET  /api/v1/assets/{id}/metrics
GET  /api/v1/assets/{id}/dependencies

POST /api/v1/discovery/jobs
GET  /api/v1/discovery/jobs/{id}

GET  /api/v1/graph
GET  /api/v1/assessments
```

Endpoints not implemented yet are part of the planned API and may change before v1.0.

## Security

Infrastructure discovery is security-sensitive.

Orbyn should therefore:

* require explicit discovery targets;
* reject accidental unrestricted scans by default;
* use read-only operations whenever possible;
* never expose credentials in logs;
* avoid storing credentials unless absolutely necessary;
* encrypt stored secrets when credential storage becomes necessary;
* run collectors with minimum privileges;
* maintain an audit trail for discovery operations;
* clearly identify which collector produced each observation.

Users are responsible for ensuring they have authorization to scan and inspect target infrastructure.

See [SECURITY.md](SECURITY.md).

## Roadmap

The project will evolve incrementally:

```text
v0.1    Network discovery
          ↓
v0.2    Inventory enrichment
          ↓
v0.3    Host discovery via SSH / WinRM
          ↓
v0.4    Dependency mapping
          ↓
v0.5    Migration assessment
          ↓
v1.0    Stable discovery platform
          ↓
v1.2    Historical metrics + right-sizing
```

See [ROADMAP.md](ROADMAP.md) and [BACKLOG.md](BACKLOG.md).

## Contributing

Orbyn is intended to be community-driven.

Contributions around collectors, infrastructure platforms, dependency detection, assessment rules, documentation and testing are welcome.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0.

See [LICENSE](LICENSE).