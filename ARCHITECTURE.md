# Architecture

## Objective

Orbyn converts heterogeneous discovery data into a normalized infrastructure graph suitable for migration assessment.

The architecture deliberately separates **collection**, **normalization**, **storage**, **assessment**, and **presentation** so individual pieces can evolve without coupling the project to a particular scanner or cloud provider.

## Technology baseline

Orbyn is a Rust project:

- **Runtime:** async Rust on `tokio`.
- **HTTP API:** `axum` (hyper/tower based), mirroring the previous Go `net/http`
  design goal of minimal dependencies and composable middleware.
- **Persistence:** `sqlx` against SQLite. The schema is versioned via `sqlx`
  migrations in `migrations/`.
- **CLI:** `clap`. A single binary exposes `serve` and `discover` subcommands,
  keeping the "one binary + one SQLite database" local-first promise.
- **Logging:** `tracing`/`tracing-subscriber`, structured and env-configurable.
- **XML parsing (Nmap):** `quick-xml`, fast and dependency-light.

Crate layout mirrors the logical layers:

```text
src/
├── main.rs               # clap CLI: serve / discover
├── lib.rs                # library surface
├── config.rs             # env-based configuration
├── domain/               # normalized domain model
├── collectors/           # Collector trait + scanner adapters
│   ├── types.rs          # Collector, ScanTarget, validation
│   └── nmap.rs           # Nmap adapter (v0.1 milestone)
├── store/                # persistence
│   ├── traits.rs         # Store trait (repository boundary)
│   └── sqlite.rs         # SQLite via sqlx
├── graph/                # dependency graph
├── metrics/              # capacity/utilization processing
├── assessment/           # migration assessment engine
└── api/                  # axum HTTP API
```

## Components

### 1. Collectors

Collectors retrieve data from external systems or hosts.

Examples:

- Nmap XML output.
- SNMP queries.
- SSH commands on Linux.
- WinRM/CIM queries on Windows.
- vCenter APIs.
- NetBox.
- Zabbix and Prometheus.
- Flow telemetry or eBPF.

Collectors must return typed observations and never write directly to database
tables. They implement the `Collector` trait, which requires:

- a stable collector name;
- validated, explicitly scoped targets;
- read-only behavior;
- subprocess targets passed as argument vectors, never shell strings.

### 2. Normalization layer

The normalization layer translates vendor/tool-specific observations into Orbyn
domain objects:

```text
Asset
Interface
Address
Service
Dependency
Capacity
MetricSample
DiscoveryJob
Observation
```

This boundary is important. Nmap may call something a host and VMware may call
it a VM, but assessment logic should operate on a normalized `Asset`. The domain
types live in `src/domain/`, are marked `#[derive(Serialize, Deserialize)]` for
API/export, and are the single vocabulary shared by collectors, store, graph,
metrics, assessment and API.

### 3. Persistence

Initial storage is SQLite via `sqlx`:

- zero external services for local installs;
- easy packaging and evaluation;
- transactional relational model;
- sufficient for the initial single-node product.

Migrations are plain SQL in `migrations/` and run automatically at startup.
`sqlx::migrate!` embeds them at compile time, so the binary has no runtime
dependency on a migration tool.

SQLite is not a permanent constraint. The `Store` trait in
`src/store/traits.rs` isolates persistence so PostgreSQL can be offered for
multi-user or larger deployments without touching collectors or assessment.

### 4. Assessment engine

The assessment layer evaluates normalized data instead of raw collector output.

Planned outputs include:

- migration complexity score;
- unsupported/legacy OS warnings;
- dependency risk;
- exposed-service risk;
- possible application groups;
- over-provisioning indicators;
- CPU/RAM target recommendations;
- cloud-target compatibility rules.

Every recommendation should include its evidence and rule/version. The v0.5
engine will be rule-driven; `src/assessment/` currently provides the
`Finding`/`Severity` vocabulary and a placeholder scoring function.

### 5. Dependency graph

Dependencies are modeled as directional edges:

```text
Asset A --tcp/5432--> Asset B
```

Evidence may come from:

- active connections;
- firewall/network flow logs;
- eBPF;
- service configuration;
- user-confirmed relationships.

Every edge should retain source and confidence. Guesses should look like
guesses, not divine revelation. `src/graph/` provides an in-memory graph over
persisted `Dependency` edges with forward/reverse lookups.

### 6. API

The axum HTTP API is the boundary for CLI/UI/automation clients.

Versioned endpoints live under `/api/v1`. The router is assembled in
`src/api/`, handlers extract an app state holding the store and return JSON.
Middleware needs (CORS, tracing, request logging) are satisfied via
`tower-http`.

## Data-flow example

```text
Nmap scan
   |
   v
Nmap adapter (subprocess, args not shell)
   |
   v
Nmap XML parser (quick-xml)
   |
   v
[]Observation
   |
   v
Normalizer -------> Reconciliation/deduplication
   |                         |
   +-------------------------+
             |
             v
           Assets (Store)
             |
      +------+-------+
      |              |
      v              v
 Assessment       Dependency graph
      |              |
      +------+-------+
             v
       Report / API
```

## CPU and memory design

Capacity and utilization are separate models.

### Capacity

One current hardware/VM allocation per asset:

```text
asset_capacity
- cpu_model
- cpu_sockets
- cpu_cores
- cpu_threads
- ram_total_mb
- collected_at
```

### Utilization

Time-series observations:

```text
metric_samples
- sampled_at
- cpu_usage_percent
- ram_used_mb
- ram_available_mb
- swap_used_mb
- load_1m
- load_5m
- load_15m
```

Right-sizing must specify its observation window, sample count, aggregation,
and safety factor. `src/metrics/` provides windowed aggregation with a minimum
sample-count guard; a single snapshot is never treated as utilization evidence.

## Future scaling

Potential evolution without changing the collector contract:

```text
SQLite     -> PostgreSQL
in-process -> worker queue / task scheduler
local data -> Prometheus/VictoriaMetrics integration
single API -> API + collectors deployed remotely
```

A remote collector/agent should communicate outbound to the server where
possible, minimizing inbound firewall requirements.

## Security boundaries

Collectors operate against user-provided network targets and credentials,
making them the highest-risk component.

Rules:

- read-only operations by default;
- scoped targets (targets validated by `validate_target`, unrestricted
  `0.0.0.0/0`-style scopes rejected);
- explicit credential profiles;
- secrets never returned through normal API responses;
- subprocess arguments, never shell interpolation (Nmap/SSH commands built as
  `std::process`/`tokio::process` argument vectors);
- discovery job audit records;
- request limits and authorization before multi-user deployments.