# Architecture

## Objective

Orbyn converts heterogeneous discovery data into a normalized infrastructure graph suitable for migration assessment.

The architecture deliberately separates **collection**, **normalization**, **storage**, **assessment**, and **presentation** so individual pieces can evolve without coupling the project to a particular scanner or cloud provider.

## Technology baseline

Orbyn is a Rust project:

- **Runtime:** async Rust on `tokio`.
- **CLI:** `clap`, with `comfy-table` for terminal tables. Every interaction is
  a subcommand; the CLI is the product boundary.
- **Presentation:** `src/output/` renders results as tables by default, or as
  `json`/`csv` for machine consumption. Logs go to stderr so stdout stays clean
  for piping.
- **Persistence:** `sqlx` against SQLite. The schema is versioned via `sqlx`
  migrations in `migrations/`.
- **Logging:** `tracing`/`tracing-subscriber`, structured and env-configurable.
- **XML parsing (Nmap):** `quick-xml`, fast and dependency-light.

Crate layout mirrors the logical layers:

```text
src/
├── main.rs               # clap CLI: discover / assets / services / export / graph / assess
├── lib.rs                # library surface
├── config.rs             # env/flag-based configuration
├── domain/               # normalized domain model
├── parsing.rs            # shared text parsing (CSV lines, ### sections)
├── collectors/           # Collector trait + scanner adapters
│   ├── types.rs          # Collector, ScanTarget, CpuFacts, validation
│   ├── credentials.rs    # CredentialProfile (no stored secrets)
│   ├── classify.rs       # device classification heuristics
│   ├── nmap.rs           # Nmap adapter (v0.1 milestone)
│   ├── snmp.rs           # SNMP adapter (v0.2 milestone)
│   ├── ssh.rs            # SSH transport + Linux host collector (v0.3)
│   ├── windows.rs        # Windows host collector over PowerShell (v0.3)
│   └── dns.rs            # DNS relationship evidence (v0.4)
├── store/                # persistence
│   ├── traits.rs         # Store trait (repository boundary)
│   └── sqlite.rs         # SQLite via sqlx
├── graph/                # dependency graph
├── metrics/              # capacity/utilization processing
├── assessment/           # migration assessment engine
│   ├── rules.rs          # rule catalog + evaluators
│   └── grouping.rs       # application grouping (union-find)
└── output/               # table / json / csv rendering
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

Host-level collectors (v0.3) authenticate through a **credential profile**
(`src/collectors/credentials.rs`): a login user, a port and an optional
identity-file path. Orbyn deliberately stores no credentials — authentication
is delegated to ssh-agent or the referenced key, so secret material never
passes through the CLI, logs or database. The Linux and Windows collectors
share one `SshTransport`; a native WinRM transport can implement the same
command contract later without touching parsing or the store.

### 2. Normalization layer

The normalization layer translates vendor/tool-specific observations into Orbyn
domain objects:

```text
Asset
Interface
Address
Service
Filesystem
RunningService
Dependency
Capacity
MetricSample
DiscoveryJob
Observation
```

Collectors normalize vendor-specific output into this model **and** enrich it:
Nmap reports hosts, ports, OS matches, and the responding MAC address with its
vendor; SNMP reports `sysDescr`/`sysName` plus the full interface table
(`ifDescr`, `ifPhysAddress`, `ifMtu`, `ifOperStatus`). A classifier maps that
evidence onto a small set of device classes (`server`, `network-device`,
`printer`, ...). Inventory annotations (environment, owner, criticality, tags)
are user metadata set through the CLI and preserved across re-discovery.

This boundary is important. Nmap may call something a host and VMware may call
it a VM, but assessment logic should operate on a normalized `Asset`. The domain
types live in `src/domain/`, are marked `#[derive(Serialize, Deserialize)]` for
JSON output/export, and are the single vocabulary shared by collectors, store,
graph, metrics, assessment and CLI output.

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

The assessment layer evaluates normalized data instead of raw collector
output. `src/assessment/` (v0.5) is a versioned rule engine:

- `rules.rs` holds the catalog: small pure functions over an
  `AssessmentInput` (full inventory snapshot) that append findings. Rules
  cover legacy/EOL OS, insecure and management service exposure, dependency
  hubs (blast radius), external endpoints, unconfirmed edges, missing
  capacity and near-full filesystems.
- Every finding carries rule id, severity, rationale and evidence; the report
  carries `rules_version` so results stay comparable across releases.
- Scoring: severity weights (Info 2 / Warning 10 / High 25) accumulate into a
  per-asset 0-100 complexity score, averaged into an overall score with a
  low/medium/high band.
- `grouping.rs` provides application grouping primitives: union-find over
  runtime/manual dependency edges (DNS alias evidence excluded), producing
  likely co-migrating application groups.

Planned later outputs include over-provisioning indicators, CPU/RAM target
recommendations (v1.2 right-sizing) and cloud-target compatibility rules.
`orbyn assess --rules` lists the catalog.

### 5. Dependency graph

Dependencies are modeled as directional edges:

```text
Asset A --tcp/5432--> Asset B
```

Evidence may come from:

- active connections (v0.4: the SSH/Windows probes report established
  sessions; the store reconciles each remote endpoint against known assets
  and upserts an edge with `active-connections` evidence);
- DNS relationships (v0.4: `orbyn deps dns` forward-resolves asset hostnames
  and links assets whose hostnames point at each other — low-confidence
  alias evidence, not a runtime dependency);
- firewall/network flow logs (planned);
- eBPF (planned);
- service configuration (planned);
- user-confirmed relationships (`orbyn deps add` / `orbyn deps confirm`).

Every edge retains its evidence source and confidence; manual confirmation
raises confidence to 1.0. Guesses look like guesses: unconfirmed edges render
dotted in Mermaid output. Raw connection observations are persisted in
`asset_connections` so the evidence behind each edge stays inspectable
(`orbyn connections <id-or-ip>`). `src/graph/` provides an in-memory graph
over persisted `Dependency` edges with forward/reverse lookups.

### 6. CLI

The command line is the interface. Each subcommand (`discover`, `assets`,
`asset`, `services`, `interfaces`, `capacity`, `disks`, `host-services`,
`connections`, `jobs`, `annotate`, `import`, `export`, `graph`, `deps`,
`assess`) fetches data through the `Store` trait, computes results, and
delegates rendering to `src/output/`.

Inventory enrichment is a read/write CLI surface:

- `orbyn asset <id-or-ip>` shows annotations, services and interfaces;
- `orbyn annotate <id-or-ip> --environment --owner --criticality --tag`
  applies user metadata that anchor migration planning;
- `orbyn jobs` exposes discovery history with per-job outcomes (assets,
  services, duration, status) for change tracking;
- `orbyn import` and `orbyn export` provide inventory interchange hooks in
  JSON and CSV.

Rendering rules:

- default output is a terminal table (`comfy-table`);
- `--format json|csv` streams machine-readable data to stdout;
- diagnostics and logs go to stderr.

A web/HTTP interface is intentionally **not** part of the core; it would be a
later optional add-on built on the same library surface and store.

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
   CLI output (table / json / csv)
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
SQLite        -> PostgreSQL
local process -> optional distributed collectors / worker queue
local data    -> Prometheus/VictoriaMetrics integration
CLI only      -> optional web UI/HTTP API add-on (later, non-core)
```

If remote collectors or a server are ever introduced, they should communicate
outbound where possible, minimizing inbound firewall requirements.

## Security boundaries

Collectors operate against user-provided network targets and credentials,
making them the highest-risk component.

Rules:

- read-only operations by default;
- scoped targets (targets validated by `validate_target`, unrestricted
  `0.0.0.0/0`-style scopes rejected);
- explicit credential profiles;
- secrets never exposed through CLI or API output;
- subprocess arguments, never shell interpolation (Nmap/SSH commands built as
  `std::process`/`tokio::process` argument vectors);
- discovery job audit records (stored job history surfaced by the CLI);
- least-privilege and scoped operation for any future multi-user or web layer.