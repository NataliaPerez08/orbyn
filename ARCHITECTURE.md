# Architecture

## Objective

OpenMigra converts heterogeneous discovery data into a normalized infrastructure graph suitable for migration assessment.

The architecture deliberately separates **collection**, **normalization**, **storage**, **assessment**, and **presentation** so individual pieces can evolve without coupling the project to a particular scanner or cloud provider.

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

Collectors should return typed observations and should not write directly to database tables.

### 2. Normalization layer

The normalization layer translates vendor/tool-specific observations into OpenMigra domain objects:

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

This boundary is important. Nmap may call something a host and VMware may call it a VM, but assessment logic should operate on a normalized `Asset`.

### 3. Persistence

Initial storage is SQLite.

Reasons:

- zero external services for local installs;
- easy packaging and evaluation;
- transactional relational model;
- sufficient for the initial single-node product.

SQLite is not a permanent constraint. Repository interfaces should eventually isolate persistence so PostgreSQL can be offered for multi-user or larger deployments.

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

Every recommendation should include its evidence and rule/version.

### 5. Dependency graph

Dependencies should be modeled as directional edges:

```text
Asset A --tcp/5432--> Asset B
```

Evidence may come from:

- active connections;
- firewall/network flow logs;
- eBPF;
- service configuration;
- user-confirmed relationships.

Every edge should retain source and confidence. Guesses should look like guesses, not divine revelation.

### 6. API

The Go API is the boundary for CLI/UI/automation clients.

Versioned endpoints live under `/api/v1`.

The first implementation uses the standard library `net/http` router to minimize dependencies. A third-party router can be introduced only when routing/middleware needs justify it.

## Data-flow example

```text
Nmap scan
   |
   v
Nmap parser
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
           Assets
             |
      +------+-------+
      |              |
      v              v
 Assessment     Dependency graph
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

Right-sizing must specify its observation window, sample count, aggregation, and safety factor.

## Future scaling

Potential evolution without changing the collector contract:

```text
SQLite     -> PostgreSQL
in-process -> worker queue
local data -> Prometheus/VictoriaMetrics integration
single API -> API + collectors deployed remotely
```

A remote collector/agent should communicate outbound to the server where possible, minimizing inbound firewall requirements.

## Security boundaries

Collectors operate against user-provided network targets and credentials, making them the highest-risk component.

Rules:

- read-only operations by default;
- scoped targets;
- explicit credential profiles;
- secrets never returned through normal API responses;
- sanitization of subprocess arguments;
- no shell interpolation for Nmap/SSH commands;
- discovery job audit records;
- request limits and authorization before multi-user deployments.
