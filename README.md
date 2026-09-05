# Orbyn

**Open-source infrastructure discovery, dependency mapping, and migration assessment — from the command line.**

Orbyn helps teams discover infrastructure, build an accurate asset inventory, understand how systems depend on each other, and generate the data needed to plan migrations and right-size target environments. Everything is a local, single-binary CLI tool.

> **Status:** Early development — v0.2 inventory enrichment, CLI focus.

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

Orbyn is a vendor-neutral discovery and assessment layer, driven entirely from a CLI.

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

Orbyn is **not intended to become another general-purpose monitoring platform**, nor is it primarily a web service.

Telemetry is collected when it contributes to:

* infrastructure discovery;
* dependency mapping;
* migration assessment;
* capacity analysis;
* right-sizing;
* migration planning.

Existing monitoring platforms such as Prometheus and Zabbix should eventually be usable as telemetry sources rather than replaced. A web/HTTP interface is a *future option*; the CLI is the interface that matters.

## Architecture

Orbyn follows a collector-based architecture in Rust: `tokio` for async runtime, `clap` for the CLI, `sqlx` for SQLite persistence, `quick-xml` for Nmap output parsing, and `comfy-table` for terminal tables.

```text
+----------+   +----------+   +-----------+   +----------+
| discover |   |  assets  |   |  export   |   |  assess  |
+-----+----+   +----+-----+   +-----+-----+   +----+-----+
      |             |               |               |
      +-------------+---------------+---------------+
                    |
                    v
           +--------+--------+
           |    CLI (clap)   |
           +--------+--------+
                    |
                    v
           +--------+--------+
           | Discovery Coordinator / Collectors
           +--------+--------+
                    |
       +------------+------------+
       |            |            |
       v            v            v
     Nmap          SNMP         SSH/WinRM
       |            |            |
       +------------+------------+
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
         CLI output (table/json/csv)
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the detailed architecture.

## Current bootstrap

The repository currently provides:

* Rust crate scaffold (single binary, CLI-first).
* CLI commands: `discover`, `assets`, `asset`, `services`, `interfaces`, `jobs`, `annotate`, `import`, `export`, `graph`, `assess`.
* Table output for humans, `--format json|csv` for machines.
* SQLite persistence via `sqlx` with versioned migrations.
* Asset, service, interface and discovery job domain model, with capacity,
  dependency and metric-sample tables reserved for upcoming milestones.
* Collector framework with target validation (unrestricted scopes rejected).
* Nmap collector adapter (executes `nmap`, parses XML output, records
  discovery jobs, classifies device type, captures the responding MAC and
  vendor).
* SNMP collector adapter (walks the system and interface MIBs via
  `snmpwalk`, derives hostname/OS/device class, and collects interface MACs,
  MTU and operational state).
* Device classification (server / network-device / printer / storage / …).
* Inventory annotations: environment, owner, criticality and tags
  (`orbyn annotate`), preserved across re-discovery.
* Import/export hooks in JSON and CSV (`orbyn import`, `orbyn export`).
* Discovery job history CLI (`orbyn jobs`) with per-job outcomes.
* Rich asset detail command (`orbyn asset <id-or-ip>`).
* Architecture documentation, roadmap and backlog.

The next functional milestone is host-level discovery via SSH and WinRM
(v0.3), which builds on the collector framework and annotation model.

## Requirements

Current development requirements:

* Rust 1.75+ (via [rustup](https://rustup.rs))
* A C toolchain for the bundled SQLite build (standard for Rust SQLite drivers)
* Nmap for network discovery
* net-snmp-utils (`snmpwalk`) for SNMP discovery

No other external services are required.

## Install & run locally

```bash
git clone https://github.com/NataliaPerez08/orbyn.git
cd orbyn

cp .env.example .env

cargo run -- --help
```

The SQLite database is created and migrated automatically at:

```text
./data/orbyn.db
```

Point any command at a different database with `--db <path>` (or `ORBYN_DB`).

## CLI reference

```text
orbyn discover --target <cidr>                    Scan a subnet with Nmap and persist inventory
orbyn discover --target <ip> --collector snmp     Walk a host over SNMP (sysDescr + interfaces)
orbyn assets [--format table|json|csv]
orbyn asset <id-or-ip> [--format ...]             Full asset record: annotations, services, interfaces
orbyn services <id-or-ip> [--format ...]
orbyn interfaces <id-or-ip> [--format ...]
orbyn annotate <id-or-ip> --environment prod --owner <team> \
    --criticality high --tag core --remove-tag dr  Enrich inventory metadata
orbyn jobs [--limit 50] [--format ...]            Discovery history with per-job outcomes
orbyn import --format json|csv [--file <file>]    Import inventory (file or stdin)
orbyn export [--format json|csv] [--output <file>]
orbyn graph [--format ...]
orbyn assess [--format ...]
```

Example session:

```bash
# scan an authorized subnet with Nmap
orbyn discover --target 10.0.0.0/24

# walk a single switch over SNMP (needs an authorized community string)
orbyn discover --target 10.0.0.8 --collector snmp --community public

# inspect what was found
orbyn assets
orbyn asset 10.0.0.10          # full record incl. interfaces and tags
orbyn services 10.0.0.10
orbyn interfaces 10.0.0.10

# enrich the inventory (metadata is preserved across re-discovery)
orbyn annotate 10.0.0.10 --environment prod --owner platform \
    --criticality high --tag core --tag api

# discovery history and change tracking
orbyn jobs

# machine-readable inventory
orbyn assets --format json
orbyn export --format csv --output inventory.csv
orbyn import --format csv --file inventory.csv

# dependency graph (v0.4)
orbyn graph

# migration assessment (v0.5)
orbyn assess
```

By default output is a terminal table; `--format json` and `--format csv`
stream machine-readable data to stdout. Logs go to stderr, so stdout stays
clean for piping.

## Configuration

| Variable     | Default           | Purpose              |
| ------------ | ----------------- | -------------------- |
| `ORBYN_DB`   | `./data/orbyn.db` | SQLite database path |
| `ORBYN_LOG`  | `orbyn=warn`      | tracing filter (also `-v`/`-vv`) |
| `ORBYN_NMAP_BIN` | `nmap`        | Nmap binary path     |
| `ORBYN_SNMP_BIN` | `snmpwalk`   | `snmpwalk` binary path (net-snmp-utils) |
| `ORBYN_SNMP_COMMUNITY` | `public`  | Default SNMP v1/v2c community string |

## Repository layout

```text
orbyn/
├── Cargo.toml
├── src/
│   ├── main.rs                  # CLI executable (clap)
│   ├── lib.rs
│   ├── config.rs                # env/flag-based configuration
│   ├── assessment/              # migration assessment
│   ├── collectors/              # discovery collectors
│   │   ├── classify.rs          # device classification
│   │   ├── nmap.rs              # Nmap adapter
│   │   └── snmp.rs              # SNMP adapter
│   ├── domain/                  # normalized domain model
│   ├── graph/                   # dependency graph
│   ├── metrics/                 # capacity/utilization processing
│   ├── output/                  # table/json/csv rendering
│   └── store/                   # store traits + SQLite
│
├── migrations/                  # versioned SQL migrations (sqlx)
├── tests/                       # integration tests
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

### CLI-first

The command line is the primary interface. Results are human-friendly by
default (tables) and machine-readable on request (`--format json|csv`). A UI
layer must never become a prerequisite for using the tool.

### Composable collectors

Every collector should transform its observations into the same normalized domain model.

Collectors discover facts.

The rest of Orbyn should not need to care whether those facts came from Nmap, SSH, VMware, Prometheus or another source.

### Local-first

A user should be able to run Orbyn with:

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

## Security

Infrastructure discovery is security-sensitive.

Orbyn therefore:

* requires explicit discovery targets;
* rejects accidental unrestricted scans by default;
* uses read-only operations whenever possible;
* never exposes credentials in logs;
* avoids storing credentials unless absolutely necessary;
* encrypts stored secrets when credential storage becomes necessary;
* runs collectors with minimum privileges;
* maintains an audit trail for discovery operations (job history);
* clearly identifies which collector produced each observation.

Users are responsible for ensuring they have authorization to scan and inspect target infrastructure.

See [SECURITY.md](SECURITY.md).

## Roadmap

The project will evolve incrementally:

```text
v0.1    Network discovery          (done)
          ↓
v0.2    Inventory enrichment       (done)
          ↓
v0.3    Host discovery via SSH / WinRM
          ↓
v0.4    Dependency mapping
          ↓
v0.5    Migration assessment
          ↓
v1.0    Stable CLI product
          ↓
v1.2    Historical metrics + right-sizing
```

A web/HTTP interface for `orbyn` is a possible later add-on, not a goal for the
core tool.

See [ROADMAP.md](ROADMAP.md) and [BACKLOG.md](BACKLOG.md).

## Contributing

Orbyn is intended to be community-driven.

Contributions around collectors, infrastructure platforms, dependency detection, assessment rules, documentation and testing are welcome.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache License 2.0.

See [LICENSE](LICENSE).