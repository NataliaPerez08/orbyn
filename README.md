# OpenMigra

OpenMigra is an open-source infrastructure discovery and migration-assessment platform. Its goal is to help teams discover assets, identify services and dependencies, build migration-ready inventories, and eventually recommend right-sized target infrastructure.

> Status: early development / v0.1 bootstrap.

## Why OpenMigra?

Migration projects often start with incomplete spreadsheets, stale CMDB entries, and tribal knowledge. OpenMigra aims to create a vendor-neutral discovery layer that can answer:

- What infrastructure exists?
- Which services are running?
- How are systems connected?
- Which assets belong to the same application?
- What is difficult or risky to migrate?
- How much CPU and RAM are provisioned and actually used?
- What target size is appropriate in AWS, Azure, Google Cloud, Huawei Cloud, or another platform?

## Scope

OpenMigra is **not** intended to become another general-purpose monitoring platform. Discovery and telemetry are collected to support migration assessment, dependency mapping, planning, and right-sizing.

## Initial architecture

```text
                 +---------------------+
                 |   CLI / Web / API   |
                 +----------+----------+
                            |
                            v
+------------+     +--------+---------+     +----------------+
| Collectors | --> | Normalization    | --> | SQLite / Store |
+------------+     +------------------+     +-------+--------+
 | Nmap                                              |
 | SNMP                                              v
 | SSH                                      +--------+---------+
 | WinRM                                    | Assessment Engine|
 | APIs                                     +--------+---------+
 | eBPF (later)                                      |
                                                      v
                                             +--------+---------+
                                             | Exporters/Reports|
                                             +------------------+
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Current bootstrap

The repository currently provides:

- Go HTTP API.
- SQLite persistence.
- Initial asset and service data model.
- Schema reserved for CPU/RAM capacity and utilization metrics.
- `/healthz` endpoint.
- `/api/v1/assets` endpoint.
- Initial architecture and roadmap documentation.

The Nmap collector is the first planned functional milestone.

## Requirements

- Go 1.22+
- A C compiler is **not** required by the selected SQLite driver.
- Nmap will be required once the discovery collector lands.

## Run locally

```bash
git clone https://github.com/your-org/openmigra.git
cd openmigra
cp .env.example .env
make run
```

The default API listens on `http://localhost:8080`.

Test it:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/api/v1/assets
```

The SQLite database is created automatically at `./data/openmigra.db`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `OPENMIGRA_ADDR` | `:8080` | HTTP listen address |
| `OPENMIGRA_DB` | `./data/openmigra.db` | SQLite database path |

## Repository layout

```text
openmigra/
├── cmd/server/             # API executable
├── internal/
│   ├── db/                 # SQLite and schema
│   ├── httpapi/            # HTTP handlers
│   └── model/              # Domain models
├── migrations/             # Versioned SQL reference migrations
├── docs/
│   ├── ARCHITECTURE.md
│   ├── ROADMAP.md
│   └── BACKLOG.md
├── .env.example
├── .gitignore
├── CONTRIBUTING.md
├── SECURITY.md
├── LICENSE
├── Makefile
├── README.md
└── go.mod
```

## Guiding principles

1. **Vendor neutral.** Collection and assessment should not depend on one cloud provider.
2. **Explainable recommendations.** Migration scores and right-sizing decisions must expose why they were produced.
3. **Agentless first, agents when justified.** Use Nmap, SNMP, SSH, WinRM, APIs, and existing monitoring data before requiring software installation.
4. **Read-only discovery by default.** A discovery tool should not surprise production systems.
5. **Composable collectors.** Every source maps into a normalized domain model.
6. **Local-first.** A user should be able to start with one binary and SQLite.
7. **Scale later without rewriting the domain.** Storage and job execution can evolve independently.

## Planned collectors

| Collector | Purpose | Phase |
|---|---|---|
| Nmap | Hosts, ports, service fingerprints | v0.1 |
| SNMP | Network/device metadata | v0.2 |
| SSH | Linux inventory and capacity | v0.3+ |
| WinRM | Windows inventory and capacity | v0.3+ |
| NetBox | Import/export source-of-truth data | Later |
| Zabbix/Prometheus | Historical utilization | v1.2+ |
| eBPF | Runtime dependency mapping | Later |

## CPU and RAM assessment

Starting around v1.2, OpenMigra should distinguish **capacity** from **utilization**.

Capacity examples:

- CPU model, sockets, cores and threads.
- Installed RAM.
- Architecture.

Utilization examples:

- CPU average, peak, p95 and p99.
- RAM average, peak, p95 and p99.
- Swap utilization.
- Linux load averages where applicable.

A single observation must be labeled as a snapshot and must not be treated as historical right-sizing evidence.

## API direction

Initial namespace:

```text
GET  /healthz
GET  /api/v1/assets
POST /api/v1/discovery/jobs       # planned
GET  /api/v1/discovery/jobs/{id}  # planned
GET  /api/v1/assets/{id}          # planned
GET  /api/v1/assets/{id}/services # planned
GET  /api/v1/assets/{id}/metrics  # planned
```

## Security

Network discovery is security-sensitive. OpenMigra should therefore:

- require explicit target scopes;
- refuse accidental unrestricted scans by default;
- keep credentials out of logs and the database unless encrypted;
- run collectors with the minimum required privileges;
- maintain an audit trail for discovery jobs;
- clearly document that users must have authorization to scan target networks.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security guidance is in [SECURITY.md](SECURITY.md).

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md) and [docs/BACKLOG.md](docs/BACKLOG.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
