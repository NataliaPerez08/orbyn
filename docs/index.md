# Orbyn

**Open-source infrastructure discovery, dependency mapping, and migration
assessment — from the command line.**

Orbyn helps teams discover infrastructure, build an accurate asset inventory,
understand how systems depend on each other, and generate the data needed to
plan migrations and right-size target environments. Everything is a local,
single-binary CLI tool.

!!! info "Status"
    v1.0.3 stable release — discovery, inventory, assessment, integrations,
    metrics/right-sizing and cloud adapters.

## Why Orbyn?

Infrastructure projects often begin with incomplete spreadsheets, outdated
CMDB entries, undocumented dependencies, and tribal knowledge.

Before moving or modernizing infrastructure, teams need to answer some
deceptively simple questions:

* What infrastructure actually exists?
* Which services are running?
* How are systems connected?
* Which assets belong to the same application?
* Which dependencies could affect a migration?
* What infrastructure is difficult or risky to move?
* How much CPU and RAM is provisioned — and how much is actually used?
* What target infrastructure would appropriately fit each workload?

Orbyn aims to build that picture automatically.

## What Orbyn is

Orbyn is a **vendor-neutral discovery and assessment layer**, driven entirely
from a CLI. It collects infrastructure information from multiple sources,
normalizes it into a common model, builds relationships between assets and
services, and makes that information available for inventory, dependency
analysis, migration assessment, and right-sizing.

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

Orbyn is **not intended to become another general-purpose monitoring
platform**, nor is it primarily a web service.

Telemetry is collected only when it contributes to discovery, dependency
mapping, migration assessment, capacity analysis, right-sizing, or migration
planning. Existing monitoring platforms such as Prometheus and Zabbix are
usable as telemetry *sources* rather than replaced. A web/HTTP interface is a
future option; the CLI is the interface that matters.

## Start here

| Section | What you get |
| --- | --- |
| [Installation](INSTALL.md) | Release binaries, requirements, shell completions |
| [Quickstart](quickstart.md) | First scan to first assessment in a few commands |
| [CLI reference](cli.md) | Every subcommand and flag, in one table |
| [Collectors](collectors/index.md) | How each discovery collector works and how to run it |
| [Importers](importers/index.md) | NetBox, Prometheus, Zabbix, Proxmox and cloud importers |
| [Configuration](configuration.md) | Environment variables, database backends, limits |
| [Security](security.md) | Read-only guarantees, secrets handling, boundaries |
| [Third-party notices](third-party.md) | External tools and services Orbyn can invoke |

## Guiding principles

* **Vendor neutral.** No cloud or vendor lock-in; a common normalized model.
* **Agentless first.** Nothing is installed on the systems being discovered.
* **Read-only by default.** Collectors never modify the systems they inspect.
* **Explainable assessment.** Every finding carries rule id, severity,
  evidence and the window it was observed over.
* **CLI-first.** Scriptable, pipeable, `--format json|csv` everywhere.
* **Local-first.** SQLite by default, PostgreSQL optional; your data stays
  yours.
