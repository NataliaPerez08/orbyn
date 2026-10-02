# Orbyn

**Open-source infrastructure discovery, dependency mapping, and migration assessment — from the command line.**

Orbyn helps teams discover infrastructure, build an accurate asset inventory, understand how systems depend on each other, and generate the data needed to plan migrations and right-size target environments. Everything is a local, single-binary CLI tool.

> **Status:** v1.0.3 stable release — discovery, inventory, assessment, integrations, metrics/right-sizing and cloud adapters.

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

Orbyn follows a collector-based architecture in Rust: `tokio` for async runtime, `clap` for the CLI, `sqlx` for SQLite/PostgreSQL persistence, `quick-xml` for Nmap output parsing, and `comfy-table` for terminal tables.

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
     Nmap          SNMP         SSH / PowerShell
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
            | Store (SQLite / PostgreSQL) |
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

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the detailed architecture.

## Current bootstrap

The repository currently provides:

* Rust crate scaffold (single binary, CLI-first).
* CLI commands: `discover`, `assets`, `asset`, `services`, `interfaces`, `capacity`, `disks`, `host-services`, `connections`, `metrics`, `jobs`, `audit`, `annotate`, `import`, `export`, `graph`, `deps`, `assess`.
* Table output for humans, `--format json|csv` for machines.
* SQLite persistence by default, PostgreSQL backend for any `postgres://` URL, both via `sqlx` with versioned migrations.
* Asset, service, interface and discovery job domain model, with capacity,
  dependency and metric-sample persistence for right-sizing.
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
* Host-level discovery (v0.3):
  * SSH collector for Linux (OS, kernel, hostname, CPU/RAM capacity,
    filesystem inventory, running systemd services) via the `ssh` binary.
  * Windows collector (OS, CPU, RAM, disks, running services) running
    read-only PowerShell CIM queries over either transport: the Windows
    OpenSSH Server, or the native WS-Man/WinRM transport over HTTPS
    (`--collector winrm`, Basic auth through `curl`).
  * Credential profile abstraction: ssh-agent / identity-file authentication
    for SSH, memory-only Basic credentials for WinRM; no credentials stored
    or logged.
  * `orbyn capacity`, `orbyn disks`, `orbyn host-services` commands; the
    asset detail view shows every recorded facet.
  * Virtualization metadata: host probes detect the hypervisor
    (`systemd-detect-virt`/DMI on Linux, `Win32_ComputerSystem` on Windows)
    and normalize it into a canonical vocabulary (`kvm`, `vmware`,
    `virtualbox`, `hyperv`, `xen`, container runtimes, ...) stored on
    capacity rows and rendered by `orbyn capacity`.
* Right-sizing foundation (v0.5):
  * SSH probes snapshot CPU/RAM/swap/load three times (~2s apart) into
    `metric_sample` observations persisted per asset.
  * `orbyn metrics <id-or-ip>` summarizes a utilization window with
    avg/p95/p99/peak CPU and RAM plus a `SampleConfidence` label based on
    sample count and validity.
* CPU/RAM/swap utilization and right-sizing (historical metrics milestone):
  * `orbyn prometheus import` pulls a week of historical CPU/RAM/swap
    utilization from a Prometheus server (`/api/v1/query_range` through
    `curl`; node_exporter queries by default, overridable) and maps series
    onto assets by the `instance` label (IP or hostname). Re-imports are
    idempotent.
  * `orbyn zabbix import` does the same from a Zabbix JSON-RPC API
    (`host.get` / `item.get` / `history.get` through `curl`), mapping hosts
    onto assets by interface IP, then by name. Read-only: Orbyn never writes
    to Zabbix.
  * Utilization windows carry their temporal span; `orbyn metrics` reports
    span, confidence and right-sizing readiness (>= 168h of history with
    high confidence — snapshots alone never qualify). A window spanning two
    full weeks also reports the prior-vs-recent p95 trend.
  * Rule catalog 0.8.0: `rs.window-insufficient` guidance, CPU/RAM
    over-provisioned suggestions (p99 + 50% headroom), CPU/RAM
    saturation warnings (p95 >= 90%), sustained swap pressure, a
    week-over-week growth warning, and oversized-storage suggestions, each
    carrying its observation window as evidence.
* Dependency mapping (v0.4):
  * Active connection observations from the SSH/Windows host probes
    (`ss -tnp` / `Get-NetTCPConnection`), reconciled into dependency edges
    whenever the remote endpoint matches a known asset.
  * DNS relationship evidence (`orbyn deps dns`; forward, CNAME-chain and
    PTR alias matching, low confidence).
  * Manual relationship confirmation and curation (`orbyn deps add`,
    `orbyn deps confirm`, `orbyn deps remove`).
  * Labeled graph views: `orbyn graph` (table/JSON/CSV), `--mermaid`
    flowchart export, and `--asset` scoped views; `orbyn connections` shows
    the raw evidence.
* Migration assessment (v0.5):
  * Versioned rule engine (`rules_version` on every report; bump on rule
    changes) evaluating the normalized domain — never raw collector output.
  * Rules: legacy/EOL OS detection, insecure and management service exposure,
    dependency hubs (blast radius), external/unmanaged coupling, unconfirmed
    edges, missing CPU/RAM capacity, nearly-full filesystems, and the
    right-sizing rules above (`rs.*`).
  * Explainable findings (rule id, severity, message, evidence) with
    per-asset complexity scores (0-100) and an overall complexity band.
  * Application grouping primitives: assets coupled by runtime/manual
    dependency edges are grouped as likely co-migrating applications.
  * `orbyn assess` (table/JSON/CSV report) and `orbyn assess --rules`
    (rule catalog).
* Third-party integrations:
  * NetBox source-of-truth importer (`orbyn netbox import`).
  * Prometheus historical utilization importer
    (`orbyn prometheus import`).
  * Zabbix historical utilization importer (`orbyn zabbix import`).
  * Ansible inventory exporter (`orbyn export --format ansible`).
  * Terraform-friendly export (`orbyn export --format terraform`).
  * Plugin/collector SDK (docs/PLUGINS.md + `examples/custom_collector.rs`).
* Cloud and platform adapters (read-only):
  * Proxmox VE importer (`orbyn proxmox import`): nodes, node datastores, QEMU
    VMs and LXC containers with per-guest interfaces (guest agent / container
    API / config fallback), OS identity, filesystems and CPU/RAM capacity.
  * AWS importer (`orbyn aws import`): EC2 instances and their elastic
    network interfaces, EBS volumes (as filesystems on their attached
    instance) and VPC/subnet resources (as assets keyed by their CIDR network
    address) via the signed EC2 query API (SigV4, no SDK), with the account id
    resolved from STS when permitted.
  * Huawei Cloud importer (`orbyn huawei import`): ECS instances and their
    network interfaces, EVS volumes (as filesystems on their attached server)
    and VPC/subnet resources (as assets keyed by their CIDR network address)
    via the signed ECS/EVS/VPC APIs (AK/SK `SDK-HMAC-SHA256`, no SDK), with
    CPU/RAM capacity from the flavor catalogue and the project id resolved
    from IAM when omitted.
  * OpenStack importer (`orbyn openstack import`): Nova instances and flavors,
    ports and attached Cinder volumes.
  * GCP importer (`orbyn gcp import`): Compute Engine instances, NICs,
    persistent disks, zones, machine capacity and labels.
  * Azure importer (`orbyn azure import`): ARM VMs, NICs, managed disks,
    VNets, subnets, regions, capacity and tags.
  * All attach provider provenance (`cloud:<provider>`,
    `cloud-account:<id>`, `cloud-region:<region>`) to every imported asset
    and record an audit event; credentials are never persisted.
* Architecture documentation, roadmap and backlog.

Third-party dependency and external-tool licensing details are documented in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
Release details are documented in
[`docs/RELEASE_NOTES_v1.0.3.md`](docs/RELEASE_NOTES_v1.0.3.md).

The v1.0 CLI surface, completions, audit trail and release packaging are
implemented. The current release is `v1.0.3`.

## Requirements

Current development requirements:

* Rust 1.75+ (via [rustup](https://rustup.rs))
* A C toolchain for the bundled SQLite build (standard for Rust SQLite drivers)
* Nmap for network discovery
* net-snmp-utils (`snmpwalk`) for SNMP discovery
* An OpenSSH client (`ssh`) for host-level collection
* `curl` for the API importers (including Proxmox VE, AWS, Huawei Cloud,
  OpenStack, GCP and Azure) and the native WinRM transport

Host-level collection uses key-based authentication (ssh-agent or
`--identity-file`); passwords are never passed through the CLI or stored.
Windows hosts can be collected through the OpenSSH Server optional feature
(PowerShell 3+, `Get-CimInstance`) or through the native WinRM transport:
a WinRM HTTPS listener (port 5986 by default) with Basic authentication
enabled. The WinRM password is sourced from `ORBYN_WINRM_PASSWORD` or stdin
(`--winrm-password -`), held in memory for the run only and streamed to
`curl` through stdin — never in process arguments, logs or on disk.

## Install & run locally

For installing a released binary without Rust or Cargo, see
[INSTALL.md](docs/INSTALL.md).

```bash
git clone https://github.com/NataliaPerez08/orbyn.git
cd orbyn

cp .env.example .env

cargo run -- --help
```

## Documentation

The full documentation site (install, CLI reference, one section per
collector, importers, configuration, security and third-party notices) is
built with [MkDocs](https://www.mkdocs.org/) + Material:

```bash
pip install -r requirements-docs.txt
mkdocs serve        # http://127.0.0.1:8000
mkdocs build --strict   # outputs to site/
```

The Markdown sources live in [`docs/`](docs); the site configuration is
[`mkdocs.yml`](mkdocs.yml). Every push to `main` rebuilds the site and
deploys it to GitHub Pages (`.github/workflows/docs.yml`; repository
**Settings → Pages → Source: GitHub Actions**).

## Shell completions

Generate a script for your shell and source it (bash / zsh / fish):

```bash
orbyn completions bash > /etc/bash_completion.d/orbyn    # bash
orbyn completions zsh  > "$fpath[1]/_orbyn"               # zsh
orbyn completions fish > ~/.config/fish/completions/orbyn.fish  # fish
```

For bash/zsh, add `source <(orbyn completions bash)` (or the zsh equivalent)
to your rc file if you prefer not to install system-wide.

The SQLite database is created and migrated automatically at:

```text
./data/orbyn.db
```

Point any command at a different database with `--db <path>` (or `ORBYN_DB`).

### PostgreSQL backend

`--db` (and `ORBYN_DB`) also accept a PostgreSQL URL: any value starting
with `postgres://` or `postgresql://` selects the PostgreSQL backend, with
the same schema applied automatically on open.

```bash
orbyn --db postgres://orbyn@localhost:5432/orbyn assets
ORBYN_DB="postgres://orbyn@db.example.com:5432/orbyn?sslmode=require" orbyn discover --target 10.0.0.0/24
```

TLS is negotiated when the server offers it (`sslmode=prefer` by default);
use `?sslmode=require` for remote databases. A URL without a password falls
back to `ORBYN_PG_PASSWORD` (or the standard `PGPASSWORD`) so the credential
never appears in the process arguments; a URL that does embed a password
prints a warning, since argv is readable by any local user (`ps`,
`/proc/<pid>/cmdline`). Prefer a least-privilege role and, where possible,
certificate or password-file authentication over inline passwords.

## CLI reference

```text
orbyn discover --target <cidr|ip> [--target ...] [--concurrency 4] \
    [--rate-limit <n>] [--collector nmap|snmp|ssh|windows|winrm] \
    [--allow-large-cidr] [--user <u>] [--port <p>] [--identity-file <key>] \
    [--community <c>|-] [--winrm-password <p>|-] [--winrm-port 5986] \
    [--winrm-insecure]
                                                  Scan targets (parallel worker pool);
                                                  CIDR wider than /16 (IPv4) or /48
                                                  (IPv6) needs --allow-large-cidr
orbyn assets [--format table|json|csv]
orbyn asset <id-or-ip> [--format ...]             Full record: annotations, interfaces, capacity, disks, units
orbyn services <id-or-ip> [--format ...]          Network services (ports)
orbyn interfaces <id-or-ip> [--format ...]
orbyn capacity <id-or-ip> [--format ...]          CPU/RAM capacity
orbyn disks <id-or-ip> [--format ...]             Filesystem inventory
orbyn host-services <id-or-ip> [--format ...]     Running host services (systemd units / Windows services)
orbyn connections <id-or-ip> [--format ...]       Active connections observed on a host
orbyn metrics <id-or-ip> [--samples N] [--format ...]
                                                  Utilization window: span, avg/p95/p99/peak,
                                                  confidence, right-sizing readiness
orbyn graph [--format ...] [--mermaid] [--asset <id-or-ip>]
orbyn deps add <src> <tgt> [--proto tcp --port N]     Add a manual dependency
orbyn deps confirm <src> <tgt> [--proto --port]       Confirm observed edges
orbyn deps remove <src> <tgt> [--proto --port]        Delete edges
orbyn deps dns                                        Derive relationship edges from DNS
orbyn assess [--format ...] [--rules]             Migration assessment report / rule catalog
orbyn annotate <id-or-ip> --environment prod --owner <team> \
    --criticality high --add-tag core --remove-tag dr [--unset <field>] \
                                                       Enrich or clear inventory metadata
orbyn jobs [--limit 50] [--format ...]            Discovery history with per-job outcomes
orbyn audit [--limit 50] [--format ...]           Mutating CLI operations and their outcomes
orbyn import --format json|csv [--file <file>]    Import inventory (file or stdin)
orbyn export [--format json|csv|ansible|ansible-yaml|terraform] [--group-by <key>] \
    [--tf-import <resource-type>] [--output <file>]
orbyn netbox import --url <url> [--token <t>|--token -]  Import devices/VMs from NetBox (SoT)
orbyn prometheus import --url <url> [--token <t>|--token -] [--lookback-hours 168] \
    [--step 5m] [--cpu-query <q>] [--ram-query <q>] [--swap-query <q>] [--no-verify]
                                                   Import historical CPU/RAM/swap utilization
orbyn zabbix import --url <url> [--token <t>|--token -] [--lookback-hours 168] [--no-verify]
                                                   Import historical CPU/RAM/swap utilization
orbyn proxmox import --url <url> [--token <t>|--token -] [--node <name>] [--no-verify]
                                                   Import nodes/VMs/containers from Proxmox VE
orbyn aws import --region <r> [--access-key <k>] [--secret-key <s>|--secret-key -] \
    [--session-token <t>|--session-token -] [--endpoint-url <url>] [--no-verify]
                                                   Import EC2 instances from AWS
orbyn huawei import --region <r> [--access-key <k>] [--secret-key <s>|--secret-key -] \
    [--project-id <id>] [--endpoint-url <url>] [--no-verify]
                                                   Import ECS instances from Huawei Cloud
orbyn completions bash|zsh|fish                      Generate a shell completion script
```

## Operational limits and partial failures

Discovery uses a bounded worker pool. `--concurrency` limits scans running at
once, while `--rate-limit` caps launches per second. Completed target batches
are persisted incrementally, so successful targets remain available when
another target fails and retained discovery memory is bounded by the worker
pool and one result batch.

External subprocesses are subject to a 60-second lifecycle timeout, a 16 MiB
stdout/response cap and a 1 MiB stderr cap. Inventory imports are capped at 64
MiB. NetBox, Prometheus, Zabbix and cloud API calls retry only transient
timeouts, transport failures, rate limits and 5xx responses, with at most three
attempts and bounded exponential backoff.

Large estates should be split into smaller import or discovery runs. A failed
target marks the discovery job failed, but observations already persisted from
successful targets are retained and shown in the job outcome.

Example session:

```bash
# scan an authorized subnet with Nmap
orbyn discover --target 10.0.0.0/24

# walk a single switch over SNMP (needs an authorized community string)
orbyn discover --target 10.0.0.8 --collector snmp --community public
# ... or keep the community off the command line entirely
orbyn discover --target 10.0.0.8 --collector snmp --community - <<< "$ORBYN_SNMP_COMMUNITY"

# collect host-level facts from Linux / Windows hosts (key-based auth)
orbyn discover --target 10.0.0.10 --collector ssh --user deploy --port 22
orbyn discover --target 10.0.0.20 --collector windows --user administrator \
    --identity-file ~/.ssh/id_ed25519

# ... or Windows hosts over native WinRM (Basic auth over HTTPS)
orbyn discover --target 10.0.0.20 --collector winrm --user administrator \
    --winrm-password - <<< "$ORBYN_WINRM_PASSWORD"

# import a week of CPU/RAM history from Prometheus (node_exporter queries
# by default; run from cron for continuous evidence)
orbyn prometheus import --url http://prometheus:9090
# ... or the same week from a Zabbix JSON-RPC API (hosts map by interface IP,
# then by name)
orbyn zabbix import --url https://zabbix.example.com/zabbix/api_jsonrpc.php \
    --token - < ~/.zabbix-token
orbyn metrics 10.0.0.10          # span, percentiles, right-sizing readiness

# bring a Proxmox VE cluster into the same inventory (read-only; API token)
orbyn proxmox import --url https://pve.example.com:8006 \
    --token - < ~/.proxmox-token
# ... or an AWS account (read-only; SigV4, credentials from the environment)
orbyn aws import --region eu-west-1
# ... or a Huawei Cloud account (read-only; AK/SK, credentials from the environment)
orbyn huawei import --region cn-north-4

# inspect what was found
orbyn assets
orbyn asset 10.0.0.10          # full record incl. interfaces and tags
orbyn services 10.0.0.10
orbyn interfaces 10.0.0.10
orbyn capacity 10.0.0.10       # CPU/RAM capacity
orbyn disks 10.0.0.10          # filesystem inventory
orbyn host-services 10.0.0.10  # running systemd units / Windows services

# enrich the inventory (metadata is preserved across re-discovery)
orbyn annotate 10.0.0.10 --environment prod --owner platform \
    --criticality high --add-tag core --add-tag api

# discovery history and change tracking
orbyn jobs

# machine-readable inventory
orbyn assets --format json
orbyn export --format csv --output inventory.csv
orbyn import --format csv --file inventory.csv

# dependency graph: edges, evidence and confidence
orbyn graph                      # labeled table
orbyn graph --mermaid            # Mermaid flowchart (solid = confirmed)
orbyn graph --asset 10.0.0.2     # everything touching one asset
orbyn connections 10.0.0.5       # raw connection evidence

# curate dependencies
orbyn deps confirm web-01 db-01 --port 5432
orbyn deps add cache-01 db-01 --port 5432
orbyn deps dns                   # DNS relationship evidence

# migration assessment: explainable findings + complexity scores
orbyn assess                    # findings, per-asset scores, application groups
orbyn assess --format json      # machine-readable report
orbyn assess --rules            # the rule catalog and its version
```

By default output is a terminal table; `--format json` and `--format csv`
stream machine-readable data to stdout. Logs go to stderr, so stdout stays
clean for piping.

## Configuration

| Variable     | Default           | Purpose              |
| ------------ | ----------------- | -------------------- |
| `ORBYN_DB`   | `./data/orbyn.db` | SQLite database path, or a `postgres://` URL |
| `ORBYN_PG_PASSWORD` | _(unset)_  | Password for a PostgreSQL URL that omits one (fallback: `PGPASSWORD`) |
| `ORBYN_LOG`  | `orbyn=warn`      | tracing filter (also `-v`/`-vv`) |
| `ORBYN_NMAP_BIN` | `nmap`        | Nmap binary path     |
| `ORBYN_NMAP_TIMEOUT_SECS` | `1800` | Whole-process timeout for an nmap run |
| `ORBYN_SNMP_BIN` | `snmpwalk`   | `snmpwalk` binary path (net-snmp-utils) |
| `ORBYN_SNMP_COMMUNITY` | `public`  | SNMP v1/v2c community string (or `--community`, `--community -` for stdin) |
| `ORBYN_SSH_BIN` | `ssh`           | `ssh` binary path (OpenSSH client) |
| `ORBYN_CURL_BIN` | `curl`        | `curl` binary path for API clients and WinRM transport |
| `ORBYN_NETBOX_TOKEN` | _(unset)_  | NetBox API token (or `--token`, `--token -` for stdin) |
| `ORBYN_PROMETHEUS_TOKEN` | _(unset)_ | Prometheus bearer token (or `--token`, `--token -` for stdin) |
| `ORBYN_ZABBIX_TOKEN` | _(unset)_ | Zabbix API token (or `--token`, `--token -` for stdin) |
| `ORBYN_PROXMOX_TOKEN` | _(unset)_ | Proxmox API token `user@realm!id=secret` (or `--token`, `--token -` for stdin) |
| `AWS_ACCESS_KEY_ID` | _(unset)_ | AWS access key id (or `--access-key`) |
| `AWS_SECRET_ACCESS_KEY` | _(unset)_ | AWS secret access key (or `--secret-key`, `--secret-key -` for stdin) |
| `AWS_SESSION_TOKEN` | _(unset)_ | AWS session token for temporary credentials (or `--session-token`) |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | _(unset)_ | AWS region (or `--region`) |
| `AWS_ENDPOINT_URL` | _(unset)_ | Override the AWS EC2 endpoint (or `--endpoint-url`) |
| `HUAWEICLOUD_SDK_AK` | _(unset)_ | Huawei Cloud access key (AK) (or `--access-key`) |
| `HUAWEICLOUD_SDK_SK` | _(unset)_ | Huawei Cloud secret key (SK) (or `--secret-key`, `--secret-key -` for stdin) |
| `HUAWEICLOUD_REGION` | _(unset)_ | Huawei Cloud region (or `--region`) |
| `HUAWEICLOUD_PROJECT_ID` | _(unset)_ | Huawei Cloud project id (or `--project-id`; resolved from IAM when omitted) |
| `ORBYN_OPENSTACK_TOKEN` | _(unset)_ | Scoped OpenStack token (or `--token`, `--token -` for stdin) |
| `OS_PROJECT_ID` / `OS_REGION_NAME` | _(unset)_ | OpenStack project and region scope |
| `ORBYN_GCP_TOKEN` | _(unset)_ | GCP OAuth bearer token (or `--token`, `--token -` for stdin) |
| `GOOGLE_CLOUD_PROJECT` | _(unset)_ | GCP project id (or `--project`) |
| `ORBYN_AZURE_TOKEN` | _(unset)_ | Azure ARM bearer token (or `--token`, `--token -` for stdin) |
| `AZURE_SUBSCRIPTION_ID` | _(unset)_ | Azure subscription id (or `--subscription-id`) |
| `ORBYN_WINRM_PASSWORD` | _(unset)_ | WinRM Basic-auth password (or `--winrm-password`, `--winrm-password -` for stdin) |

Secrets can also be piped in so they never appear in argv or the
environment: `--token -`, `--community -`, `--secret-key -` and
`--winrm-password -` read one line from stdin (e.g. `orbyn netbox import
--url <url> --token - < token.txt`).

A `.env` file in the current working directory is loaded at startup
(existing environment variables win; parent directories are never
searched). Values it sets for `ORBYN_*_BIN` are execution paths — a
non-standard value prints a warning, since Orbyn will execute that binary.

## Repository layout

```text
orbyn/
├── Cargo.toml
├── src/
│   ├── main.rs                  # CLI executable (clap)
│   ├── lib.rs
│   ├── config.rs                # env/flag-based configuration (DbTarget)
│   ├── process.rs               # bounded subprocess execution (timeouts, capture caps)
│   ├── redact.rs                # value-based secret redaction
│   ├── import.rs                # JSON/CSV inventory import
│   ├── assessment/              # migration assessment
│   ├── collectors/              # discovery collectors
│   │   ├── classify.rs          # device classification
│   │   ├── nmap.rs              # Nmap adapter
│   │   ├── snmp.rs              # SNMP adapter
│   │   ├── ssh.rs               # SSH transport + Linux collector
│   │   ├── windows.rs           # Windows collector (PowerShell over SSH)
│   │   └── dns.rs               # DNS relationship evidence
│   ├── domain/                  # normalized domain model
│   ├── graph/                   # dependency graph
│   ├── integrations/            # NetBox/monitoring importers, cloud adapters, exporters
│   │   └── cloud/               # read-only Proxmox/AWS/Huawei/OpenStack/GCP/Azure adapters
│   ├── metrics/                 # capacity/utilization processing
│   ├── output/                  # table/json/csv rendering
│   └── store/                   # Store trait + SQLite and PostgreSQL backends
│
├── migrations/                  # versioned SQL migrations (sqlx)
├── migrations/postgres/         # PostgreSQL dialect of the same schema
├── tests/                       # integration tests
│
├── Makefile
├── .env.example
├── .gitignore
├── docs/
│   ├── CONTRIBUTING.md
│   ├── SECURITY.md
│   └── ...
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
* SSH (Linux) and PowerShell over SSH (Windows)
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
one SQLite database (or one PostgreSQL URL)
```

Larger deployments can point `--db` at PostgreSQL today; distributed
collection can come later.

### Scale without rewriting the domain

Storage, scheduling and telemetry infrastructure may evolve independently as Orbyn grows.

The underlying asset and dependency model should remain portable.

## Planned collectors

| Collector  | Information                           | Target |
| ---------- | ------------------------------------- | ------ |
| Nmap       | Hosts, ports and service fingerprints | v0.1   |
| SNMP       | Network and device metadata           | v0.2   |
| SSH        | Linux inventory and capacity          | v0.3   |
| PowerShell | Windows inventory and capacity (over OpenSSH) | v0.3 |
| WinRM      | Native Windows transport (WS-Man over HTTPS) | v0.3 |
| VMware     | VM and hypervisor inventory           | Later  |
| NetBox     | Source-of-truth import (devices/VMs)  | Shipped |
| Prometheus | Historical utilization                | Shipped |
| Zabbix     | Historical utilization                | Shipped |
| Proxmox VE | Nodes, storage, VMs, containers, disks, interfaces | Shipped |
| AWS        | EC2, EBS, VPC/subnets and network interfaces | Shipped |
| Huawei Cloud | ECS, EVS, VPC/subnets, interfaces and flavor capacity | Shipped |
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

See [SECURITY.md](docs/SECURITY.md).

## Roadmap

The project will evolve incrementally:

```text
v0.1    Network discovery          (done)
          ↓
v0.2    Inventory enrichment       (done)
          ↓
v0.3    Host discovery via SSH / Windows (done — SSH, PowerShell over
        OpenSSH, and native WinRM over HTTPS)
          ↓
v0.4    Dependency mapping       (done)
          ↓
v0.5    Migration assessment     (done)
           ↓
 v1.0    Stable CLI product    (done)
          ↓
v1.0.x  Integrations, metrics + right-sizing, cloud adapters
```

A web/HTTP interface for `orbyn` is a possible later add-on, not a goal for the
core tool.

See [ROADMAP.md](docs/ROADMAP.md) and [BACKLOG.md](docs/BACKLOG.md).

## Contributing

Orbyn is intended to be community-driven.

Contributions around collectors, infrastructure platforms, dependency detection, assessment rules, documentation and testing are welcome.

See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

Apache License 2.0.

See [LICENSE](LICENSE).
