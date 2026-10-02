# Orbyn

**Open-source infrastructure discovery, dependency mapping, and migration assessment — from the command line.**

Orbyn discovers infrastructure, builds an accurate asset inventory, maps how systems depend on each other, and produces the data needed to plan migrations and right-size target environments — from a local, single-binary CLI.

> **Status:** v1.0.3 stable release — discovery, inventory, assessment, integrations, metrics/right-sizing and cloud adapters.

## What Orbyn does

```text
                  Infrastructure
                       │
                       ▼
         discovery (nmap / snmp / ssh / winrm / APIs / monitoring)
                       │
                       ▼
               normalized inventory
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
  dependency       metrics +      assessment
  graph         right-sizing    (explainable)
        │              │              │
        └──────────────┼──────────────┘
                       ▼
        export (json / csv / ansible / terraform / mermaid)
```

Everything is read-only, scoped to authorized targets, and runs locally against a SQLite database (or a PostgreSQL URL).

## Capabilities

- **Discovery**: Nmap (ports/services/OS), SNMP (network gear), SSH (Linux), PowerShell over SSH and native WinRM (Windows), DNS relationship evidence.
- **Inventory**: assets, interfaces, services, host services, CPU/RAM capacity, filesystems, virtualization metadata, tags, environment, owner and criticality.
- **Dependencies**: active-connection, DNS and manual edges with confidence; graph table/JSON/CSV and Mermaid export; application grouping.
- **Metrics & right-sizing**: snapshot utilization plus a week of history from Prometheus or Zabbix; avg/p95/p99/peak windows with sample confidence; explainable CPU/RAM/swap/storage sizing rules (`rs.*`) — snapshots alone never drive a sizing decision.
- **Assessment**: versioned rule catalog with explainable findings (rule id, evidence, observation window), per-asset complexity scores and application groups.
- **Integrations**: NetBox source-of-truth import; Proxmox VE, AWS, Huawei Cloud, OpenStack, GCP and Azure adapters; Ansible and Terraform exports.
- **Operations**: bounded concurrency, rate limiting, subprocess timeouts and output caps, import size caps, retries with backoff, audit trail, discovery job history, secret redaction, deterministic golden datasets and CI-enforced fuzzing.

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Requirements

- Rust 1.75+ to build; a released binary needs no toolchain (see [INSTALL.md](docs/INSTALL.md)).
- External tools for collection: `nmap`, `snmpwalk` (net-snmp-utils), an OpenSSH client (`ssh`), `curl` (API importers and WinRM), optionally `dig`.

Host-level collection uses key-based auth (ssh-agent or `--identity-file`); secrets are never stored. Windows hosts can be collected over OpenSSH or native WinRM (HTTPS, Basic auth); the WinRM password comes from `ORBYN_WINRM_PASSWORD` or stdin and is streamed to `curl` on stdin — never argv, logs or disk.

## Install & run locally

For a released binary without Rust, see [INSTALL.md](docs/INSTALL.md).

```bash
git clone https://github.com/NataliaPerez08/orbyn.git
cd orbyn
cargo run -- --help
```

The SQLite database is created and migrated automatically at `./data/orbyn.db`; point elsewhere with `--db <path>` (or `ORBYN_DB`). `--db` also accepts a `postgres://`/`postgresql://` URL, applying the same schema on open. TLS defaults to `sslmode=prefer`; use `?sslmode=require` for remote databases. A URL without a password falls back to `ORBYN_PG_PASSWORD`/`PGPASSWORD` so it never appears in argv.

## Quick tour

```bash
# scan an authorized subnet
orbyn discover --target 10.0.0.0/24

# host-level facts (key-based auth), and Windows over native WinRM
orbyn discover --target 10.0.0.10 --collector ssh --user deploy
orbyn discover --target 10.0.0.20 --collector winrm --user administrator --winrm-password -

# a week of utilization history, then the window + right-sizing readiness
orbyn prometheus import --url http://prometheus:9090
orbyn metrics 10.0.0.10

# import a cloud account (read-only, credentials from the environment)
orbyn proxmox import --url https://pve.example.com:8006 --token -
orbyn aws import --region eu-west-1

# inspect, enrich, and assess
orbyn assets
orbyn annotate 10.0.0.10 --environment prod --owner platform --criticality high --add-tag core
orbyn graph --mermaid            # dependency graph (solid = confirmed)
orbyn assess                     # explainable findings + complexity
orbyn export --format csv --output inventory.csv
```

Output defaults to terminal tables; `--format json|csv` streams machine-readable data to stdout, and logs go to stderr.

## CLI reference

Run `orbyn <command> --help` for the full surface, or see the [CLI reference](docs/cli.md). The main commands:

- **Discovery**: `discover`, `jobs`, `audit`
- **Inventory**: `assets`, `asset`, `services`, `interfaces`, `capacity`, `disks`, `host-services`, `connections`, `annotate`, `import`, `export`
- **Relationships**: `graph`, `deps add|confirm|remove|dns`
- **Metrics & assessment**: `metrics`, `assess [--rules]`
- **Integrations**: `netbox import`, `prometheus import`, `zabbix import`, `proxmox import`, `aws import`, `huawei import`, `openstack import`, `gcp import`, `azure import`
- **Other**: `completions`

## Configuration

Secrets and binaries are configured through environment variables (see [configuration.md](docs/configuration.md) for the full table): `ORBYN_DB`, `ORBYN_NMAP_BIN`, `ORBYN_SNMP_COMMUNITY`, `ORBYN_SSH_BIN`, `ORBYN_CURL_BIN`, `ORBYN_NETBOX_TOKEN`, `ORBYN_PROMETHEUS_TOKEN`, `ORBYN_ZABBIX_TOKEN`, `ORBYN_PROXMOX_TOKEN`, `ORBYN_WINRM_PASSWORD`, plus the standard AWS/Huawei/OpenStack/GCP/Azure credential variables.

Secrets can be piped so they never appear in argv or the environment: `--token -`, `--community -`, `--secret-key -`, `--winrm-password -` read one line from stdin. A `.env` file in the current directory is loaded at startup (existing environment variables win; parent directories are never searched).

## Operational limits and partial failures

- Bounded worker pool (`--concurrency`) and launch pacing (`--rate-limit`); successful targets are persisted incrementally, so a failed target never discards completed work.
- Subprocesses: 60-second lifecycle timeout, 16 MiB stdout/response cap, 1 MiB stderr cap. Imports are capped at 64 MiB.
- External API calls retry only transient timeouts/transport failures/rate limits/5xx, at most three attempts with bounded backoff; rejected credentials and malformed payloads fail immediately.
- Large estates should be imported or scanned in smaller runs. A failed target marks the job failed but keeps already-persisted observations.

## Security

Infrastructure discovery is security-sensitive. Orbyn therefore requires explicit discovery targets, rejects unrestricted scans by default, is read-only, never exposes credentials in logs or argv (secrets travel to `curl` on stdin), avoids storing credentials, keeps database files `0600`, and maintains an audit trail.

Users are responsible for ensuring they are authorized to scan the target infrastructure. See [SECURITY.md](docs/SECURITY.md), the [threat model](docs/THREAT_MODEL.md) and the [validation matrix](docs/VALIDATION_MATRIX.md).

## Guiding principles

- **Vendor neutral** — a single normalized model for bare metal, private and public clouds.
- **Agentless first** — prefer existing protocols (nmap, SNMP, SSH, WinRM, APIs, monitoring systems) over installing agents.
- **Read-only by default** — discovery never modifies the systems it inspects.
- **Explainable** — every finding and right-sizing recommendation exposes its evidence and rules.
- **CLI-first** — tables for humans, `--format json|csv` for machines; a UI is never a prerequisite.
- **Local-first** — one binary + one SQLite database (or one PostgreSQL URL); PostgreSQL supports larger estates today.

## Roadmap

```text
v0.1  Network discovery   v0.3  Host discovery (SSH / Windows / WinRM)
v0.2  Inventory           v0.4  Dependency mapping
v0.5  Migration assessment
v1.0  Stable CLI product
v1.0.x  Integrations, metrics + right-sizing, cloud adapters
```

A web/HTTP interface is a possible later add-on, not a goal for the core tool. See [ROADMAP.md](docs/ROADMAP.md) and [BACKLOG.md](docs/BACKLOG.md).

## Documentation

The full site (install, CLI reference, collectors, importers, configuration, security) is built with MkDocs + Material:

```bash
pip install -r requirements-docs.txt
mkdocs serve          # http://127.0.0.1:8000
mkdocs build --strict # outputs to site/
```

Every push to `main` rebuilds and deploys it to GitHub Pages. Third-party licensing is documented in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md); release notes in [`docs/RELEASE_NOTES_v1.0.3.md`](docs/RELEASE_NOTES_v1.0.3.md).

## Contributing

Contributions around collectors, infrastructure platforms, dependency detection, assessment rules, documentation and testing are welcome. See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).