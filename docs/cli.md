# CLI reference

Orbyn is a single binary. Every command writes data to the local database
(`./data/orbyn.db` by default) and prints a terminal table; `--format json`
and `--format csv` stream machine-readable data to stdout. Logs go to stderr,
so stdout stays clean for piping.

```bash
orbyn --help
orbyn <command> --help
```

## Global flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--db <path-or-url>` | `./data/orbyn.db` | SQLite path or a `postgres://` URL (env `ORBYN_DB`) |
| `-v`, `--verbose` | off | Repeatable log verbosity (or set `ORBYN_LOG`) |
| `--version` | — | Print version |

Most commands also accept `--format table|json|csv`.

## Discovery

```text
orbyn discover --target <cidr|ip> [--target ...] [--concurrency 4] \
    [--rate-limit <n>] [--collector nmap|snmp|ssh|windows|winrm] \
    [--allow-large-cidr] [--user <u>] [--port <p>] [--identity-file <key>] \
    [--community <c>|-] [--snmp-version 1|2c] [--snmp-port 161] \
    [--winrm-password <p>|-] [--winrm-port 5986] [--winrm-insecure] \
    [--format table|json|csv]
```

| Flag | Default | Applies to | Purpose |
| --- | --- | --- | --- |
| `--target <cidr\|ip>` | *(required, repeatable)* | all | Scope to scan. Validated before anything runs |
| `--collector <name>` | `nmap` | all | `nmap`, `snmp`, `ssh`, `windows`, `winrm` |
| `--concurrency <n>` | `4` | all | Targets scanned in parallel (must be ≥ 1) |
| `--rate-limit <n>` | *(none)* | all | Max target launches per second (must be ≥ 1) |
| `--allow-large-cidr` | off | all | Widen the CIDR floor beyond IPv4 `/16` / IPv6 `/48` |
| `--format <f>` | `table` | all | `table`, `json`, `csv` |
| `--community <c>` | `public` | snmp | Community string; `-` reads one line from stdin |
| `--snmp-version <v>` | `2c` | snmp | `1` or `2c` |
| `--snmp-port <p>` | `161` | snmp | SNMP agent UDP port |
| `--user <u>` | *(current user)* | ssh, windows, winrm | Login account; **required** for winrm |
| `--port <p>` | `22` | ssh, windows | SSH port |
| `--identity-file <path>` | *(none)* | ssh, windows | Private key file (never read or stored by Orbyn) |
| `--winrm-password <p>` | `ORBYN_WINRM_PASSWORD` | winrm | `-` reads one line from stdin |
| `--winrm-port <p>` | `5986` | winrm | WinRM HTTPS port |
| `--winrm-insecure` | off | winrm | Skip TLS verification (lab certs only; warns loudly) |

## Inventory

| Command | Purpose |
| --- | --- |
| `orbyn assets [--format ...]` | List discovered assets |
| `orbyn asset <id-or-ip> [--format ...]` | Full record: annotations, interfaces, capacity, disks, units |
| `orbyn services <id-or-ip>` | Network services (ports) |
| `orbyn interfaces <id-or-ip>` | Interfaces (MAC, vendor, MTU, state) |
| `orbyn capacity <id-or-ip>` | CPU/RAM capacity |
| `orbyn disks <id-or-ip>` | Filesystem inventory |
| `orbyn host-services <id-or-ip>` | Running host services (systemd units / Windows services) |
| `orbyn connections <id-or-ip>` | Active connections observed on a host |
| `orbyn annotate <id-or-ip> --environment prod --owner <team> \|--criticality high --add-tag core --remove-tag dr [--unset <field>]` | Enrich or clear inventory metadata (preserved across re-discovery) |
| `orbyn jobs [--limit 50]` | Discovery history with per-job outcomes |
| `orbyn audit [--limit 50]` | Mutating CLI operations and their outcomes |

## Metrics and right-sizing

| Command | Purpose |
| --- | --- |
| `orbyn metrics <id-or-ip> [--samples N]` | Utilization window: span, avg/p95/p99/peak, confidence, right-sizing readiness |

## Dependencies and graph

| Command | Purpose |
| --- | --- |
| `orbyn graph [--format ...] [--mermaid] [--asset <id>]` | Labeled dependency graph; `--mermaid` exports a flowchart (solid = confirmed) |
| `orbyn deps add <src> <tgt> [--proto tcp --port N]` | Add a manual dependency |
| `orbyn deps confirm <src> <tgt> [--proto --port]` | Confirm observed edges |
| `orbyn deps remove <src> <tgt> [--proto --port]` | Delete edges |
| `orbyn deps dns` | Derive relationship edges from DNS evidence |

## Assessment

| Command | Purpose |
| --- | --- |
| `orbyn assess [--format ...] [--rules]` | Migration assessment report / rule catalog |
| `orbyn sku-match --provider aws\|azure\|gcp --cores <n> --ram-mb <m> [--format ...]` | Match a right-sizing baseline to candidate instance types (SKUs), smallest fit first |
| `orbyn waves [--format ...] [--pin <asset>=<wave>]... [--exclude <asset>]...` | Ordered migration waves (low risk first) with exposed reasoning |

`sku-match` keeps provider catalogs separate from the assessment: feed it the
baseline suggested by an `rs.*` finding (e.g. "4 cores, 6144 MB") to see which
provider instance types satisfy it. The catalog is a curated subset; a baseline
with no fit reports so rather than guessing. See [Cloud SKU matching](sku.md).

`waves` scores assets into three risk bands (low/medium/high), keeps application
groups together, and honors manual `--pin`/`--exclude` constraints. See
[Migration waves](waves.md).

## Import and export

```text
orbyn import --format json|csv [--file <file>]    Import inventory (file or stdin)
orbyn export [--format json|csv|ansible|ansible-yaml|terraform] [--group-by <key>] \
    [--tf-import <resource-type>] [--output <file>]

orbyn netbox import --url <url> [--token <t>|--token -]
orbyn prometheus import --url <url> [--token <t>|--token -] [--lookback-hours 168] \
    [--step 5m] [--cpu-query <q>] [--ram-query <q>] [--swap-query <q>] [--no-verify]
orbyn zabbix import --url <url> [--token <t>|--token -] [--lookback-hours 168] [--no-verify]
orbyn proxmox import --url <url> [--token <t>|--token -] [--node <name>] [--no-verify]
orbyn aws import --region <r> [--access-key <k>] [--secret-key <s>|--secret-key -] \
    [--session-token <t>|--session-token -] [--endpoint-url <url>] [--no-verify]
orbyn huawei import --region <r> [--access-key <k>] [--secret-key <s>|--secret-key -] \
    [--project-id <id>] [--endpoint-url <url>] [--no-verify]
orbyn openstack import --url <url> [--token <t>|--token -] [--project-id <id>] [--no-verify]
orbyn gcp import --project <id> [--token <t>|--token -] [--no-verify]
orbyn azure import --subscription-id <id> [--token <t>|--token -] [--no-verify]
```

See [Importers & integrations](importers/index.md) for per-importer details.

## Completions

```bash
orbyn completions bash|zsh|fish
```

## Example session

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

# inspect what was found
orbyn assets
orbyn asset 10.0.0.10
orbyn capacity 10.0.0.10
orbyn assess
orbyn waves
```

## Operational limits and partial failures

Discovery uses a bounded worker pool. `--concurrency` limits scans running at
once, while `--rate-limit` caps launches per second. Completed target batches
are persisted incrementally, so successful targets remain available when
another target fails.

External subprocesses are subject to a 60-second lifecycle timeout, a 16 MiB
stdout cap and a 1 MiB stderr cap (nmap uses its own configurable timeout,
1800 s by default). Inventory imports are capped at 64 MiB. NetBox,
Prometheus, Zabbix and cloud API calls retry only transient timeouts,
transport failures, rate limits and 5xx responses, with at most three
attempts and bounded exponential backoff.

Large estates should be split into smaller import or discovery runs. A failed
target marks the discovery job failed, but observations already persisted
from successful targets are retained and shown in the job outcome.
