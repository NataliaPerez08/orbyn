# Source of truth and export

## NetBox

Pulls devices, VMs, their interfaces and assigned IPs from a NetBox instance
and maps them into the same inventory the collectors produce.

```bash
orbyn netbox import --url https://netbox.example.com --token - < ~/.netbox-token

# token from the environment instead
ORBYN_NETBOX_TOKEN=... orbyn netbox import --url https://netbox.example.com

# self-signed certificate
orbyn netbox import --url https://netbox.example.com --token - --no-verify < tok
```

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--url` | *(required)* | NetBox base URL |
| `--token` / `ORBYN_NETBOX_TOKEN` | *(required)* | API token; `-` reads stdin |
| `--no-verify` | off | Skip TLS verification |

Read-only: Orbyn never creates or modifies an object in NetBox.

## File import

```bash
orbyn import --format json --file inventory.json
orbyn import --format csv < inventory.csv          # stdin works too
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--format json\|csv` | `json` | Input format |
| `--file <path>` | stdin | Input file |

Imports are capped at 64 MiB. Inventory metadata (environment, owner,
criticality, tags) is preserved across re-discovery.

## Export

```bash
orbyn export --format json --output inventory.json
orbyn export --format csv --output inventory.csv

# Ansible inventory, grouped by device class (default) or another key
orbyn export --format ansible --group-by environment --output hosts.ini
orbyn export --format ansible-yaml --output hosts.yaml

# Terraform import blocks for a specific resource type
orbyn export --format terraform --tf-import aws_instance --output import.tf
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `-f, --format` | `json` | `json`, `csv`, `ansible`, `ansible-yaml`, `terraform` |
| `--group-by <key>` | `device-class` | Grouping key for the Ansible inventory |
| `--tf-import <resource-type>` | *(none)* | Generate `import` blocks; requires `--format terraform` |
| `-o, --output <file>` | stdout | Write to a file instead |

!!! note
    `export --format table` was removed in the integrations milestone — use `orbyn assets` for a
    human-readable table, or `--format csv` for a file.

## Typical flows

```bash
# NetBox is the source of truth, discovery fills the gaps
orbyn netbox import --url https://netbox.example.com --token - < tok
orbyn discover --target 10.0.0.0/24                 # hostnames, ports, MACs
orbyn asset 10.0.0.10                               # both sources, one record

# hand the inventory to configuration management
orbyn export --format ansible --group-by environment --output stage.ini

# round-trip through a spreadsheet
orbyn export --format csv --output inventory.csv
# ... edit ...
orbyn import --format csv --file inventory.csv
```
