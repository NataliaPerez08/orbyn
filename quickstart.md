# Orbyn Quickstart

Follow these steps, in order. Total time for the 5-minute path: ~5 minutes.

## 0. Prerequisites

```bash
# Debian / Ubuntu
sudo apt install nmap snmp

# other systems: cargo (Rust 1.75+) + nmap + net-snmp-utils
```

## 1. Build

```bash
cd orbyn
cp .env.example .env
cargo build
```

The binary is `./target/debug/orbyn` (release: `cargo build --release`).

The SQLite database is created and migrated automatically at `./data/orbyn.db`.
Point at another database with `--db <path>` or `ORBYN_DB`.

> Tip: add a shell alias so you can type `orbyn` directly:
> `alias orbyn="$PWD/target/debug/orbyn"`

## 2. Smoke test (no network needed)

```bash
orbyn --help
orbyn discover --target 127.0.0.1
orbyn assets
```

The discover against your loopback should print a summary such as
`Discovery job ... complete: 1 assets, N services.` and `assets` must show
`127.0.0.1`.

## 3. Inspect results

```bash
orbyn assets                 # table (default)
orbyn assets --format json   # machine-readable
orbyn assets --format csv
orbyn asset 127.0.0.1        # full record: annotations, services, interfaces
orbyn services 127.0.0.1
orbyn interfaces 127.0.0.1
orbyn jobs                   # discovery history / audit trail
```

## 4. Real discovery (against authorized targets only)

```bash
# Nmap scan of your OWN subnet or lab
orbyn discover --target 192.168.1.0/24

# single host over SNMP (needs an authorized community string)
orbyn discover --target 192.168.1.10 --collector snmp --community public
```

Orbyn rejects unrestricted scopes by default. You are responsible for having
authorization to scan targets.

## 5. Collect host-level facts (SSH / Windows)

```bash
# Linux host: OS, kernel, CPU/RAM capacity, filesystems, running services
orbyn discover --target 192.168.1.10 --collector ssh --user deploy

# Windows host (OpenSSH Server enabled): OS, CPU, RAM, disks, services
orbyn discover --target 192.168.1.20 --collector windows \
    --user administrator --identity-file ~/.ssh/id_ed25519

orbyn capacity 192.168.1.10        # CPU/RAM
orbyn disks 192.168.1.10           # filesystems
orbyn host-services 192.168.1.10   # running systemd units / Windows services
```

Authentication is key-based only (ssh-agent or `--identity-file`); Orbyn never
stores or logs credentials. Native WinRM transport is planned (ROADMAP.md).

## 6. Enrich inventory

```bash
orbyn annotate 127.0.0.1 --environment prod --owner platform \
    --criticality high --tag core --tag api
orbyn asset 127.0.0.1
```

Annotations are preserved across re-discovery.

## 7. Export / import & integrations

```bash
orbyn export --format csv --output inventory.csv
orbyn import --format csv --file inventory.csv

# automation exporters
orbyn export --format ansible                 # INI inventory (groups)
orbyn export --format terraform               # HCL locals.orbyn_inventory

# NetBox source-of-truth import
orbyn netbox import --url https://netbox.example.com --token "$ORBYN_NETBOX_TOKEN"
```

```bash
orbyn export --format csv --output inventory.csv
orbyn import --format csv --file inventory.csv
```

## 8. Dependency graph & assessment

Host-level collection (step 5) records active connections; Orbyn turns them
into dependency edges whenever the remote endpoint is a known asset.

```bash
orbyn graph                    # labeled edges with evidence + confidence
orbyn graph --mermaid          # Mermaid flowchart (dotted = unconfirmed)
orbyn graph --asset 10.0.0.2   # everything touching one asset
orbyn connections 10.0.0.5     # raw connection evidence

orbyn deps confirm web-01 db-01 --port 5432   # confirm what was observed
orbyn deps add cache-01 db-01 --port 5432     # add a manual edge
orbyn deps dns                                 # DNS relationship evidence

orbyn assess                    # explainable findings + complexity scores
orbyn assess --rules            # the rule catalog and its version
```

## Troubleshooting

| Symptom                       | Cause / fix                                                       |
| ----------------------------- | ----------------------------------------------------------------- |
| `nmap not found`              | scope uses nmap without `nmap` installed (`sudo apt install nmap`) |
| `snmpwalk: command not found` | install net-snmp-utils (`sudo apt install snmp`)                  |
| SNMP discover returns nothing | wrong/firewalled target, or community string not authorized       |
| `ssh ... Permission denied`   | host-level collection needs key auth: `ssh-add` or `--identity-file` |
| ssh collector hangs/times out | check the port (`--port`), firewall, and that the host is authorized |
| no activity on a command      | `-vv` for verbose logs; stdout is clean, logs go to stderr        |

Full reference and configuration (env vars, collectors, formats) live in
[README.md](README.md).