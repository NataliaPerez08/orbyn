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

## 5. Enrich inventory

```bash
orbyn annotate 127.0.0.1 --environment prod --owner platform \
    --criticality high --tag core --tag api
orbyn asset 127.0.0.1
```

Annotations are preserved across re-discovery.

## 6. Export / import

```bash
orbyn export --format csv --output inventory.csv
orbyn import --format csv --file inventory.csv
```

## 7. Dependency graph & assessment

```bash
orbyn graph
orbyn assess
```

## Troubleshooting

| Symptom                       | Cause / fix                                                       |
| ----------------------------- | ----------------------------------------------------------------- |
| `nmap not found`              | scope uses nmap without `nmap` installed (`sudo apt install nmap`) |
| `snmpwalk: command not found` | install net-snmp-utils (`sudo apt install snmp`)                  |
| SNMP discover returns nothing | wrong/firewalled target, or community string not authorized       |
| no activity on a command      | `-vv` for verbose logs; stdout is clean, logs go to stderr        |

Full reference and configuration (env vars, collectors, formats) live in
[README.md](README.md).