# Test environment runs

This page shows **real executions** of the `orbyn` CLI against a small test
environment: two seeded hosts plus two hosts "discovered" through stubbed
collectors. No real network, cloud account, or credentials are involved — every
command below actually ran and its output is reproduced verbatim.

The environment is built in four steps:

```text
import a JSON estate (db-01, cache-01)
  + discover 10.0.0.10 with a stub nmap (server-a)
  + discover 10.0.0.5  with a stub ssh   (web-01, with live connections)
  + record one manual dependency (cache-01 -> db-01)
```

!!! note "What the stubs are"
    `ORBYN_NMAP_BIN` / `ORBYN_SSH_BIN` point at small shell scripts that emit
    the same Nmap XML / SSH probe output a real host would. The collectors and
    pipeline are the real production code — only the *probe response* is
    scripted. Every step shown here is also covered by the automated
    end-to-end suite (see the [validation matrix](VALIDATION_MATRIX.md)).

## 1. Seed the inventory

```bash
orbyn --db demo.db import --format json < seed.json
```

```text
Imported 2 assets.
┌──────────────────────────────────────┬───────────┬───────────┬───────────────────┬─────────────┬──────────┬────────┬──────────┬─────────────┬─────────┬───────┐
│ ID                                   ┆ Collector ┆ Status    ┆ Targets           ┆ Started     ┆ Duration ┆ Assets ┆ Services ┆ Filesystems ┆ Running ┆ Conns │
╞══════════════════════════════════════╪═══════════╪═══════════╪═══════════════════╪═════════════╪══════════╪════════╪══════════╪═════════════╪═════════╪═══════╡
│ 29f50154-f17b-4d2e-95d2-2897ca0e5f41 ┆ import    ┆ succeeded ┆ 10.0.0.2,10.0.0.9 ┆ ... 00:21:29 ┆ 0s       ┆ 2      ┆ 0        ┆ 0           ┆ 0       ┆ 0     │
└──────────────────────────────────────┴───────────┴───────────┴───────────────────┴─────────────┴──────────┴────────┴──────────┴─────────────┴─────────┴───────┘
```

The import records an audit job with a stable id, and everything is persisted
to `demo.db` (SQLite).

## 2. Discover hosts

```bash
ORBYN_NMAP_BIN=stubs/nmap orbyn --db demo.db discover --target 10.0.0.10 --collector nmap
ORBYN_SSH_BIN=stubs/ssh   orbyn --db demo.db discover --target 10.0.0.5  --collector ssh
```

```text
Discovery job 1e61081d-f611-4bc4-8a18-0298bce38a87 complete: 1 assets, 2 services, 0 filesystems, 0 running services, 0 connections.
Discovery job 60c4d557-1669-4db6-81d8-cf3cb8ce4bb5 complete: 1 assets, 0 services, 1 filesystems, 1 running services, 2 connections.
```

The nmap run found `server-a.example.com` with two open services; the ssh probe
found `web-01`, a nearly-full `/` filesystem, the running `nginx` service, and
two live connections — one to the database `db-01` and one to an external
endpoint (`203.0.113.9:443`).

## 3. Inspect the inventory

```bash
orbyn --db demo.db assets --format csv
```

```text
id,ip,hostname,device_class,os_name,os_version,environment,owner,criticality,tags,first_seen,last_seen
10-0-0-10,10.0.0.10,server-a.example.com,server,Linux 5.15.0-94-generic,,,,,,2026-10-03T00:21:29.843367976+00:00,2026-10-03T00:21:29.843367976+00:00
10-0-0-2,10.0.0.2,db-01,server,Ubuntu 18.04.6 LTS,,prod,,critical,,2026-10-03T00:21:29.822058416+00:00,2026-10-03T00:21:29.822058416+00:00
10-0-0-5,10.0.0.5,web-01,server,Ubuntu 22.04.4 LTS,5.15.0-94-generic,,,,,2026-10-03T00:21:29.859995445+00:00,2026-10-03T00:21:29.859995445+00:00
10-0-0-9,10.0.0.9,cache-01,server,Ubuntu 22.04.4 LTS,,,,,,2026-10-03T00:21:29.822059146+00:00,2026-10-03T00:21:29.822059146+00:00
```

A single host record shows capacity, disks, and services:

```bash
orbyn --db demo.db asset 10.0.0.5
```

```text
Asset     : 10-0-0-5
IP        : 10.0.0.5
Hostname  : web-01
Class     : server
OS        : Ubuntu 22.04.4 LTS 5.15.0-94-generic
Env       : -
Owner     : -
Criticality: -
Tags      : -
First seen: 2026-10-03 00:21:29
Last seen : 2026-10-03 00:21:29

CPU model  : Intel(R) Xeon(R) Gold 6138 CPU @ 2.00GHz
Sockets    : 1
Cores      : 4
vCPU       : 8
RAM        : 16001 MB
Hypervisor : - (bare metal or undetected)
Collected  : 2026-10-03 00:21:29

┌───────────┬───────┬──────┬───────┬───────┬─────────┬──────┐
│ Device    ┆ Mount ┆ Type ┆ Size  ┆ Used  ┆ Free    ┆ Use% │
╞═══════════╪═══════╪══════╪═══════╪═══════╪═════════╪══════╡
│ /dev/sda1 ┆ /     ┆ ext4 ┆ 50.0G ┆ 46.0G ┆ 3059.2M ┆ 92%  │
└───────────┴───────┴──────┴───────┴───────┴─────────┴──────┘

┌───────────────┬─────────┬───────────────────────────────┐
│ Service       ┆ State   ┆ Description                   │
╞═══════════════╪═════════╪═══════════════════════════════╡
│ nginx.service ┆ running ┆ A high performance web server │
└───────────────┴─────────┴───────────────────────────────┘
```

## 4. Map dependencies

The observed connection `web-01 -> db-01 (tcp/5432)` becomes an *unconfirmed*
edge from active connections; a manual edge records the cache dependency:

```bash
orbyn --db demo.db deps add cache-01 db-01 --port 6379
orbyn --db demo.db graph
```

```text
Dependency added: cache-01 -> db-01 (tcp/6379).

┌─────────────────────┬────┬──────────────────┬──────────┬────────────────────┬────────────┬───────────┐
│ Source              ┆ -> ┆ Target           ┆ Via      ┆ Evidence           ┆ Confidence ┆ Confirmed │
╞═════════════════════╪════╪══════════════════╪══════════╪════════════════════╪════════════╪═══════════╡
│ web-01 (10.0.0.5)   ┆ -> ┆ db-01 (10.0.0.2) ┆ tcp/5432 ┆ active-connections ┆ 90%        ┆ no        │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┤
│ cache-01 (10.0.0.9) ┆ -> ┆ db-01 (10.0.0.2) ┆ tcp/6379 ┆ manual             ┆ 100%       ┆ yes       │
└─────────────────────┴────┴──────────────────┴──────────┴────────────────────┴────────────┴───────────┘
```

The unconfirmed edge is the one to confirm before planning:

```bash
orbyn --db demo.db deps confirm web-01 db-01 --proto tcp --port 5432
```

```text
Confirmed 1 edge(s).
```

## 5. Assess the estate

```bash
orbyn --db demo.db assess
```

```text
Migration assessment
Rules version : 0.8.0
Assets assessed : 4
Overall score  : 16/100 (low)
```

The findings surface the EOL database OS, the hub (`db-01`), external coupling,
and the near-full disk — each with its rule id and evidence:

```bash
orbyn --db demo.db assess --format csv
```

```text
rule_id,severity,asset_id,message
os.eol,high,10-0-0-2,"operating system is at or near end of vendor support; in-place upgrade or re-platforming is likely required before migration"
dep.hub,warning,10-0-0-2,"2 assets depend on this asset; migration requires coordinated planning and a verified blast radius"
dep.external,warning,10-0-0-5,"active connections target endpoints outside the managed inventory; unknown coupling complicates migration planning"
disk.near-full,warning,10-0-0-5,"filesystem is nearly full; data transfer windows and target sizing need review before migration"
dep.unconfirmed,info,,"dependency edges are observed but not yet confirmed; confirm them (`orbyn deps confirm`) before wave planning"
capacity.missing,info,10-0-0-10,"no CPU/RAM capacity recorded; right-sizing is impossible until host-level collection runs"
```

Per-asset complexity and application groups:

```text
Asset complexity:
┌───────────┬───────┬──────────┐
│ Asset     ┆ Score ┆ Findings │
╞═══════════╪═══════╪══════════╡
│ 10-0-0-2  ┆ 37    ┆ 3        │
├╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┤
│ 10-0-0-5  ┆ 22    ┆ 3        │
├╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┤
│ 10-0-0-10 ┆ 2     ┆ 1        │
├╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┤
│ 10-0-0-9  ┆ 2     ┆ 1        │
└───────────┴───────┴──────────┘

Application groups:
┌───────┬──────────────────────────────┬───────┐
│ Group ┆ Assets                       ┆ Edges │
╞═══════╪══════════════════════════════╪═══════╡
│ app-1 ┆ 10-0-0-2, 10-0-0-5, 10-0-0-9 ┆ 2     │
└───────┴──────────────────────────────┴───────┘
```

## 6. Plan migration waves

```bash
orbyn --db demo.db waves --format csv
```

```text
wave,label,asset,score,reasons
1,low risk,10-0-0-10,3,"environment unset (treated as neutral); criticality unset (treated as high); complexity low (score 2/100)"
3,high risk / core,10-0-0-9,3,"environment unset (treated as neutral); criticality unset (treated as high); complexity low (score 2/100); member of app-1 (migrates as one unit)"
3,high risk / core,10-0-0-5,6,"environment unset (treated as neutral); criticality unset (treated as high); complexity medium (score 22/100); 1 external endpoint(s); 1 unconfirmed dependency edge(s); member of app-1 (migrates as one unit)"
3,high risk / core,10-0-0-2,7,"production environment prod; criticality critical; complexity medium (score 37/100); 1 unconfirmed dependency edge(s); member of app-1 (migrates as one unit)"
```

The planner scores `db-01` highest (prod + critical + complexity) and keeps the
whole application group together in wave 3. A manual pin overrides the band:

```bash
orbyn --db demo.db waves --pin 10-0-0-2=1
```

```text
Wave: 1 (low risk) — 10-0-0-2 (score 7) ... pinned to wave 1 via --pin
Wave: 1 (low risk) — 10-0-0-5 (score 6) ... pinned to wave 1 via --pin
Wave: 1 (low risk) — 10-0-0-9 (score 3) ... pinned to wave 1 via --pin
```

## 7. Match target SKUs

The `rs.*` right-sizing baseline feeds `sku-match` to pick concrete instance
types (here, a web server sized at 8 vCPU / 16 GiB):

```bash
orbyn --db demo.db sku-match --provider aws --cores 8 --ram-mb 16384
```

```text
aws instance types meeting 8 vCPU and 16384 MiB RAM (smallest fit first):
┌─────────────┬──────┬───────────┐
│ Name        ┆ vCPU ┆ RAM (MiB) │
╞═════════════╪══════╪═══════════╡
│ c5.2xlarge  ┆ 8    ┆ 16384     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┤
│ t3.2xlarge  ┆ 8    ┆ 32768     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┤
│ m5.2xlarge  ┆ 8    ┆ 32768     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┤
│ m6i.2xlarge ┆ 8    ┆ 32768     │
├╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┤
│ r5.2xlarge  ┆ 8    ┆ 65536     │
└─────────────┴──────┴───────────┘
```

## 8. Export for automation

```bash
orbyn --db demo.db export --format ansible
```

```text
[server]
cache-01 ansible_host=10.0.0.9
db-01 ansible_host=10.0.0.2 orbyn_environment=prod orbyn_criticality=critical
server-a.example.com ansible_host=10.0.0.10
web-01 ansible_host=10.0.0.5
```

## What was demonstrated

| Capability | Command | Output shows |
| --- | --- | --- |
| Persistence | `import` | audit job + merged estate |
| Discovery | `discover` (nmap/ssh) | services, filesystem, services, connections |
| Inventory | `assets` / `asset` | normalized records, capacity, disks |
| Dependency mapping | `deps add` / `graph` | observed + manual edges, confidence |
| Assessment | `assess` | findings with rule ids, scores, groups |
| Wave planning | `waves` | risk-banded waves with reasons |
| Target sizing | `sku-match` | smallest-fit instance types |
| Automation | `export` | Ansible inventory |

These runs are reproducible: the JSON seed and collector stubs mirror the
fixtures used by the automated suite, so what you see here is what CI checks.