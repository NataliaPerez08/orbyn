# Demo environments

Orbyn ships three demo environments, from least to most realistic. Each one
exercises the same pipeline — inventory, dependency graph, assessment, wave
planning — with a different amount of real infrastructure behind it.

| Level | Directory | What it needs | What it proves |
| --- | --- | --- | --- |
| 1. CSV | `demo/csv/` | an `orbyn` binary, 10 seconds | graph, assess, application grouping, waves with zero infrastructure |
| 2. Docker | — | *(planned, not implemented yet)* | integration testing against containers that generate real traffic |
| 3. QEMU | `demo/qemu/` | QEMU, ~10 GB disk, ~8 GB RAM, sudo | the SSH collector against VMs that behave like real servers |

The separation also serves as Orbyn's manual validation environment: level 1
runs anywhere in seconds, level 3 reproduces collector behavior against
infrastructure that behaves much more like production.

## Level 1 — CSV demo (instant)

A predefined estate of 17 assets — load balancer, web and API tiers, workers,
PostgreSQL, Redis, monitoring, bastion, staging and dev environments, and two
deliberately end-of-life legacy systems — plus 19 dependency edges, all in two
fixture files. No infrastructure is contacted.

```bash
cd demo/csv
./run.sh
```

`run.sh` imports `fixtures/inventory.csv`, seeds the edges from
`fixtures/dependencies.txt` via `orbyn deps add`, then walks through the
estate, dependency graph, assessment, and migration waves. The `orbyn` binary
is picked up from `PATH`; override with `ORBYN_BIN=/path/to/orbyn`.

What to look for in the output:

- `os.eol` findings on `db-01` (Ubuntu 18.04), `legacy-app-01` (Debian 9),
  and `legacy-db-01` (CentOS 7)
- `dep.hub` on `db-01` — seven assets depend on it
- three application groups: the prod platform, the stage/dev chain, and the
  legacy pair
- wave planning keeps each application group together and bands `db-01` into
  the high-risk wave

The CSV format is the same one `orbyn export --format csv` produces; see
[Source of truth & export](importers/inventory.md) for the field reference.

## Level 2 — Docker demo (planned)

Not implemented yet. The goal is a functional lab:

```bash
cd docker
docker compose up -d
./generate-traffic.sh
./discover.sh
```

running an architecture similar to:

```text
nginx -> api -> postgres
             redis
worker -> postgres
prometheus -> services
```

The containers generate traffic between services so Orbyn can discover and
analyze real dependencies.

## Level 3 — QEMU demo (realistic infrastructure)

Four Linux VMs with SSH enabled on a private bridge:

| VM | IP | OS | Role |
| --- | --- | --- | --- |
| web-01 | 192.0.2.11 | Ubuntu 24.04 | nginx reverse proxy to api-01 (keepalive upstream) |
| api-01 | 192.0.2.12 | Ubuntu 22.04 | small Flask API holding PostgreSQL and Redis connections |
| db-01 | 192.0.2.13 | Ubuntu 20.04 | PostgreSQL + Redis for the lab |
| legacy-01 | 192.0.2.14 | Debian 11 | "legacy" box subscribed to Redis pub/sub |

The services are real packages installed by cloud-init, and each one holds
long-lived TCP connections to its dependencies, so Orbyn's SSH collector sees
established connections at probe time and derives `active-connections` edges:
`web-01 -> api-01`, `api-01 -> db-01`, `legacy-01 -> db-01`.

### Prerequisites

- `qemu-system-x86`, `qemu-img` (qemu-utils)
- `cloud-localds` (package `cloud-image-utils`) or `genisoimage`
- `ssh`, `curl`, `ip` (iproute2), `iptables`
- sudo, used once per host to create the lab bridge and NAT rule
- KVM (`/dev/kvm`) strongly recommended; without it the lab falls back to TCG
  emulation and boots slowly

### Workflow

```bash
cd demo/qemu
./download-images.sh   # fetch + checksum-verify the 4 cloud images (~2 GB)
./create-vms.sh        # SSH key, qcow2 overlays, cloud-init seeds
./start-lab.sh         # bridge + NAT (sudo), boot VMs, wait for cloud-init
./discover.sh          # orbyn discover --collector ssh, then graph/assess
./stop-lab.sh          # shut the VMs down
```

`discover.sh` runs one SSH discovery job over all four targets as the
`deploy` user with the generated `lab_key`, then prints the estate, the
web-01 asset detail (CPU, RAM, filesystems, running services, hypervisor
detected as `kvm`), the dependency graph, and the assessment.

### Notes

- The lab network is 192.0.2.0/24 (TEST-NET-3, never routed on real
  networks). The host takes 192.0.2.1 on bridge `br0` and NATs VM traffic to
  the internet so cloud-init can install packages.
- The SSH collector authenticates with keys only; `create-vms.sh` generates
  `lab_key` and cloud-init installs it for the `deploy` user on every VM.
- The PostgreSQL password in `cloud-init/db-01-user-data.yaml` is a throwaway
  that is only valid inside the isolated lab bridge.
- VM disks are qcow2 overlays of the downloaded images; delete `disks/` and
  re-run `create-vms.sh` for a pristine lab, or keep them to persist state.
- Boot consoles are logged to `logs/<vm>.console.log` for debugging.
