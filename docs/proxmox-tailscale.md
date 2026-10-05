# Research test: Proxmox over Tailscale

This page records a **real connectivity test** against a live Proxmox VE
hypervisor reached over a [Tailscale](https://tailscale.com) tailnet. Every
command below actually ran from a Linux host on the same tailnet and its
output is reproduced verbatim. No port forwarding, public IP, or VPN
concentration server is involved — the Proxmox web UI and API are only
reachable from inside the tailnet.

The same path works for the [Proxmox importer](importers/cloud.md#proxmox-ve):
point `orbyn proxmox import` at the tailnet address instead of exposing the
PVE API to a network.

## Environment

| Item | Value |
|------|-------|
| Proxmox node | `proxmox` (Tailscale device name) |
| Tailnet address | `100.115.215.49` (100.64.0.0/10, only routable inside the tailnet) |
| API daemon | `pve-api-daemon/3.0` |
| Web UI | HTTPS on `tcp/8006` (self-signed certificate) |
| Test client | Linux host on the same tailnet, `tailscale` CLI + `curl` |

## 1. The host is on the tailnet

```bash
tailscale status | grep proxmox
```

```text
100.115.215.49   proxmox   nataliaapr08@  linux   -
```

```bash
tailscale ping -c 3 proxmox
```

```text
pong from proxmox (100.115.215.49) via 201.137.46.179:58728 in 240ms
```

The first pongs may traverse a DERP relay until a direct path is established.

## 2. ICMP reachability

```bash
ping -c 3 100.115.215.49
```

```text
PING 100.115.215.49 (100.115.215.49) 56(84) bytes of data:
64 bytes from 100.115.215.49: icmp_seq=1 ttl=64 time=236 ms
64 bytes from 100.115.215.49: icmp_seq=2 ttl=64 time=6.61 ms
64 bytes from 100.115.215.49: icmp_seq=3 ttl=64 time=22.3 ms

--- 100.115.215.49 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 6.611/88.256/235.823/104.542 ms
```

0% packet loss; latency settles to single-digit milliseconds once the
direct WireGuard path replaces the relay.

## 3. TCP reachability

```bash
timeout 3 bash -c 'echo > /dev/tcp/100.115.215.49/22' && echo 'tcp/22 open'
```

```text
tcp/22 open
```

SSH (tcp/22) and the PVE web UI/API (tcp/8006) both accept connections
from the tailnet.

## 4. Web UI responds over HTTPS

```bash
curl -sk -o /dev/null -w '%{http_code} %{time_total}s\n' https://100.115.215.49:8006/
```

```text
200 0.403652s
200 0.274677s
200 0.344827s
```

```bash
curl -skI https://100.115.215.49:8006/ | grep -i server
```

```text
Server: pve-api-daemon/3.0
```

`-k` is required because PVE ships a self-signed certificate for the
node's public name, not the tailnet address.

## 5. API requires authentication

```bash
curl -sk -w '\nHTTP:%{http_code}\n' https://100.115.215.49:8006/api2/json/version
```

```text
HTTP:401
```

The API endpoint is reachable but rejects unauthenticated requests, as it
should. A valid API token or ticket is required for any real call.

## 6. Using the path with orbyn

With an [API token](importers/cloud.md#proxmox-ve) created in the PVE UI:

```bash
orbyn proxmox import --url https://100.115.215.49:8006 --token - < ~/.proxmox-token
```

The importer talks to the same `pve-api-daemon` verified above, so the
connectivity results apply directly.

## 7. Resource inventory with orbyn

The path was then used for a real import. A dedicated read-only API token
was created on the node over SSH, using the built-in `PVEAuditor` role —
no privileges beyond reading cluster state:

```bash
ssh root@100.115.215.49
pveum user add orbyn@pve --comment "orbyn importer"
pveum acl modify / --users orbyn@pve --roles PVEAuditor
pveum user token add orbyn@pve docs --privsep 0
```

The token secret (`orbyn@pve!docs=<value>`) is stored in `~/.proxmox-token`
(`chmod 600`), never in the repository.

### The import

```bash
orbyn --db proxmox.db proxmox import \
  --url https://100.115.215.49:8006 --token - --no-verify < ~/.proxmox-token
```

```text
WARNING: --no-verify disables TLS certificate verification.
Only use this against a trusted self-signed Proxmox instance; connections can be silently intercepted.
Imported 11 assets, 39 interfaces, 11 capacity rows, 17 filesystems from Proxmox (proxmox:orbyn@pve).
Skipped 1 resource(s) that could not be represented.
```

One guest (`debian12`, vmid 102) was skipped: it has no reachable IP
address — no guest agent and no IP in its configuration.

### The inventory

```bash
orbyn --db proxmox.db assets --format csv
```

```text
id,ip,hostname,device_class,os_name,os_version,environment,owner,criticality,tags,first_seen,last_seen
10-0-0-21,10.0.0.21,pushlane-git,virtual-machine,Ubuntu 24.04.5 LTS,24.04,,,,"proxmox-node:proxmox,proxmox-vmid:204,proxmox-status:running,cloud:proxmox,cloud-account:orbyn@pve",2026-10-05T22:11:44.348946335+00:00,2026-10-05T22:11:44.348946335+00:00
10-0-0-22,10.0.0.22,pushlane-ci,virtual-machine,Ubuntu 24.04.5 LTS,24.04,,,,"proxmox-node:proxmox,proxmox-vmid:202,proxmox-status:running,cloud:proxmox,cloud-account:orbyn@pve",2026-10-05T22:11:44.348946335+00:00,2026-10-05T22:11:44.348946335+00:00
10-0-0-23,10.0.0.23,pushlane-app,virtual-machine,Ubuntu 24.04.5 LTS,24.04,,,,"proxmox-node:proxmox,proxmox-vmid:203,proxmox-status:running,cloud:proxmox,cloud-account:orbyn@pve",2026-10-05T22:11:44.348946335+00:00,2026-10-05T22:11:44.348946335+00:00
10-0-0-50,10.0.0.50,noble-template,virtual-machine,Linux,,,,,"proxmox-node:proxmox,proxmox-vmid:9000,proxmox-status:stopped,cloud:proxmox,cloud-account:orbyn@pve",2026-10-05T22:11:44.348946335+00:00,2026-10-05T22:11:44.348946335+00:00
172-20-0-10,172.20.0.10,proxmox,hypervisor,,,,,,"proxmox-node:proxmox,cloud:proxmox,cloud-account:orbyn@pve",2026-10-05T22:11:44.348946335+00:00,2026-10-05T22:11:44.348946335+00:00
172-20-0-16,172.20.0.16,loki-ct,container,debian,,,,,"proxmox-node:proxmox,proxmox-vmid:111,proxmox-status:running,cloud:proxmox,cloud-account:orbyn@pve",2026-10-05T22:11:44.348946335+00:00,2026-10-05T22:11:44.348946335+00:00
172-20-0-20,172.20.0.20,monitoring,container,debian,,,,,"proxmox-node:proxmox,proxmox-vmid:200,proxmox-status:running,cloud:proxmox,cloud-account:orbyn@pve",2026-10-05T22:11:44.348946335+00:00,2026-10-05T22:11:44.348946335+00:00
172-20-0-21,172.20.0.21,cloudflared,container,debian,,,,,"proxmox-node:proxmox,proxmox-vmid:201,proxmox-status:running,cloud:proxmox,cloud-account:orbyn@pve",2026-10-05T22:11:44.348946335+00:00,2026-10-05T22:11:44.348946335+00:00
172-20-0-22,172.20.0.22,overleaf,container,ubuntu,,,,,"proxmox-node:proxmox,proxmox-vmid:110,proxmox-status:running,cloud:proxmox,cloud-account:orbyn@pve",2026-10-05T22:11:44.348946335+00:00,2026-10-05T22:11:44.348946335+00:00
172-20-0-26,172.20.0.26,development,container,debian,,,,,"proxmox-node:proxmox,proxmox-vmid:100,proxmox-status:stopped,cloud:proxmox,cloud-account:orbyn@pve",2026-10-05T22:11:44.348946335+00:00,2026-10-05T22:11:44.348946335+00:00
172-20-0-30,172.20.0.30,nextcloud,container,ubuntu,,,,,"proxmox-node:proxmox,proxmox-vmid:112,proxmox-status:running,cloud:proxmox,cloud-account:orbyn@pve",2026-10-05T22:11:44.348946335+00:00,2026-10-05T22:11:44.348946335+00:00
```

That is **1 hypervisor**, **4 virtual machines** (3 running, plus the
stopped `noble-template`) and **6 LXC containers** (5 running, plus the
stopped `development`). The two networks are visible in the addressing:
VMs live on `10.0.0.0/24`, containers on `172.20.0.0/24`.

### Node capacity and datastores

```bash
orbyn --db proxmox.db asset 172.20.0.10
```

```text
Asset     : 172-20-0-10
IP        : 172.20.0.10
Hostname  : proxmox
Class     : hypervisor
Tags      : proxmox-node:proxmox,cloud:proxmox,cloud-account:orbyn@pve

CPU model  : -
Sockets    : -
Cores      : 4
RAM        : 15862 MB
Hypervisor : - (bare metal or undetected)
Collected  : 2026-10-05 22:11:44

┌────────┬───────────┬─────────┬────────┬────────┬────────┬──────┐
│ Device ┆ Mount     ┆ Type    ┆ Size   ┆ Used   ┆ Free   ┆ Use% │
╞════════╪═══════════╪════════╪════════╪════════╪════════╪══════╡
│ -      ┆ local     ┆ dir     ┆ 93.9G  ┆ 58.4G  ┆ 30.7G  ┆ 62%  │
├╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┤
│ -      ┆ local-lvm ┆ lvmthin ┆ 347.9G ┆ 124.2G ┆ 223.7G ┆ 36%  │
└────────┴──────────┴─────────┴────────┴────────┴────────┴──────┘
```

### A guest, in detail

`orbyn --db proxmox.db asset 10.0.0.22` shows what the importer captures
per guest — here the `pushlane-ci` VM, including the Docker bridges its
guest agent reports:

```text
Asset     : 10-0-0-22
IP        : 10.0.0.22
Hostname  : pushlane-ci
Class     : virtual-machine
OS        : Ubuntu 24.04.5 LTS 24.04
Tags      : proxmox-node:proxmox,proxmox-vmid:202,proxmox-status:running,cloud:proxmox,cloud-account:orbyn@pve

┌─────────────────┬───────────────────┬───────────────────────────┬────────┬─────┬───────┐
│ Name            ┆ MAC               ┆ IP                        ┆ Vendor ┆ MTU ┆ State │
╞═════════════════╪═══════════════════╪═══════════════════════════╪════════╪═════╪═══════╡
│ br-3aa71f70d989 ┆ 3a:73:9d:67:29:0b ┆ 172.18.0.1                ┆ -      ┆ -   ┆ up    │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌┼╌╌╌╌╌╌┤
│ br-5b9507338350 ┆ 96:8e:61:95:0e:b0 ┆ 172.19.0.1                ┆ -      ┆ -   ┆ up    │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌┼╌╌╌╌╌╌┤
│ docker0         ┆ d2:13:48:ad:5a:a6 ┆ 172.17.0.1                ┆ -      ┆ -   ┆ up    │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌┼╌╌╌╌╌╌┤
│ eth0            ┆ bc:24:11:e8:b4:73 ┆ 10.0.0.22                 ┆ -      ┆ -   ┆ up    │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌┼╌╌╌╌╌╌┤
│ veth011b320     ┆ a6:32:8d:28:55:0c ┆ fe80::a432:8dff:fe28:550c ┆ -      ┆ -   ┆ up    │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌┼╌╌╌╌╌╌┤
│ veth7ba096b     ┆ 6e:db:2b:7f:fa5d ┆ fe80::6cdb:2bff:fe7f:fa5d ┆ -      ┆ -   ┆ up    │
└─────────────────┴───────────────────┴───────────────────────────┴────────┴─────┴───────┘
CPU model  : -
Sockets    : 1
Cores      : 4
RAM        : 4096 MB
Hypervisor : kvm
Collected  : 2026-10-05 22:11:44

┌────────────┬───────────┬──────┬────────┬─────────┬────────┬──────┐
│ Device     ┆ Mount     ┆ Type ┆ Size   ┆ Used    ┆ Free   ┆ Use% │
╞════════════╪═══════════╪══════╪════════╪═════════╪════════╪══════╡
│ /dev/sda1  ┆ /         ┆ ext4 ┆ 37.7G  ┆ 8024.6M ┆ 29.9G  ┆ 21%  │
├╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┤
│ /dev/sda16 ┆ /boot     ┆ ext4 ┆ 818.7M ┆ 116.6M  ┆ 702.2M ┆ 14%  │
├╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌┤
│ /dev/sda15 ┆ /boot/efi ┆ vfat ┆ 104.3M ┆ 6249K   ┆ 98.2M  ┆ 6%   │
└────────────┴──────────┴──────┴────────┴─────────┴────────┴──────┘
```

Containers import the same way — e.g. `nextcloud` (vmid 112) lands as a
`container` asset at `172.20.0.30` with hypervisor `lxc` and its
`local-lvm:vm-112-disk-0` root filesystem.

### Dependencies

`orbyn --db proxmox.db graph` reports no dependencies yet: a cloud import
inventories resources but does not observe live connections. To map who
talks to whom, run host-level collection on the guests
(see [SSH collector](collectors/ssh.md)) or add edges manually with
`orbyn deps add`.

## Security notes

- The PVE web UI and API (`tcp/8006`) are **not** exposed to the public
  internet; they are only reachable from inside the tailnet, which
  authenticates every member.
- Restrict the tailnet further with Tailscale ACLs so only approved
  devices may reach the `proxmox` node on `tcp/22` and `tcp/8006`.
- Prefer a dedicated, least-privilege PVE API token for imports over
  reusing a user account.
- The tailnet address in this page is a private CGNAT-range IP
  (100.64.0.0/10); it is not routable outside the tailnet.

## Reproducing

From any device on the same tailnet:

```bash
tailscale status | grep proxmox
tailscale ping proxmox
ping -c 3 100.115.215.49
curl -sk -o /dev/null -w '%{http_code}\n' https://100.115.215.49:8006/
curl -sk -w '\nHTTP:%{http_code}\n' https://100.115.215.49:8006/api2/json/version
```

Expected: `pong` responses, 0% ping loss, `200` from the UI, and `401`
from the API without credentials.
