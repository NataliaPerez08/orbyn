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
