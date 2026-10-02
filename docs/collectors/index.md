# Collectors

Collectors transform external observations into the normalized domain model.
They never write to the database directly — they return typed observations and
the store handles persistence. **All collectors are read-only**: they must not
modify the systems they inspect, targets are passed as argument vectors (never
shell strings), and secrets are stripped from every child process
environment.

## The collector set

| `--collector` | Module | What it discovers | Needs |
| --- | --- | --- | --- |
| `nmap` *(default)* | `src/collectors/nmap.rs` | Hosts, open ports, service banners, OS guess, MAC/vendor | `nmap` |
| `snmp` | `src/collectors/snmp.rs` | Hostname, OS/device class, interfaces (MAC, MTU, state) | `snmpwalk` (net-snmp) |
| `ssh` | `src/collectors/ssh.rs` | Linux OS, capacity, filesystems, systemd units, connections, metrics | OpenSSH client |
| `windows` | `src/collectors/windows.rs` | Windows OS, capacity, disks, services, connections, metrics — over OpenSSH | OpenSSH client + target OpenSSH Server |
| `winrm` | `src/collectors/winrm.rs` | Same Windows facts — over native WS-Man/HTTPS | `curl` + WinRM listener |
| *(not a collector)* | `src/collectors/dns.rs` | Relationship evidence from forward/CNAME/PTR lookups | `dig` (optional) |

Two more modules are internal helpers with no CLI entry point:

* **`virt`** — normalizes hypervisor detection into a canonical vocabulary
  (`kvm`, `vmware`, `hyperv`, …) for the `capacity` facet.
* **`classify`** — classifies a device as `server`, `network-device`,
  `printer`, `storage` or `security-appliance` from OS name, MAC vendor,
  service names and `sysDescr`.

Both are described in [Framework internals](framework.md), together with the
`Collector` trait, target validation and the credential profile type.

## Running a collector

```bash
orbyn discover --target <cidr|ip> [--target ...] --collector <name> [options]
```

Every run creates a discovery job — collector name, targets, status, counts —
visible with [`orbyn jobs`](../cli.md#inventory).

```bash
# Nmap over a whole authorized subnet
orbyn discover --target 10.0.0.0/24

# one switch over SNMP
orbyn discover --target 10.0.0.8 --collector snmp --community - <<< "$ORBYN_SNMP_COMMUNITY"

# one Linux host
orbyn discover --target 10.0.0.10 --collector ssh --user deploy --identity-file ~/.ssh/id_ed25519
```

!!! note "Single-host collectors"
    `snmp`, `ssh`, `windows` and `winrm` each collect **one host per
    `--target`**. A CIDR is rejected at scan time with
    `target must be an IP address`. Only `nmap` accepts ranges; for the others,
    loop over addresses yourself and rely on `--concurrency` / `--rate-limit`.

## Target validation

Targets are validated *before* any collector runs
(`validate_target_with_policy`):

| Rule | Value |
| --- | --- |
| Minimum IPv4 prefix | `/16` (65 536 addresses) |
| Minimum IPv6 prefix | `/48` |
| Override | `--allow-large-cidr` |
| Always rejected | `/0` prefixes, `0.0.0.0` / `::` base addresses |
| Always rejected | Anything that is not an IP or CIDR (hostnames included) |

## Shared runtime limits

| Limit | Value | Override |
| --- | --- | --- |
| Parallel scans | `--concurrency` (default `4`) | flag |
| Launch pacing | none | `--rate-limit N` |
| Subprocess stdout cap | 16 MiB | — |
| Subprocess stderr cap | 1 MiB | — |
| Child env secrets | scrubbed | — |

Per-collector timeouts:

| Collector | Timeout |
| --- | --- |
| nmap | 1800 s whole process (`ORBYN_NMAP_TIMEOUT_SECS`) |
| snmp | 30 s per walk (`snmpwalk -t 3 -r 1`) |
| ssh / windows-over-ssh | 60 s per probe, `ConnectTimeout=10` |
| winrm | 60 s per request, WS-Man `PT30S`, ≤ 16 receive rounds |
| dns | 5 s per resolution |

Partial failure: observations from successful targets are **always**
persisted; the job is marked failed with `N of M targets failed: …`.

## Reading the results

| Observation | Produced by | Display with |
| --- | --- | --- |
| Asset | nmap, snmp, ssh, windows, winrm | `orbyn assets`, `orbyn asset <ip>` |
| Service | nmap | `orbyn services <ip>` |
| Interface | nmap, snmp | `orbyn interfaces <ip>` |
| Capacity | ssh, windows, winrm | `orbyn capacity <ip>` |
| Filesystem | ssh, windows, winrm | `orbyn disks <ip>` |
| Running service | ssh, windows, winrm | `orbyn host-services <ip>` |
| Connection | ssh, windows, winrm | `orbyn connections <ip>` → reconciled into dependency edges |
| Metric sample | ssh, windows, winrm | `orbyn metrics <ip> [--samples N]` |
| Dependency | dns, connections, manual | `orbyn graph`, `orbyn deps ...` |
| Discovery job | discovery runner | `orbyn jobs` |

Connections observed by the host probes are reconciled into dependency edges
with evidence `active-connections` at confidence `0.9`, which feed
[`orbyn graph`](../cli.md#dependencies-and-graph) and
[`orbyn assess`](../cli.md#assessment).
