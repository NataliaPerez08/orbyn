# SNMP collector

`--collector snmp` walks two MIB subtrees on **one host** with the
externally installed `snmpwalk` (net-snmp):

| Subtree | Content |
| --- | --- |
| `1.3.6.1.2.1.1` (system) | `sysName`, `sysDescr`, `sysObjectID` |
| `1.3.6.1.2.1.2.2.1` (ifTable) | interface descr, MAC, index, MTU, oper status |

Exact argv:

```text
snmpwalk -v <1|2c> -On -t 3 -r 1 <ip>:<port> <oid>
```

`SNMPCONFPATH` is pointed at a private temporary directory for the walk and
removed afterwards.

## When to use it

Network devices that have no shell to log into: switches, routers, printers,
firewalls. Complement an Nmap pass to get interface tables and a trustworthy
device class.

```bash
orbyn discover --target 10.0.0.8 --collector snmp --community public

# keep the community off argv entirely (reads one line from stdin)
orbyn discover --target 10.0.0.8 --collector snmp --community - <<< "$ORBYN_SNMP_COMMUNITY"

# SNMP v1 agent
orbyn discover --target 10.0.0.8 --collector snmp --snmp-version 1 --community - < community.txt

# non-standard agent port
orbyn discover --target 10.0.0.8 --collector snmp --snmp-port 1161 --community public
```

!!! warning "Single host only"
    A CIDR target is accepted by validation but rejected at scan time:
    `SNMP walks a single host; target must be an IP address (got '<cidr>')`.

## Options

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--community <c>` / `ORBYN_SNMP_COMMUNITY` | `public` | Community string; `-` reads one line from stdin |
| `--snmp-version <v>` | `2c` | `1` or `2c` |
| `--snmp-port <p>` | `161` | Agent UDP port |
| `ORBYN_SNMP_BIN` | `snmpwalk` | Binary path |

The community is **never** passed as an argument. Orbyn writes a temporary
`snmp.conf` (`0600` inside a `0700` directory) containing
`defCommunity <community>`, points `SNMPCONFPATH` at it, and deletes it after
the walk. A community containing newlines or NUL bytes is rejected, and the
value is registered with the redactor so it never appears in logs, errors or
the audit trail. Stale temp directories older than an hour are cleaned once
per process.

## Requirements

* `snmpwalk` from net-snmp (`net-snmp` / `net-snmp-utils` package) supporting
  `-On` and `SNMPCONFPATH`.
* An SNMP agent answering on the target with a valid v1/v2c community.
* Reachability on UDP `--snmp-port` (default 161).

## What it produces

| Observation | Fields |
| --- | --- |
| `Asset` | hostname from `sysName` (fallback: raw `sysDescr`), `os_name` derived from `sysDescr` (known families such as `Cisco IOS`, `Juniper Junos`; otherwise the first comma segment), `device_class` |
| `Interface` | descr, MAC from `ifPhysAddress`, ifIndex, MTU, `is_up` from `ifOperStatus == 1` |

Rows with neither description nor MAC are skipped. `sysDescr` itself is kept
raw; the derived OS name is stored separately, so no evidence is lost.

Vendor identification comes from enterprise numbers in `sysObjectID`
(Cisco 9, Juniper 2636, HP 11/4405, Huawei 2011, Fortinet 12356, Avaya 171,
Riverbed 11638, IBM 236) and feeds classification.

```bash
orbyn assets 10.0.0.8
orbyn interfaces 10.0.0.8
orbyn asset 10.0.0.8
```

## Limits and failures

* One walk per target, 30 s timeout (`snmpwalk -t 3 -r 1`).
* Output above 16 MiB fails the target: `the walk result is incomplete`.
* `sysDescr` is truncated to 79 characters plus an ellipsis when it is used
  as an OS name.
* No SNMPv3 — v1/v2c communities only.
