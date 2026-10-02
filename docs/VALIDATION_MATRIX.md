# Validation matrix

Status of every integration across fixture, live and scale validation (Phase 4
of `ORBYN_AGENT_PLAN.md`). Labels are honest: **no integration is claimed
production-validated on fixture tests alone** — fixture coverage proves
behavior against recorded responses, not against a real system.

- **Fixture Tested**: automated end-to-end suite runs the real binary against
  recorded/scripted tool output (fake `nmap`/`ssh`/`snmpwalk`/`curl`/`dig`).
- **Live Tested**: verified against a real system; where credentials or billing
  make continuous testing impractical this is documented as a manual procedure.
- **Scale Tested**: exercised at representative size (import/assess/export of a
  10k-asset estate; discovery fan-out over 1,024 targets; a week of metric
  history over 1.5k assets).

## Matrix

| Integration | Fixture Tested | Live Tested | Scale Tested | Last Validation | Notes |
|---|---|---|---|---|---|
| Nmap collector | Yes | No | Yes (1,024-target fan-out) | 2026-10-03 | read-only `-sS -sV`; scope validated; timeout/stderr-flood covered |
| SNMP collector | Yes | No | Yes (estate) | 2026-10-03 | community via 0600 `snmp.conf`, never argv |
| SSH (Linux) | Yes | No | Yes (estate) | 2026-10-03 | ssh-agent/identity only; no credentials stored |
| Windows OpenSSH | Yes | No | No | 2026-10-03 | PowerShell probe over SSH |
| WinRM/WS-Man | Yes | No | No | 2026-10-03 | HTTPS-only; password via stdin, never persisted |
| DNS evidence | Yes | No | No | 2026-10-03 | CNAME/PTR; `dig` option-guard for hostile names |
| NetBox importer | Yes | No | No | 2026-10-03 | token via stdin; hostile pagination URLs rejected |
| Prometheus importer | Yes | No | Yes (1.5k assets × week) | 2026-10-03 | right-sizing window; idempotent re-import; 429 retried |
| Zabbix importer | Yes | No | No | 2026-10-03 | history + right-sizing; token redacted |
| Proxmox VE adapter | Yes | No | No | 2026-10-03 | nodes, VMs, LXC, storage, guest agent |
| AWS adapter | Yes | No | No | 2026-10-03 | SigV4 no-SDK; pagination; account provenance |
| Huawei Cloud adapter | Yes | No | No | 2026-10-03 | AK/SK signer; pagination; flavor capacity |
| OpenStack adapter | Yes | No | No | 2026-10-03 | Nova servers + flavors, Cinder volumes |
| GCP adapter | Yes | No | No | 2026-10-03 | Compute aggregated API, disks, labels |
| Azure adapter | Yes | No | No | 2026-10-03 | ARM VMs, NICs, disks, VNets |
| Ansible export | Yes | No | Yes (10k estate) | 2026-10-03 | INI + YAML; injection-safe host/tag names |
| Terraform export | Yes | No | Yes (10k estate) | 2026-10-03 | HCL locals + import blocks; `${}` escaped |
| SQLite backend | Yes | Yes (local, every run) | Yes (10k estate) | 2026-10-03 | 0600 file; migrations; corrupt-file clean failure |
| PostgreSQL backend | Yes (gated) | Partial — audit OY-06 live check 2026-09-30 | No | 2026-09-30 | CI runs the suite when a live PG is present |

## Live validation

Continuous live validation is impractical for cloud/billing-gated providers,
so each is documented as a manual procedure. Run against authorized systems and
verify the assertions listed.

```text
Linux / SSH    orbyn discover --target <ip> --collector ssh
               -> host facts, capacity, filesystems, running services, edges

Windows / WinRM  ORBYN_WINRM_PASSWORD=<pw> orbyn discover --target <ip> --collector winrm
               -> host facts + connections over HTTPS (5986)

NetBox         orbyn netbox import --url https://netbox.example.com --token -
               -> devices/VMs appear; token absent from output and argv

Prometheus     orbyn prometheus import --url http://prometheus:9090
               -> a week of history; `orbyn metrics <id>` shows span + readiness

Zabbix         orbyn zabbix import --url http://zabbix --user <u> --password -
               -> history maps to assets; re-import is idempotent

Proxmox VE     orbyn proxmox import --url https://pve:8006 --token -
               -> nodes, VMs, LXC, datastores, guest-agent interfaces

AWS            AWS_ACCESS_KEY_ID/... orbyn aws import --region <r>
               -> EC2 + EBS + VPC/subnets; provenance tags; detached volumes skipped

Huawei Cloud   HUAWEICLOUD_SDK_AK/... orbyn huawei import --region <r>
               -> ECS + EVS + VPC/subnets; flavor capacity

OpenStack      orbyn openstack import --url <v2.1/project> --token <t> --project <p>
               -> servers, flavors, volumes

GCP            orbyn gcp import --project <p> --endpoint-url <url> --token <t>
               -> instances, disks, machine-type capacity

Azure          orbyn azure import --subscription-id <s> --token <t>
               -> VMs, NICs, disks, VNets

PostgreSQL     ORBYN_PG_PASSWORD=<pw> orbyn --db postgres://user@host:5432/db assets
               -> backend selected, schema migrated, credentials not in argv
```

## Caveats

- Credentials are never persisted or echoed; the redactor scrubs known values
  from errors and job records.
- A fixture-passing adapter is **not** a production validation: provider API
  drift, network topology and real capacity data are only exercised live.
- Scale numbers are order-of-magnitude expectations from this repository's
  machines; see `docs/PERFORMANCE.md`.