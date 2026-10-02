# Importers & integrations

Importers pull inventory or utilization history from systems you already run.
Everything is **read-only**: Orbyn never writes back to NetBox, Prometheus,
Zabbix, a Proxmox cluster or a cloud account.

| Importer | Command | Pulls |
| --- | --- | --- |
| NetBox | `orbyn netbox import` | Devices, VMs, interfaces, assigned IPs |
| Prometheus | `orbyn prometheus import` | Historical CPU/RAM utilization |
| Zabbix | `orbyn zabbix import` | Historical CPU/RAM/swap utilization |
| Proxmox VE | `orbyn proxmox import` | Nodes, datastores, QEMU VMs, LXC containers |
| AWS | `orbyn aws import` | EC2 instances, ENIs, EBS volumes, VPC/subnets |
| Azure | `orbyn azure import` | ARM VMs, NICs, managed disks, VNets, subnets |
| GCP | `orbyn gcp import` | Compute Engine instances, NICs, persistent disks |
| OpenStack | `orbyn openstack import` | Nova instances and flavors, ports, Cinder volumes |
| Huawei Cloud | `orbyn huawei import` | ECS instances, EVS volumes, VPC/subnets |
| File | `orbyn import` | Inventory from JSON or CSV |
| Export | `orbyn export` | JSON, CSV, Ansible, Terraform |

Cloud importers attach provenance tags to every asset — `cloud:<provider>`,
`cloud-account:<id>`, `cloud-region:<region>` — and record an audit event.

## Credentials

Secrets are never persisted and never logged. Prefer stdin so they never land
in argv or the environment:

```bash
# any flag that accepts "-" reads one line from stdin
orbyn netbox import --url https://netbox.example.com --token - < ~/.netbox-token
orbyn zabbix import --url https://zabbix.example.com/api_jsonrpc.php --token - < ~/.zabbix-token
```

| Secret | Flag | Environment fallback |
| --- | --- | --- |
| NetBox API token | `--token` | `ORBYN_NETBOX_TOKEN` |
| Prometheus bearer token | `--token` | `ORBYN_PROMETHEUS_TOKEN` |
| Zabbix API token | `--token` | `ORBYN_ZABBIX_TOKEN` |
| Proxmox API token | `--token` | `ORBYN_PROXMOX_TOKEN` |
| AWS access key / secret / session token | `--access-key` / `--secret-key` / `--session-token` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
| Huawei AK / SK | `--access-key` / `--secret-key` | `HUAWEICLOUD_SDK_AK`, `HUAWEICLOUD_SDK_SK` |
| OpenStack scoped token | `--token` | `ORBYN_OPENSTACK_TOKEN` |
| GCP OAuth bearer | `--token` | `ORBYN_GCP_TOKEN` |
| Azure AD bearer | `--token` | `ORBYN_AZURE_TOKEN` |

A value containing newlines or NUL bytes is rejected; literal secrets on argv
trigger an audit warning.

## Shared behaviour

* **TLS:** every importer accepts `--no-verify` for self-signed lab
  certificates. Use it only where you accept the risk.
* **Retries:** transient timeouts, transport failures, rate limits and 5xx
  responses retry up to **three times** with bounded exponential backoff.
  4xx responses do not retry.
* **Size caps:** inventory imports are capped at 64 MiB; HTTP responses are
  capped per request.
* **Idempotency:** re-importing the same history does not duplicate samples;
  inventory metadata is preserved across re-discovery.
* **Environment:** a `.env` file in the current working directory is loaded at
  startup (existing environment variables win; parent directories are never
  searched).

## Where to go next

* [Cloud platforms](cloud.md) — Proxmox, AWS, Azure, GCP, OpenStack, Huawei
* [Observability](observability.md) — Prometheus and Zabbix utilization history
* [Source of truth & export](inventory.md) — NetBox, file import, Ansible and
  Terraform exports
