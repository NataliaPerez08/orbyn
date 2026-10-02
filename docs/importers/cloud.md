# Cloud and platform importers

Read-only adapters that bring a cluster or cloud account into the same
inventory the collectors build. No agent is installed anywhere and nothing is
written back to the provider.

## Proxmox VE

Nodes, node datastores, QEMU VMs and LXC containers — with per-guest
interfaces (guest agent → container API → config fallback), OS identity,
filesystems and CPU/RAM capacity.

```bash
orbyn proxmox import --url https://pve.example.com:8006 --token - < ~/.proxmox-token

# single node only
orbyn proxmox import --url https://pve.example.com:8006 --token - --node pve1 < tok

# self-signed certificate
orbyn proxmox import --url https://pve.example.com:8006 --token - --no-verify < tok
```

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--url` | *(required)* | Base URL, e.g. `https://pve.example.com:8006` |
| `--token` / `ORBYN_PROXMOX_TOKEN` | *(required)* | API token `user@realm!tokenid=secret`; `-` reads stdin |
| `--node <name>` | *(all nodes)* | Restrict to one cluster node |
| `--no-verify` | off | Skip TLS verification |

## AWS

EC2 instances and their elastic network interfaces, EBS volumes (attached to
their instance as filesystems) and VPC/subnet resources (as assets keyed by
their CIDR network address), through the signed EC2 query API — SigV4
implemented directly, **no SDK**. The account id is resolved from STS when
permitted.

```bash
# credentials from the environment
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=eu-west-1
orbyn aws import

# explicit flags, secret from stdin
orbyn aws import --region eu-west-1 --access-key AKIA... --secret-key - < ~/.aws-secret

# temporary credentials / private endpoint
orbyn aws import --region eu-west-1 --session-token - --endpoint-url https://ec2.internal --no-verify < tok
```

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--region` / `AWS_REGION`, `AWS_DEFAULT_REGION` | *(required unless env set)* | e.g. `eu-west-1` |
| `--access-key` / `AWS_ACCESS_KEY_ID` | env | Access key id |
| `--secret-key` / `AWS_SECRET_ACCESS_KEY` | env | Secret key; `-` reads stdin |
| `--session-token` / `AWS_SESSION_TOKEN` | env | Session token for temporary credentials |
| `--endpoint-url` / `AWS_ENDPOINT_URL` | AWS default | Private or test endpoint |
| `--no-verify` | off | Skip TLS verification |

## Azure

ARM VMs, NICs, managed disks, VNets, subnets, regions, capacity and tags.

```bash
export ORBYN_AZURE_TOKEN=...
export AZURE_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000
orbyn azure import

# token from stdin
orbyn azure import --subscription-id <id> --token - < ~/.azure-token
```

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--subscription-id` / `AZURE_SUBSCRIPTION_ID` | *(required)* | Subscription scope |
| `--token` / `ORBYN_AZURE_TOKEN` | *(required)* | Azure AD bearer token; `-` reads stdin |
| `--endpoint-url` | ARM default | Private or test endpoint |
| `--no-verify` | off | Skip TLS verification |

## GCP

Compute Engine instances, NICs, persistent disks, zones, machine capacity and
labels.

```bash
export GOOGLE_CLOUD_PROJECT=my-project
export ORBYN_GCP_TOKEN="$(gcloud auth print-access-token)"
orbyn gcp import
```

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--project` / `GOOGLE_CLOUD_PROJECT` | *(required)* | Project id |
| `--token` / `ORBYN_GCP_TOKEN` | *(required)* | OAuth bearer token; `-` reads stdin |
| `--endpoint-url` | Google default | Private or test endpoint |
| `--no-verify` | off | Skip TLS verification |

## OpenStack

Nova instances and flavors, ports and attached Cinder volumes.

```bash
export ORBYN_OPENSTACK_TOKEN="$(openstack token issue -f value -c id)"
export OS_PROJECT_ID=...
export OS_REGION_NAME=RegionOne
orbyn openstack import
```

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--url` | *(required)* | Nova endpoint, e.g. `https://cloud.example/v2.1/project-id` |
| `--token` / `ORBYN_OPENSTACK_TOKEN` | *(required)* | Scoped Keystone token; `-` reads stdin |
| `--project` / `OS_PROJECT_ID` | env | Project scope |
| `--region` / `OS_REGION_NAME` | env | Region scope |
| `--no-verify` | off | Skip TLS verification |

## Huawei Cloud

ECS instances and their network interfaces, EVS volumes (as filesystems on
their attached server) and VPC/subnet resources, through the signed
ECS/EVS/VPC APIs (`SDK-HMAC-SHA256`, no SDK). CPU/RAM capacity comes from the
flavor catalogue; the project id is resolved from IAM when omitted.

```bash
export HUAWEICLOUD_SDK_AK=...
export HUAWEICLOUD_REGION=cn-north-4
orbyn huawei import --secret-key - < ~/.huawei-sk

orbyn huawei import --region cn-north-4 --access-key <ak> --secret-key - \
    --project-id <id> --no-verify < sk.txt
```

Get the imported assets back out:

```bash
orbyn assets --format csv            # all ECS instances, volumes and VPC/subnets
orbyn assets --format json           # full records, including provenance tags
orbyn asset 10.0.1.4                 # one ECS instance: capacity, disks, tags
orbyn capacity 10.0.1.4              # CPU/RAM from the flavor catalogue
```

Every imported row carries `cloud:huawei` (plus `cloud-region:...` and
`cloud-account:...`) in its tags, so the origin is attributable per asset.

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--region` / `HUAWEICLOUD_REGION` | *(required unless env set)* | e.g. `cn-north-4` |
| `--access-key` / `HUAWEICLOUD_SDK_AK` | env | Access key (AK) |
| `--secret-key` / `HUAWEICLOUD_SDK_SK` | env | Secret key (SK); `-` reads stdin |
| `--project-id` / `HUAWEICLOUD_PROJECT_ID` | resolved from IAM | Project scope |
| `--endpoint-url` | Huawei default | Private or test endpoint |
| `--no-verify` | off | Skip TLS verification |

## After any cloud import

```bash
orbyn assets --format json          # includes provenance tags
orbyn asset 10.0.1.4                # full record: capacity, disks, tags
orbyn capacity 10.0.1.4             # CPU/RAM + hypervisor
orbyn assess                        # findings over the merged inventory
```

Credentials are never persisted; an audit event is recorded for every import.
