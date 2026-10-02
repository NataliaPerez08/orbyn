# Configuration

Orbyn is configured by a `.env` file in the current working directory and by
environment variables. Existing environment variables win; parent directories
are never searched. Copy the template to get started:

```bash
cp .env.example .env
```

!!! warning "`ORBYN_*_BIN` values are executed"
    If `.env` sets `ORBYN_NMAP_BIN`, `ORBYN_SNMP_BIN`, `ORBYN_SSH_BIN` or
    `ORBYN_CURL_BIN` to anything other than the built-in default, Orbyn prints
    `WARNING: .env configures ORBYN_…_BIN=…; Orbyn will execute that binary.`
    Make sure the path points at the tool you intend.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `ORBYN_DB` | `./data/orbyn.db` | SQLite database path, or a `postgres://` URL |
| `ORBYN_PG_PASSWORD` | *(unset)* | Password for a PostgreSQL URL that omits one (fallback: `PGPASSWORD`) |
| `ORBYN_LOG` | `orbyn=warn` | tracing filter (also `-v`/`-vv`) |
| `ORBYN_NMAP_BIN` | `nmap` | Nmap binary path |
| `ORBYN_NMAP_TIMEOUT_SECS` | `1800` | Whole-process timeout for an nmap run |
| `ORBYN_SNMP_BIN` | `snmpwalk` | `snmpwalk` binary path (net-snmp-utils) |
| `ORBYN_SNMP_COMMUNITY` | `public` | SNMP v1/v2c community string (or `--community`; `-` for stdin) |
| `ORBYN_SSH_BIN` | `ssh` | `ssh` binary path (OpenSSH client) |
| `ORBYN_CURL_BIN` | `curl` | `curl` binary path for API clients and WinRM transport |
| `ORBYN_DIG_BIN` | `dig` | `dig` binary path for DNS evidence (optional) |
| `ORBYN_WINRM_PASSWORD` | *(unset)* | WinRM Basic-auth password (or `--winrm-password`; `-` for stdin) |
| `ORBYN_NETBOX_TOKEN` | *(unset)* | NetBox API token (or `--token`; `-` for stdin) |
| `ORBYN_PROMETHEUS_TOKEN` | *(unset)* | Prometheus bearer token (or `--token`; `-` for stdin) |
| `ORBYN_ZABBIX_TOKEN` | *(unset)* | Zabbix API token (or `--token`; `-` for stdin) |
| `ORBYN_PROXMOX_TOKEN` | *(unset)* | Proxmox API token `user@realm!id=secret` |
| `AWS_ACCESS_KEY_ID` | *(unset)* | AWS access key id (or `--access-key`) |
| `AWS_SECRET_ACCESS_KEY` | *(unset)* | AWS secret access key (or `--secret-key`; `-` for stdin) |
| `AWS_SESSION_TOKEN` | *(unset)* | Session token for temporary credentials (or `--session-token`) |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | *(unset)* | AWS region (or `--region`) |
| `AWS_ENDPOINT_URL` | *(unset)* | Override the AWS EC2 endpoint (or `--endpoint-url`) |
| `HUAWEICLOUD_SDK_AK` | *(unset)* | Huawei Cloud access key (AK) |
| `HUAWEICLOUD_SDK_SK` | *(unset)* | Huawei Cloud secret key (SK) (`-` for stdin) |
| `HUAWEICLOUD_REGION` | *(unset)* | Huawei Cloud region (or `--region`) |
| `HUAWEICLOUD_PROJECT_ID` | *(unset)* | Huawei project id (resolved from IAM when omitted) |
| `ORBYN_OPENSTACK_TOKEN` | *(unset)* | Scoped OpenStack token |
| `OS_PROJECT_ID` / `OS_REGION_NAME` | *(unset)* | OpenStack project and region scope |
| `ORBYN_GCP_TOKEN` | *(unset)* | GCP OAuth bearer token |
| `GOOGLE_CLOUD_PROJECT` | *(unset)* | GCP project id (or `--project`) |
| `ORBYN_AZURE_TOKEN` | *(unset)* | Azure ARM bearer token |
| `AZURE_SUBSCRIPTION_ID` | *(unset)* | Azure subscription id (or `--subscription-id`) |

## Secrets on stdin

Any secret flag accepts a literal `-` and reads **one trimmed line from
stdin**, so the value never appears in argv, in `ps`, or in the environment:

```bash
orbyn netbox import --url https://netbox.example.com --token - < ~/.netbox-token
orbyn discover --target 10.0.0.8 --collector snmp --community - <<< "$ORBYN_SNMP_COMMUNITY"
orbyn aws import --region eu-west-1 --secret-key - < ~/.aws-secret
orbyn discover --target 10.0.0.20 --collector winrm --user admin --winrm-password - < pw.txt
```

An empty line is an error; values containing newlines or NUL bytes are
rejected. Passing a literal secret on the command line prints an audit
warning.

## Database backends

SQLite by default, created and migrated automatically at `./data/orbyn.db`.
Any `--db` / `ORBYN_DB` value starting with `postgres://` or `postgresql://`
selects the PostgreSQL backend with the same schema.

```bash
orbyn --db postgres://orbyn@localhost:5432/orbyn assets
ORBYN_DB="postgres://orbyn@db:5432/orbyn?sslmode=require" orbyn discover --target 10.0.0.0/24
```

TLS is negotiated when the server offers it (`sslmode=prefer` by default);
use `?sslmode=require` for remote databases. A URL without a password falls
back to `ORBYN_PG_PASSWORD` (or `PGPASSWORD`); a URL that embeds a password
prints a warning, since argv is readable by any local user. Prefer a
least-privilege role and certificate or password-file authentication.

## Operational limits

| Limit | Value |
| --- | --- |
| Subprocess stdout / stderr capture | 16 MiB / 1 MiB |
| Inventory import size | 64 MiB |
| API retries | 3 attempts, bounded exponential backoff, transient errors only |
| Discovery concurrency | `--concurrency` (default 4) |
| Discovery launch pacing | `--rate-limit` (default none) |
| `.env` location | current working directory only |

Logs go to **stderr**; stdout carries only command output, so pipes stay
clean.

## Shell completions

```bash
orbyn completions bash > /etc/bash_completion.d/orbyn
orbyn completions zsh  > "$fpath[1]/_orbyn"
orbyn completions fish > ~/.config/fish/completions/orbyn.fish
```
