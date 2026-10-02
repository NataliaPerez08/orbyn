# Observability importers

Both importers turn historical CPU/RAM/swap utilization into metric samples
that [`orbyn metrics`](../cli.md#metrics-and-right-sizing) can evaluate for
right-sizing. They exist because a single discovery run only snapshots three
points — a week of history is what makes utilization evidence trustworthy.

```bash
# node_exporter queries by default; run from cron for continuous evidence
orbyn prometheus import --url http://prometheus:9090

# same window from Zabbix JSON-RPC (hosts map by interface IP, then by name)
orbyn zabbix import --url https://zabbix.example.com/zabbix/api_jsonrpc.php \
    --token - < ~/.zabbix-token

orbyn metrics 10.0.0.10    # span, percentiles, confidence, readiness
```

!!! note "Read-only"
    Orbyn only queries these APIs. It never writes a series, an item or a
    trigger to Prometheus or Zabbix.

## Prometheus

Queries `/api/v1/query_range` through `curl`. Series map onto assets by the
`instance` label (IP or hostname). Re-imports are idempotent.

```bash
orbyn prometheus import --url http://prometheus:9090 --lookback-hours 168 --step 5m

# bearer token from stdin, self-signed TLS
orbyn prometheus import --url https://prometheus.example.com --token - --no-verify < tok

# custom queries (must aggregate per `instance`)
orbyn prometheus import --url http://prometheus:9090 \
    --cpu-query 'avg by (instance) (rate(node_cpu_seconds_total{mode!="idle"}[5m])) * 100' \
    --ram-query 'avg by (instance) (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes)' \
    --swap-query 'avg by (instance) (node_memory_SwapTotal_bytes - node_memory_SwapFree_bytes)'
```

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--url` | *(required)* | Base URL, e.g. `http://prometheus:9090` |
| `--token` / `ORBYN_PROMETHEUS_TOKEN` | *(none)* | Bearer token; `-` reads stdin |
| `--lookback-hours` | `168` | History window (168 h = the right-sizing minimum) |
| `--step` | `5m` | Query resolution step |
| `--cpu-query` | node_exporter CPU query | Must aggregate per `instance`, percent |
| `--ram-query` | node_exporter RAM query | Must aggregate per `instance`, bytes |
| `--swap-query` | node_exporter swap query | A query the endpoint cannot answer is skipped with a warning; CPU and RAM history still import |
| `--no-verify` | off | Skip TLS verification |

## Zabbix

Uses the JSON-RPC API (`host.get` / `item.get` / `history.get`) through
`curl`. Hosts map onto assets by interface IP first, then by name.

```bash
orbyn zabbix import --url https://zabbix.example.com/zabbix/api_jsonrpc.php \
    --token - < ~/.zabbix-token

orbyn zabbix import --url https://zabbix.example.com/zabbix/api_jsonrpc.php \
    --lookback-hours 336 --no-verify < tok      # two weeks: enables trend reporting
```

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--url` | *(required)* | JSON-RPC endpoint, e.g. `https://host/zabbix/api_jsonrpc.php` |
| `--token` / `ORBYN_ZABBIX_TOKEN` | *(required)* | API token; `-` reads stdin |
| `--lookback-hours` | `168` | History window |
| `--no-verify` | off | Skip TLS verification |

## What the imported window gives you

* `orbyn metrics <id-or-ip>` reports span, avg/p95/p99/peak CPU and RAM, a
  `SampleConfidence` label based on sample count and validity, and
  **right-sizing readiness** — a window of at least 168 h with high
  confidence. Snapshots alone never qualify.
* A window spanning two full weeks also reports the prior-vs-recent p95
  trend.
* The rule catalog (`orbyn assess --rules`) evaluates that evidence:
  over-provisioned CPU/RAM (p99 + 50% headroom), saturation (p95 ≥ 90%),
  sustained swap pressure, week-over-week growth, insufficient windows.

## Scheduling

Metric samples are collected **on demand only** — there is no built-in
scheduler. Run the importers from cron or a systemd timer to build continuous
evidence:

```cron
17 * * * * orbyn prometheus import --url http://prometheus:9090 >> /var/log/orbyn-import.log 2>&1
```
