# Nmap collector

`--collector nmap` — **the default**. Runs the externally installed `nmap`
binary and parses its XML output with `quick-xml`.

Orbyn executes exactly:

```text
nmap -oX - -sV --no-stylesheet <target>
```

No OS-detection (`-O`), no NSE scripts, no explicit scan type — service
detection only, stdout parsed as XML, stdin closed.

## When to use it

The only collector that accepts **CIDR ranges**. Use it for first contact with
an unknown network: which hosts are up, which ports are open, what is
answering on them.

```bash
# authorized subnet
orbyn discover --target 10.0.0.0/24

# several scopes in one job, paced
orbyn discover --target 10.0.0.0/24 --target 10.1.0.0/24 \
    --concurrency 4 --rate-limit 10

# machine-readable output
orbyn discover --target 10.0.0.0/24 --format json > discovery.json
```

## Options

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `--target` | *(required)* | IP or CIDR, repeatable |
| `--concurrency` | `4` | Scans in flight |
| `--rate-limit` | *(none)* | Launches per second |
| `--allow-large-cidr` | off | Allow wider than `/16` (IPv4) or `/48` (IPv6) |
| `ORBYN_NMAP_BIN` | `nmap` | Binary path |
| `ORBYN_NMAP_TIMEOUT_SECS` | `1800` | Whole-process timeout |

## Requirements

* `nmap` installed on the Orbyn host and supporting `-oX -` and `-sV`.
  A spawn failure reports `failed to start nmap; is it installed?`.
* Network reachability to the targets. No credentials are used.

## What it produces

| Observation | Fields |
| --- | --- |
| `Asset` | IP, hostname, `os_name` from the first `<osmatch>`, `device_class` (see [classification](framework.md#device-classification)), first/last seen |
| `Interface` | MAC address, IP, vendor — only when the scan reports an `addrtype="mac"` address |
| `Service` | One row per port with `state == "open"`: protocol, port, name, banner (`product + version`) |

Hosts with no usable address (hosts that are down) are skipped.

```bash
orbyn assets                 # who responded
orbyn services 10.0.0.10     # open ports and banners
orbyn interfaces 10.0.0.10   # MAC + vendor
orbyn jobs                   # job outcome and counts
```

## Limits and failures

* Target validation runs before nmap starts (see [overview](index.md#target-validation)).
* Whole-process timeout 1800 s; an invalid or zero `ORBYN_NMAP_TIMEOUT_SECS`
  logs a warning and falls back to 1800.
* If XML output exceeds 16 MiB the target **fails** rather than storing
  partial data: scan a narrower CIDR so the report stays parseable.
* A non-zero exit surfaces the trimmed stderr as the target error; the
  secrets env vars are removed from nmap's environment before it runs.

## Known limitations

* Banner-based OS detection — accuracy depends on `nmap`'s version probes and
  on how much the service reveals.
* `device_class` matching uses word boundaries so `ios` does not match inside
  `bios`.
* MAC vendor normalization drops addresses it cannot parse.
