# DNS evidence

`src/collectors/dns.rs` is **not a `--collector`** — there is no `dns` variant
of `--collector`. It is a relationship-evidence module driven by a single
command:

```bash
orbyn deps dns
```

It resolves every asset hostname and every asset IP, then stores the matches
as low-confidence dependency edges.

## How matching works

| Step | Source | Command |
| --- | --- | --- |
| Forward | asset hostname → A/AAAA | `dig +short <host>`, falling back to the system resolver |
| CNAME chain | followed up to 8 links | `dig +short <host>` |
| Reverse | asset IP → PTR names | `dig +short -x <ip>` |

An edge is created when a resolved address matches a known asset IP, or when
a PTR name matches a known asset hostname. Edges are deduplicated one per
`(source, target)` pair and stored as
`Dependency { proto: "dns", port: 0, evidence: dns, confidence: 0.4,
confirmed: false }`.

```bash
orbyn deps dns
# DNS evidence produced 4 relationship edge(s).
# 1 hostname(s) could not be resolved; skipped.

orbyn graph                 # see the edges
orbyn graph --mermaid       # flowchart export
orbyn deps confirm web-01 db-01   # promote one to confirmed
```

## Options

| Flag / env | Default | Purpose |
| --- | --- | --- |
| `ORBYN_DIG_BIN` | `dig` | Binary path for `dig` |

Without `dig` Orbyn still resolves through the system resolver, so **forward
IP matching keeps working**; only CNAME chains and PTR evidence are lost.

## Requirements

* Optional: `dig` from BIND utilities for CNAME/PTR evidence.
* Reachability to your resolvers. Nothing is installed on targets.

## Limits

| Limit | Value |
| --- | --- |
| Timeout per resolution | 5 s |
| Addresses per host | 64 |
| CNAME chain depth | 8 |
| PTR names per IP | 8 |
| `dig` stdout cap | 64 KiB |

Matching is exact and case-insensitive. Loopback, self and unmanaged IPs
produce no edge. Resolution failures degrade instead of failing the run.

## Interpreting DNS edges

DNS edges are **identity evidence, not observed traffic**: confidence `0.4`,
`confirmed = false`. They are excluded from application grouping in the
migration assessment — confirm them with
[`orbyn deps confirm`](../cli.md#dependencies-and-graph) if they represent a
real dependency. Stronger evidence comes from the active connections observed
by the [SSH](ssh.md) and [Windows](windows.md) host probes (confidence `0.9`).
