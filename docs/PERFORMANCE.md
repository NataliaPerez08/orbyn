# Performance baselines

Reproduced with `make bench` (Linux, GNU `time`, release build; treat as
order-of-magnitude expectations, not portable benchmarks).

Reference machine: General Purpose Processor, 16 cores, 30758 MiB RAM.

Reference dataset: the deterministic representative inventory from
`examples/bench_inventory` (2 interfaces, 4 services per asset),
byte-identical to the one the scale tests use, extended after import with a
deterministic dependency chain (asset i -> asset i+1, n-1 edges) seeded
through the real `deps add` CLI, and one week of metric samples for the
first asset (fake `curl` mirroring `tests/e2e_scale.rs`).

## Dataset shape

| Assets | Interfaces | Services | Dependency edges | Metric samples |
|-------:|-----------:|---------:|-----------------:|---------------:|
| 100 | 200 | 400 | 99 | 48 |
| 1000 | 2000 | 4000 | 999 | 48 |
| 10000 | 20000 | 40000 | 9999 | 48 |

Metric samples cover one asset (48 CPU samples over a week), mirroring the
scale-suite fixture; `metrics` is a per-asset operation, so its row measures
the aggregation over that window.

## Measurements

| Assets | Phase | Wall clock | Peak RSS | DB size |
|-------:|-------|----------:|---------:|--------:|
| 100 | startup | 0:00.07 s | 10 MiB | 0.1 MiB |
| 100 | import | 0:00.11 s | 12 MiB | 0.2 MiB |
| 100 | assets | 0:00.00 s | 11 MiB | 0.3 MiB |
| 100 | graph | 0:00.00 s | 11 MiB | 0.3 MiB |
| 100 | assess | 0:00.00 s | 11 MiB | 0.3 MiB |
| 100 | metrics | 0:00.00 s | 11 MiB | 0.3 MiB |
| 100 | waves | 0:00.00 s | 12 MiB | 0.3 MiB |
| 100 | export | 0:00.00 s | 11 MiB | 0.3 MiB |
| 1000 | startup | 0:00.06 s | 11 MiB | 0.1 MiB |
| 1000 | import | 0:00.21 s | 21 MiB | 0.9 MiB |
| 1000 | assets | 0:00.02 s | 16 MiB | 1.3 MiB |
| 1000 | graph | 0:00.01 s | 12 MiB | 1.3 MiB |
| 1000 | assess | 0:00.05 s | 13 MiB | 1.3 MiB |
| 1000 | metrics | 0:00.00 s | 11 MiB | 1.3 MiB |
| 1000 | waves | 0:00.06 s | 17 MiB | 1.3 MiB |
| 1000 | export | 0:00.04 s | 14 MiB | 1.3 MiB |
| 10000 | startup | 0:00.07 s | 10 MiB | 0.1 MiB |
| 10000 | import | 0:01.55 s | 123 MiB | 7.9 MiB |
| 10000 | assets | 0:00.19 s | 68 MiB | 11.9 MiB |
| 10000 | graph | 0:00.13 s | 22 MiB | 11.9 MiB |
| 10000 | assess | 0:02.52 s | 43 MiB | 11.9 MiB |
| 10000 | metrics | 0:00.00 s | 11 MiB | 11.9 MiB |
| 10000 | waves | 0:02.50 s | 82 MiB | 11.9 MiB |
| 10000 | export | 0:00.34 s | 49 MiB | 11.9 MiB |

Startup/migration is the first open of a brand-new database (schema creation
plus an empty asset listing); its DB size is the empty schema. All other
phases run against the fully seeded database.

## Seeding throughput

- 100 assets: chain of 99 edges seeded via `deps add` in 2 s (one process per edge — the CLI has no bulk edge import)
- 1000 assets: chain of 999 edges seeded via `deps add` in 17 s (one process per edge — the CLI has no bulk edge import)
- 10000 assets: chain of 9999 edges seeded via `deps add` in 168 s (one process per edge — the CLI has no bulk edge import)

The scale suite (`tests/e2e_scale.rs`) enforces generous wall-clock budgets to
catch order-of-magnitude regressions (above all the return of per-asset N+1
queries). A change of more than ~25% against an identical reference dataset on
the same machine warrants investigation.
