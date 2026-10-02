# Performance baselines

Reproduced with `make bench` (Linux, GNU `time`, release build, local machine;
treat as order-of-magnitude expectations, not portable benchmarks).

Reference dataset: the deterministic representative inventory from
`examples/bench_inventory` (2 interfaces, 4 services per asset), byte-identical
to the one the scale tests use. Dependency edges are 0 in this baseline, so the
`graph` row measures the store read + render path, not edge reconciliation.

The scale suite (`tests/e2e_scale.rs`) enforces generous wall-clock budgets to
catch order-of-magnitude regressions (above all the return of per-asset N+1
queries). A change of more than ~25% against an identical reference dataset on
the same machine warrants investigation.

| Assets | Phase | Wall clock | Peak RSS | DB size |
|--------|-------|-----------:|---------:|--------:|
| 100 | import | 0:00.02 s | 12 MiB | 0.2 MiB |
| 100 | assess | 0:00.00 s | 12 MiB | 0.2 MiB |
| 100 | export | 0:00.00 s | 11 MiB | 0.2 MiB |
| 100 | graph | 0:00.00 s | 11 MiB | 0.2 MiB |
| 1000 | import | 0:00.14 s | 21 MiB | 0.9 MiB |
| 1000 | assess | 0:00.04 s | 13 MiB | 0.9 MiB |
| 1000 | export | 0:00.04 s | 14 MiB | 0.9 MiB |
| 1000 | graph | 0:00.01 s | 12 MiB | 0.9 MiB |
| 10000 | import | 0:01.72 s | 124 MiB | 7.9 MiB |
| 10000 | assess | 0:02.06 s | 41 MiB | 7.9 MiB |
| 10000 | export | 0:00.37 s | 52 MiB | 7.9 MiB |
| 10000 | graph | 0:00.08 s | 20 MiB | 7.9 MiB |
