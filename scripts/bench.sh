#!/usr/bin/env bash
# Performance baselines (Phase 6 of docs/ORBYN_AGENT_PLAN.md).
#
# Measures import / assess / export / graph wall-clock and peak RSS at 100,
# 1,000 and 10,000 assets on the release binary and rewrites
# docs/PERFORMANCE.md. Linux + GNU time required.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN="target/release/orbyn"
GEN="target/release/examples/bench_inventory"
OUT="docs/PERFORMANCE.md"

cargo build --release --quiet
cargo build --release --example bench_inventory --quiet

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

rows=""
for n in 100 1000 10000; do
  inv="$WORK/inv-$n.json"
  db="$WORK/bench-$n.db"
  "$GEN" "$n" > "$inv"

  "$BIN" --db "$db" import --format json --file "$inv" > /dev/null
  db_size="$(stat -c %s "$db")"
  db_mib="$(awk -v b="$db_size" 'BEGIN{printf "%.1f", b/1048576}')"

  for phase in import assess export graph; do
    case "$phase" in
      import) args=(import --format json --file "$inv") ;;
      assess) args=(assess --format json) ;;
      export) args=(export --format json) ;;
      graph) args=(graph --format csv) ;;
    esac
    t_out="$WORK/time-$n-$phase.txt"
    /usr/bin/time -v "$BIN" --db "$db" "${args[@]}" > /dev/null 2> "$t_out"
    wall="$(grep -m1 'Elapsed (wall clock)' "$t_out" | sed -E 's/.*: ([0-9:.]+)$/\1/')"
    rss="$(grep -m1 'Maximum resident set size' "$t_out" | grep -oE '[0-9]+$' | awk '{printf "%.0f", $1/1024}')"
    rows="$rows| $n | $phase | $wall s | ${rss} MiB | $db_mib MiB |\n"
  done
done

{
  cat <<'HEADER'
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
HEADER
  printf '%b' "$rows"
} > "$OUT"

echo "wrote $OUT"