#!/usr/bin/env bash
# Performance baselines (v1.1 plan, Priority 5).
#
# Measures database startup/migration, inventory import, asset listing,
# dependency graph, assessment, metrics aggregation, migration waves and
# export at 100, 1,000 and 10,000 assets on the release binary and rewrites
# docs/PERFORMANCE.md. Linux + GNU time required.
#
# The estate is the deterministic inventory from examples/bench_inventory
# (byte-identical to the scale suite's fixture) plus a deterministic chain of
# dependency edges (asset i -> asset i+1, seeded through the real `deps add`
# CLI) and one week of metric samples for the first asset (fake curl mirroring
# tests/e2e_scale.rs, so the metrics numbers are comparable across runs).
set -euo pipefail

cd "$(dirname "$0")/.."

BIN="target/release/orbyn"
GEN="target/release/examples/bench_inventory"
OUT="docs/PERFORMANCE.md"

cargo build --release --quiet
cargo build --release --example bench_inventory --quiet

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Fake curl serving a week of low utilization for one instance — verbatim
# from the scale suite (tests/e2e_scale.rs).
cat > "$WORK/curl" <<'CURL'
#!/usr/bin/env bash
url=""
for a in "$@"; do
  case "$a" in
    */api/v1/query_range*) url="$a" ;;
  esac
done
instance="$(printf '%s' "$url" | sed -n 's/.*instance%22%3A%22\([^%&]*\).*/\1/p')"
[[ -n "$instance" ]] || instance='10.0.0.1:9100'
now="$(date +%s)"
points=''
for i in $(seq 0 47); do
  ts=$((now - i * 8 * 3600))
  [[ -n "$points" ]] && points="$points,"
  points="$points[$ts,\"15.00\"]"
done
printf '{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"instance":"%s"},"values":[%s]}]}}' "$instance" "$points"
printf '200'
CURL
chmod +x "$WORK/curl"

# IP of asset i in the bench_inventory estate (10.<i/250>.<i%250>.1).
ip_of() { printf '10.%d.%d.1' $(( $1 / 250 )) $(( $1 % 250 )); }

# measure <db> <phase> <args...> — appends a result row.
measure() {
  local db="$1" phase="$2"; shift 2
  local t_out="$WORK/time.txt"
  /usr/bin/time -v "$BIN" --db "$db" "$@" > /dev/null 2> "$t_out"
  local wall rss db_size db_mib
  wall="$(grep -m1 'Elapsed (wall clock)' "$t_out" | sed -E 's/.*: ([0-9:.]+)$/\1/')"
  rss="$(grep -m1 'Maximum resident set size' "$t_out" | grep -oE '[0-9]+$' | awk '{printf "%.0f", $1/1024}')"
  db_size="$(stat -c %s "$db")"
  db_mib="$(awk -v b="$db_size" 'BEGIN{printf "%.1f", b/1048576}')"
  rows="$rows| $n | $phase | $wall s | ${rss} MiB | $db_mib MiB |\n"
}

rows=""
counts=""
notes=""
for n in 100 1000 10000; do
  inv="$WORK/inv-$n.json"
  db="$WORK/bench-$n.db"
  fresh="$WORK/fresh-$n.db"
  "$GEN" "$n" > "$inv"

  # Startup/migration: first open of a brand-new database (schema only).
  measure "$fresh" startup assets

  # Import: the write-heavy path (every asset, interface and service).
  measure "$db" import import --format json --file "$inv"

  # Setup (not a measured phase): seed a deterministic dependency chain
  # through the real CLI — one process per edge, no bulk import exists.
  seed_start="$SECONDS"
  for (( i = 0; i < n - 1; i++ )); do
    "$BIN" --db "$db" deps add "$(ip_of $i)" "$(ip_of $(( i + 1 )))" --port 443 > /dev/null 2>&1
  done
  notes="$notes- $n assets: chain of $(( n - 1 )) edges seeded via \`deps add\` in $(( SECONDS - seed_start )) s (one process per edge — the CLI has no bulk edge import)\n"

  # Setup: one week of metric samples for the first asset (fake curl).
  ORBYN_CURL_BIN="$WORK/curl" "$BIN" --db "$db" prometheus import --url http://prometheus:9090 > /dev/null

  counts="$counts| $n | $(( n * 2 )) | $(( n * 4 )) | $(( n - 1 )) | 48 |\n"

  # Read-heavy phases over the full estate.
  measure "$db" assets assets
  measure "$db" graph graph --format csv
  measure "$db" assess assess --format json
  measure "$db" metrics metrics 10.0.0.1 --format csv
  measure "$db" waves waves
  measure "$db" export export --format json
done

cpu="$(grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //')"
ram_mib="$(awk '/MemTotal/ {printf "%.0f", $2/1024}' /proc/meminfo)"
cores="$(nproc)"

{
  cat <<HEADER
# Performance baselines

Reproduced with \`make bench\` (Linux, GNU \`time\`, release build; treat as
order-of-magnitude expectations, not portable benchmarks).

Reference machine: ${cpu}, ${cores} cores, ${ram_mib} MiB RAM.

Reference dataset: the deterministic representative inventory from
\`examples/bench_inventory\` (2 interfaces, 4 services per asset),
byte-identical to the one the scale tests use, extended after import with a
deterministic dependency chain (asset i -> asset i+1, n-1 edges) seeded
through the real \`deps add\` CLI, and one week of metric samples for the
first asset (fake \`curl\` mirroring \`tests/e2e_scale.rs\`).

## Dataset shape

| Assets | Interfaces | Services | Dependency edges | Metric samples |
|-------:|-----------:|---------:|-----------------:|---------------:|
$(printf '%b' "$counts")

Metric samples cover one asset (48 CPU samples over a week), mirroring the
scale-suite fixture; \`metrics\` is a per-asset operation, so its row measures
the aggregation over that window.

## Measurements

| Assets | Phase | Wall clock | Peak RSS | DB size |
|-------:|-------|----------:|---------:|--------:|
$(printf '%b' "$rows")

Startup/migration is the first open of a brand-new database (schema creation
plus an empty asset listing); its DB size is the empty schema. All other
phases run against the fully seeded database.

## Seeding throughput

$(printf '%b' "$notes")

The scale suite (\`tests/e2e_scale.rs\`) enforces generous wall-clock budgets to
catch order-of-magnitude regressions (above all the return of per-asset N+1
queries). A change of more than ~25% against an identical reference dataset on
the same machine warrants investigation.
HEADER
} > "$OUT"

echo "wrote $OUT"
