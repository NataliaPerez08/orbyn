#!/usr/bin/env bash
# Functional smoke tests for the Windows `orbyn.exe`.
#
# Runs the compiled Windows binary against a throwaway SQLite database and
# exercises the local-only CLI surface (no network, no external tools):
# parsing, migration, import/export round trip, inventory reads, annotation,
# dependencies, assessment, applications/targets, SKU matching, waves and the
# audit trail, plus an error path.
#
# The same script runs two ways:
#   * Linux + Wine:  ORBYN_WINE=wine ORBYN_EXE=target/x86_64-pc-windows-gnu/release/orbyn.exe
#   * Windows (Git Bash / MSYS): ORBYN_WINE= (empty) ORBYN_EXE=target/release/orbyn.exe
#
# Usage: windows-smoke.sh [path/to/orbyn.exe]
# Env:   ORBYN_EXE  path to the .exe (arg wins)
#        ORBYN_WINE runner prefix (defaults to `wine` if on PATH, else empty)
set -u

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

exe="${1:-${ORBYN_EXE:-}}"
if [ -z "$exe" ]; then
  # Prefer a release build, then any cross/native target.
  for cand in \
    "$repo_root"/target/*/release/orbyn.exe \
    "$repo_root"/target/release/orbyn.exe; do
    [ -f "$cand" ] && exe="$cand" && break
  done
fi
[ -n "$exe" ] && [ -f "$exe" ] || {
  echo "no orbyn.exe found; build it first, e.g." >&2
  echo "  cargo build --release --target x86_64-pc-windows-gnu" >&2
  exit 2
}
# Resolve to an absolute path; the tests cd into a temp dir.
exe="$(cd "$(dirname "$exe")" && pwd)/$(basename "$exe")"

if [ -z "${ORBYN_WINE+x}" ]; then
  if command -v wine >/dev/null 2>&1; then ORBYN_WINE=wine; else ORBYN_WINE=; fi
fi
if [ -n "$ORBYN_WINE" ]; then
  export WINEDEBUG=-all
  RUN=("$ORBYN_WINE" "$exe")
else
  RUN=("$exe")
fi

expected_version="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$repo_root/Cargo.toml" | head -n1)"
: "${expected_version:=unknown}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

pass=0
fail=0

# run <args...> : executes the exe, leaves combined output in $out, status in $st.
run() {
  out="$("${RUN[@]}" "$@" 2>&1)"
  st=$?
}

ok() {
  pass=$((pass + 1))
  printf 'ok   %s\n' "$1"
}

bad() {
  fail=$((fail + 1))
  printf 'FAIL %s\n' "$1"
  printf '  cmd:    %s\n' "$2"
  printf '  want:   %s\n' "$3"
  printf '  status: %s\n' "$st"
  printf '  output: %s\n' "$(printf '%s' "$out" | head -c 400)"
}

# expect_contains <name> <substring> <cmd...>
expect_contains() {
  local name="$1" want="$2"; shift 2
  run "$@"
  if [ "$st" -eq 0 ] && printf '%s' "$out" | grep -qF -- "$want"; then
    ok "$name"
  else
    bad "$name" "$*" "exit 0 and '$want'"
  fi
}

# expect_fails <name> <substring> <cmd...>
expect_fails() {
  local name="$1" want="$2"; shift 2
  run "$@"
  if [ "$st" -ne 0 ] && printf '%s' "$out" | grep -qF -- "$want"; then
    ok "$name"
  else
    bad "$name" "$*" "non-zero exit and '$want'"
  fi
}

# --- fixture: assets + interfaces + services -------------------------------
cat > inventory.json <<'JSON'
{"assets":[
  {"ip":"10.0.0.1","hostname":"api-01","device_class":"server","environment":"prod","owner":"platform","criticality":"high","tags":["core","api"]},
  {"ip":"10.0.0.2","hostname":"db-01","device_class":"server","environment":"prod","os_name":"Ubuntu 22.04.4 LTS","criticality":"critical"},
  {"ip":"10.0.0.3","hostname":"web-01","device_class":"server"}
],"interfaces":[
  {"asset_id":"10.0.0.1","name":"eth0","mac":"00:11:22:33:44:55","ip":"10.0.0.1","vendor":"Intel","mtu":1500,"is_up":true},
  {"asset_id":"10.0.0.1","name":"eth1","is_up":false}
],"services":[
  {"asset_id":"10.0.0.1","proto":"tcp","port":443,"name":"https","state":"open","banner":"nginx"},
  {"asset_id":"10.0.0.1","proto":"tcp","port":22,"name":"ssh","state":"open"}
]}
JSON

db="smoke.db"

# 1. version
expect_contains "version" "orbyn $expected_version" --version

# 2. help renders
expect_contains "help" "Usage:" --help
expect_contains "help lists commands" "discover" --help

# 3. completions
expect_contains "completions" "_orbyn" completions bash

# 4. fresh database migrates and serves the (empty) inventory
expect_contains "fresh db migrates" "id,ip,hostname,device_class," \
  --db "$db" assets --format csv

# 5. import JSON
expect_contains "import json" "Imported 3 assets, 2 interfaces, 2 services" \
  --db "$db" import --format json --file inventory.json

# 6. inventory listing
expect_contains "assets listing" "api-01" --db "$db" assets --format csv
expect_contains "assets preserves OS" "Ubuntu 22.04.4 LTS" --db "$db" assets --format csv
expect_contains "assets preserves criticality" "critical" --db "$db" assets --format csv

# 7. asset detail by hostname and by ip
expect_contains "asset detail (hostname)" "platform" --db "$db" asset api-01
expect_contains "asset detail (ip)" "api-01" --db "$db" asset 10.0.0.1

# 8. interfaces + services reads
expect_contains "interfaces" "00:11:22:33:44:55" --db "$db" interfaces 10.0.0.1 --format csv
expect_contains "services" "tcp,443,https,open,nginx" --db "$db" services 10.0.0.1 --format csv

# 9. annotate then read back
expect_contains "annotate" "web-01" \
  --db "$db" annotate 10.0.0.3 --environment staging --owner edge-team --criticality low --add-tag web
expect_contains "annotation persisted" "staging" --db "$db" asset web-01

# 10. dependencies + graph
expect_contains "deps add" "Dependency added" --db "$db" deps add 10.0.0.1 10.0.0.2 --port 5432
expect_contains "graph edge" "10-0-0-1,10-0-0-2,tcp,5432" --db "$db" graph --format csv

# 11. export -> import round trip into a second database
run --db "$db" export --format json --output export.json
if [ "$st" -eq 0 ] && grep -qF '"assets"' export.json; then
  ok "export json"
else
  bad "export json" "--db $db export --format json --output export.json" "exit 0 and non-empty export.json"
fi
expect_contains "re-import" "Imported 3 assets" --db "roundtrip.db" import --format json --file export.json
expect_contains "round trip preserves asset" "api-01" --db "roundtrip.db" assets --format csv

# 12. assessment
expect_contains "assess runs" "\"rules_version\"" --db "$db" assess --format json
expect_contains "assess findings" "capacity.missing" --db "$db" assess --format json

# 13. applications + target intelligence
expect_contains "applications discover" "discovered" --db "$db" applications discover
expect_contains "targets compare" "strategy rehost" --db "$db" targets compare app-1

# 14. SKU matching against the embedded catalog
expect_contains "sku-match" "smallest fit first" \
  --db "$db" sku-match --provider aws --cores 2 --ram-mb 4096

# 15. migration waves
expect_contains "waves" "low risk" --db "$db" waves

# 16. audit trail records the mutations
expect_contains "audit annotate" ",annotate," --db "$db" audit --format csv
expect_contains "audit deps" ",deps.add," --db "$db" audit --format csv

# 17. error path: unknown asset fails loudly
expect_fails "unknown asset errors" "no asset matches 'nonexistent'" \
  --db "$db" asset nonexistent

printf '\n%s passed, %s failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
