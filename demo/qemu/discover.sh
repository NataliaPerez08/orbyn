#!/usr/bin/env bash
# Run Orbyn's SSH collector against the running lab and show the results.
# Requires: an `orbyn` binary on PATH (or ORBYN_BIN=/path/to/orbyn) and the
# lab up (./start-lab.sh).
set -euo pipefail
cd "$(dirname "$0")"

ORBYN="${ORBYN_BIN:-orbyn}"
DB=lab.db

rm -f "$DB"

echo "== Discovering the lab over SSH =="
"$ORBYN" --db "$DB" discover \
  --target 192.0.2.11 --target 192.0.2.12 --target 192.0.2.13 --target 192.0.2.14 \
  --collector ssh --user deploy --identity-file lab_key --concurrency 4

echo
echo "== Estate =="
"$ORBYN" --db "$DB" assets

echo
echo "== Asset detail: web-01 =="
"$ORBYN" --db "$DB" asset 192.0.2.11

echo
echo "== Dependency graph =="
"$ORBYN" --db "$DB" graph

echo
echo "== Migration assessment =="
"$ORBYN" --db "$DB" assess
