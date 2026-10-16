#!/usr/bin/env bash
# Level 1 demo (CSV): import a predefined estate, map dependencies, assess, plan waves.
# Requires: an `orbyn` binary on PATH (or ORBYN_BIN=/path/to/orbyn).
set -euo pipefail
cd "$(dirname "$0")"

ORBYN="${ORBYN_BIN:-orbyn}"
DB=demo.db

rm -f "$DB"

echo "== Importing fixtures/inventory.csv =="
"$ORBYN" --db "$DB" import --format csv --file fixtures/inventory.csv

echo
echo "== Seeding dependencies from fixtures/dependencies.txt =="
while read -r src dst port; do
  case "$src" in '' | '#'*) continue ;; esac
  "$ORBYN" --db "$DB" deps add "$src" "$dst" --port "$port"
done < fixtures/dependencies.txt

echo
echo "== Estate =="
"$ORBYN" --db "$DB" assets

echo
echo "== Dependency graph =="
"$ORBYN" --db "$DB" graph

echo
echo "== Migration assessment =="
"$ORBYN" --db "$DB" assess

echo
echo "== Migration waves =="
"$ORBYN" --db "$DB" waves
