#!/usr/bin/env bash
# Release smoke test (Phase 8 of docs/ORBYN_AGENT_PLAN.md).
#
# Extracts a built artifact and exercises the real binary: the version matches
# the release tag, --help renders, and a fresh database migrates and serves
# `orbyn assets`. Runs in CI after packaging and locally before a release.
#
# Usage: release-smoke.sh <artifact> <expected-version>
set -euo pipefail

artifact="${1:?usage: release-smoke.sh <artifact> <expected-version>}"
version="${2:?usage: release-smoke.sh <artifact> <expected-version>}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

case "$artifact" in
  *.zip) (cd "$work" && unzip -q "$OLDPWD/$artifact") ;;
  *.tar.gz) tar -xzf "$artifact" -C "$work" ;;
  *) echo "unsupported artifact: $artifact" >&2; exit 2 ;;
esac

bin="$(find "$work" -maxdepth 1 -type f -name 'orbyn*' ! -name '*.sha256' | head -n1)"
[[ -n "$bin" ]] || { echo "no binary in the archive" >&2; exit 2; }

got="$("$bin" --version)"
echo "$got" | grep -q "orbyn $version" || {
  echo "version mismatch: '$got' does not match '$version'" >&2
  exit 1
}

"$bin" --help > /dev/null

# A fresh database must migrate and serve the (empty) inventory.
db="$work/smoke.db"
csv="$("$bin" --db "$db" assets --format csv)"
echo "$csv" | grep -q "^id,ip,hostname,device_class," || {
  echo "fresh database did not serve the inventory: $csv" >&2
  exit 1
}

echo "smoke ok: $got"