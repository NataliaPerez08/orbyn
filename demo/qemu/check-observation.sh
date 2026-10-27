#!/usr/bin/env bash
# v1.5 exit-criteria check — validate the 7-day observation run.
#
# After ./agent-lab.sh --service has been running for at least a week,
# this checks the synced coverage on the server database:
#
#   - every enrolled VM has samples (the observation is recoverable
#     from the server after outages, because the local buffer is the
#     retry policy)
#   - the observed span is at least 168 hours
#   - the largest gap between consecutive samples stays under
#     OBS_MAX_GAP_SECS (default 600 = 10 missed 60s intervals)
#
# Requires: the lab up and the ingest server database (server.db) with
# the synced samples. Adjust the database with SERVER_DB=... if needed.
set -euo pipefail
cd "$(dirname "$0")"

SERVER_DB="${SERVER_DB:-server.db}"
ORBYN="${ORBYN_BIN:-orbyn}"
command -v "$ORBYN" >/dev/null || { echo "orbyn not found (set ORBYN_BIN=/path/to/orbyn)" >&2; exit 1; }
[ -f "$SERVER_DB" ] || { echo "$SERVER_DB not found — run ./agent-lab.sh --service first" >&2; exit 1; }

MIN_SPAN_HOURS=168
MAX_GAP_SECS="${OBS_MAX_GAP_SECS:-600}"
VMS=("web-01 192.0.2.11" "api-01 192.0.2.12" "db-01 192.0.2.13")

PASS=0; FAIL=0
check() {
  if [ "$2" = 1 ]; then PASS=$((PASS + 1)); echo "  PASS  $1"
  else FAIL=$((FAIL + 1)); echo "  FAIL  $1"; fi
}

json_num() { # json key -> value (null when absent)
  grep -oE "\"$1\": *[0-9.]+" | grep -oE '[0-9.]+'
}

echo "== v1.5 observation coverage (span >= ${MIN_SPAN_HOURS}h, largest gap <= ${MAX_GAP_SECS}s) =="
for spec in "${VMS[@]}"; do
  read -r name ip <<<"$spec"
  REPORT=$("$ORBYN" --db "$SERVER_DB" agent report --asset-ip "$ip" --format json 2>/dev/null || true)
  if [ -z "$REPORT" ]; then
    check "$name: report available" 0
    continue
  fi
  COUNT=$(json_num sample_count <<<"$REPORT")
  SPAN=$(json_num span_hours <<<"$REPORT")
  GAP=$(json_num largest_gap_secs <<<"$REPORT")
  if [ -n "$COUNT" ] && [ "$COUNT" -gt 0 ]; then
    check "$name: samples present ($COUNT)" 1
  else
    check "$name: samples present" 0
    continue
  fi
  if [ -n "$SPAN" ] && awk "BEGIN{exit !($SPAN >= $MIN_SPAN_HOURS)}"; then
    check "$name: span >= ${MIN_SPAN_HOURS}h ($SPAN h)" 1
  else
    check "$name: span >= ${MIN_SPAN_HOURS}h (${SPAN:-null} h — keep the lab running)" 0
  fi
  if [ -n "$GAP" ] && awk "BEGIN{exit !($GAP <= $MAX_GAP_SECS)}"; then
    check "$name: largest gap <= ${MAX_GAP_SECS}s ($GAP s)" 1
  else
    check "$name: largest gap <= ${MAX_GAP_SECS}s (${GAP:-null} s)" 0
  fi
done

echo
echo "HTML report: $ORBYN --db $SERVER_DB agent report --asset-ip <ip> --format html > report.html"
echo "v1.5 exit criteria: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
