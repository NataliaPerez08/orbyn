#!/usr/bin/env bash
# v1.6 exit-criteria evidence — manual run against the live ingest server.
# agent-lab.sh wipes server.db on start; this variant preserves the ongoing
# 7-day observation (v1.5). Criteria mirror agent-lab.sh exactly.
set -uo pipefail
cd "$(dirname "$0")"
ORBYN=/usr/local/bin/orbyn
SSH_OPTS=(-i lab_key -o BatchMode=yes)
PASS=0; FAIL=0
check() { if [ "$2" = 1 ]; then PASS=$((PASS+1)); echo "  PASS  $1"; else FAIL=$((FAIL+1)); echo "  FAIL  $1"; fi; }
samples() { "$ORBYN" --db server.db agent report --asset-ip "$1" --format json 2>/dev/null | grep -oE '"sample_count": *[0-9]+' | grep -oE '[0-9]+' | head -1; }

echo "== criterion 1: three heterogeneous hosts observed through the server =="
OBS=0
for ip in 192.0.2.11 192.0.2.12 192.0.2.13; do
  N=$(samples "$ip")
  echo "  $ip: ${N:-0} samples"
  [ -n "$N" ] && [ "$N" -gt 0 ] && OBS=$((OBS+1))
done
if [ "$OBS" -eq 3 ]; then check "three heterogeneous hosts observed through the server (3/3)" 1
else check "three heterogeneous hosts observed through the server ($OBS/3)" 0; fi

echo "== criterion 2: connections backed by evidence =="
# connections CSV columns: asset_id,proto,local_ip,local_port,remote_ip,remote_port,process
CONNS=$("$ORBYN" --db server.db connections 192.0.2.12 --format csv 2>/dev/null)
echo "$CONNS" | grep -q "192\.0\.2\.13,5432" \
  && check "api-01 -> db-01:5432 observed with evidence" 1 \
  || check "api-01 -> db-01:5432 observed with evidence" 0
echo "$CONNS" | grep -q "192\.0\.2\.13,6379" \
  && check "api-01 -> db-01:6379 observed with evidence" 1 \
  || check "api-01 -> db-01:6379 observed with evidence" 0
CONNS=$("$ORBYN" --db server.db connections 192.0.2.11 --format csv 2>/dev/null)
echo "$CONNS" | grep -q "192\.0\.2\.12,8080" \
  && check "web-01 -> api-01:8080 observed with evidence" 1 \
  || check "web-01 -> api-01:8080 observed with evidence" 0
"$ORBYN" --db server.db graph --format csv 2>/dev/null | grep -q "192-0-2-12,192-0-2-13" \
  && check "dependency graph has api-01 -> db-01 edges" 1 \
  || check "dependency graph has api-01 -> db-01 edges" 0

echo "== criterion 3: revocation verified mid-run =="
# Freeze the sync timer so the manual starts below are real runs, not
# no-ops racing an in-flight timer sync.
ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 "sudo systemctl stop orbyn-agent-sync.timer" 2>/dev/null
BEFORE=$(samples 192.0.2.13)
"$ORBYN" --db server.db server revoke 192-0-2-13 >/dev/null
if ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 "sudo systemctl start orbyn-agent-sync.service" 2>/dev/null; then
  check "revoked db-01 sync is refused" 0
else
  check "revoked db-01 sync is refused" 1
fi
AFTER=$(samples 192.0.2.13)
if [ "$BEFORE" = "$AFTER" ]; then
  check "server sample count for db-01 unchanged after revocation ($AFTER)" 1
else
  check "server sample count for db-01 unchanged after revocation ($BEFORE -> $AFTER)" 0
fi
BUFFERED=$(ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 \
  "sudo /usr/local/bin/orbyn agent report --asset-ip 192.0.2.13 --format json --db /var/lib/orbyn/agent.db 2>/dev/null | grep -oE '\"sample_count\": *[0-9]+' | grep -oE '[0-9]+' | tail -1" || true)
if [ -n "$BUFFERED" ] && [ "$BUFFERED" != "0" ]; then
  check "db-01 keeps buffering locally after revocation ($BUFFERED)" 1
else
  check "db-01 keeps buffering locally after revocation" 0
fi

echo "== re-enroll db-01 (leave the lab usable, resume the observation) =="
NEW_TOKEN=$("$ORBYN" --db server.db server enroll --asset-ip 192.0.2.13 2>/dev/null)
ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 \
  "echo 'ORBYN_SYNC_TOKEN=$NEW_TOKEN' | sudo tee /etc/orbyn/sync.env >/dev/null"
if ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 "sudo systemctl start orbyn-agent-sync.service" 2>/dev/null; then
  check "re-enrolled db-01 sync succeeds" 1
else
  check "re-enrolled db-01 sync succeeds" 0
fi
FINAL=$(samples 192.0.2.13)
if [ -n "$FINAL" ] && [ "$FINAL" -gt "$AFTER" ]; then
  check "buffered samples shipped after re-enroll ($AFTER -> $FINAL)" 1
else
  check "buffered samples shipped after re-enroll ($AFTER -> ${FINAL:-none})" 0
fi
ssh "${SSH_OPTS[@]}" deploy@192.0.2.13 "sudo systemctl start orbyn-agent-sync.timer" 2>/dev/null

echo
echo "v1.6 exit criteria: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
